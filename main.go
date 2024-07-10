package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB // Declare db globally
var cookieName = "forum_session"
var sessionDuration = 24 * time.Hour // Session duration (24 hours)

// User struct
type User struct {
	UserID      int    `json:"user_id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	DateCreated string `json:"date_created"`
}

// Post struct
type Post struct {
	PostID       int    `json:"post_id"`
	UserID       int    `json:"user_id"`
	PostText     string `json:"post_text"`
	PostDate     string `json:"post_date"`
	LikeCount    int    `json:"like_count"`
	DislikeCount int    `json:"dislike_count"`
	Username     string
	Categories   []string // Add this field to store categories
}

type Comment struct {
	CommentID    int    `json:"comment_id"`
	PostID       int    `json:"post_id"`
	UserID       int    `json:"user_id"`
	CommentText  string `json:"comment_text"`
	CommentDate  string `json:"comment_date"`
	LikeCount    int    `json:"like_count"`
	DislikeCount int    `json:"dislike_count"`
	Username     string
}

// Category struct
type Category struct {
	CategoryID   int    `json:"category_id"`
	CategoryName string `json:"category_name"`
}

// popular category
type PopularCategory struct {
	CategoryID   int
	CategoryName string
	PostCount    int
}

// session
type Session struct {
	ID        string    `json:"id"`
	UserID    int       `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PostLikes struct {
	UserID    int       `json:"user_id"`
	PostID    int       `json:"post_id"`
	CreatedAt time.Time `json:"created_at"`
}

type PostDislikes struct {
	UserID    int       `json:"user_id"`
	PostID    int       `json:"post_id"`
	CreatedAt time.Time `json:"created_at"`
}

type CommentLikes struct {
	UserID    int       `json:"user_id"`
	CommentID int       `json:"comment_id"`
	CreatedAt time.Time `json:"created_at"`
}

type CommentDislikes struct {
	UserID    int       `json:"user_id"`
	CommentID int       `json:"comment_id"`
	CreatedAt time.Time `json:"created_at"`
}

type UserProfile struct {
	Username       string
	Email          string
	DateCreated    time.Time
	Posts          []Post
	Comments       []Comment
	LikedPosts     []Post
	PostCount      int
	CommentCount   int
	LikedPostCount int
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "test_forum.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		log.Fatalf("Error setting journal_mode: %v", err)
	}
	http.HandleFunc("/like/", LikeHandler)
	http.HandleFunc("/dislike/", DislikeHandler)
	http.HandleFunc("/clike/", CommentikeHandler)
	http.HandleFunc("/cdislike/", CommentDislikeHandler)
	http.HandleFunc("/like2/", LikeHandler2)
	http.HandleFunc("/dislike2/", DislikeHandler2)
	http.HandleFunc("/home", Handler)
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Debug: Request to %s", r.URL.Path)
	})
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/create_post", PostHandler)
	http.HandleFunc("/create_category/", CategoryHandler)
	http.HandleFunc("/view_categories/", ViewCategoriesHandler)
	http.HandleFunc("/category/", ViewCategoryPostsHandler)
	http.HandleFunc("/view_post/", handleViewPost)
	http.HandleFunc("/add_comment/", handleAddCommentAJAX)
	http.HandleFunc("/profile", ViewProfileHandler)
	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	log.Print("http://localhost:8080/")
	http.ListenAndServe(":8080", nil)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	log.Printf("handleRoot: Request to %s", r.URL.Path)
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if isAuthenticated(r) {
		log.Println("handleRoot: User authenticated, redirecting to /home")
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
	log.Println("handleRoot: User not authenticated, redirecting to /login")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Helper function to set a cookie
func setCookie(w http.ResponseWriter, name string, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expires,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

// Helper function to get a cookie value
func getCookie(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("forum_session")
	if err != nil {
		log.Println("No session cookie found")
		log.Printf("Cookies received: %v", r.Cookies())
		return false
	}

	log.Printf("Session cookie found: %s", cookie.Value)
	// Validate the session ID from the cookie with your session store
	return validateSession(cookie.Value)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Basic validation
		if username == "" || password == "" {
			http.Error(w, "Please fill in all fields", http.StatusBadRequest)
			return
		}

		// Start a transaction
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer func() {
			if rErr := tx.Rollback(); rErr != nil && err == nil {
				log.Printf("Error rolling back transaction: %v", rErr)
			}
		}()

		// Find the user in the database
		var user User
		err = tx.QueryRow("SELECT user_id, username, email, password, date_created FROM users WHERE username = ?", username).Scan(&user.UserID, &user.Username, &user.Email, &user.Password, &user.DateCreated)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("User not found for username: %s", username)
				http.Error(w, "Invalid username or password", http.StatusBadRequest)
				return
			}
			log.Printf("Error querying user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Compare the hashed password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			log.Printf("Password mismatch for username: %s", username)
			http.Error(w, "Invalid username or password", http.StatusBadRequest)
			return
		}

		// Create a new session
		sessionID := uuid.New().String()
		expiresAt := time.Now().Add(24 * time.Hour) // Set session to expire after 24 hours

		// Insert the session into the database
		_, err = db.Exec("INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", sessionID, user.UserID, time.Now(), expiresAt)
		if err != nil {
			log.Printf("Error inserting session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Commit the transaction
		err = tx.Commit()
		if err != nil {
			log.Printf("Error committing transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set the session cookie
		cookie := &http.Cookie{
			Name:     "forum_session",
			Value:    sessionID,
			Expires:  expiresAt,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode, // Change to http.SameSiteNoneMode for testing
		}
		http.SetCookie(w, cookie)
		log.Printf("Set-Cookie: %s=%s; Path=%s; Expires=%s; HttpOnly=%t; SameSite=%s",
			cookie.Name, cookie.Value, cookie.Path, cookie.Expires, cookie.HttpOnly, cookie.SameSite)

		log.Printf("Login successful for user: %s, session ID: %s", username, sessionID)
		// Redirect to the home page
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	} else {
		t, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, nil)
		if err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
			return
		}
	}
}

// validateSession checks if the session ID exists and is still valid
func validateSession(sessionID string) bool {
	var expiresAt time.Time

	// Query the database for the session
	err := db.QueryRow("SELECT expires_at FROM sessions WHERE id = ?", sessionID).Scan(&expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Session ID not found: %s", sessionID)
			return false
		}
		log.Printf("Error querying session: %v", err)
		return false
	}

	// Check if the session has expired
	if time.Now().After(expiresAt) {
		log.Printf("Session ID expired: %s", sessionID)
		return false
	}

	return true
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("forum_session")
	if err != nil {
		if err == http.ErrNoCookie {
			// No session to log out from
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer func() {
		if rErr := tx.Rollback(); rErr != nil && err == nil {
			log.Printf("Error rolling back transaction: %v", rErr)
		}
	}()

	// Delete the session from the database
	_, err = tx.Exec("DELETE FROM sessions WHERE id = ?", cookie.Value)
	if err != nil {
		log.Printf("Error deleting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		log.Printf("Error committing transaction: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Invalidate the session cookie
	cookie = &http.Cookie{
		Name:     "forum_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Change to http.SameSiteNoneMode for testing
	}
	http.SetCookie(w, cookie)

	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username == "" || email == "" || password == "" {
			http.Error(w, "Please fill in all fields", http.StatusBadRequest)
			return
		}

		// Hash the password
		hashedPassword, err := hashPassword(password)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Start a transaction
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback() // Roll back the transaction if it's not committed

		// Prepare the SQL statement
		stmt, err := tx.Prepare("INSERT INTO users(username, email, password) VALUES(?, ?, ?)")
		if err != nil {
			log.Printf("Error preparing SQL statement: %v", err)
			http.Error(w, "Error preparing SQL statement", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		// Execute the statement
		result, err := stmt.Exec(username, email, hashedPassword)
		if err != nil {
			log.Printf("Error inserting user: %v", err)
			http.Error(w, "Error inserting user", http.StatusInternalServerError)
			return
		}

		// Commit the transaction
		err = tx.Commit()
		if err != nil {
			log.Printf("Error committing transaction: %v", err)
			http.Error(w, "Error committing transaction", http.StatusInternalServerError)
			return
		}

		lastInsertID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Error getting last inserted ID: %v", err)
		} else {
			log.Printf("Last inserted ID: %d", lastInsertID)
		}

		http.Redirect(w, r, "/home", http.StatusSeeOther)
	} else {
		t, err := template.ParseFiles("templates/register.html")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, nil)
		if err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
			return
		}
	}
}

func ViewProfileHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	profile, err := getUserProfile(userID)
	if err != nil {
		http.Error(w, "Error fetching user profile", http.StatusInternalServerError)
		return
	}

	t, err := template.ParseFiles("templates/view_profile.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, profile)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func getUserProfile(userID int) (UserProfile, error) {
	var profile UserProfile

	// Fetch user details
	var user User
	err := db.QueryRow("SELECT username, email, date_created FROM Users WHERE user_id = ?", userID).
		Scan(&user.Username, &user.Email, &user.DateCreated)
	if err != nil {
		return profile, err
	}
	profile.Username = user.Username
	profile.Email = user.Email
	profile.DateCreated, _ = time.Parse("2006-01-02 15:04:05", user.DateCreated)

	// Fetch user's posts and count
	rows, err := db.Query("SELECT post_id, user_id, post_text, post_date, like_count, dislike_count FROM Posts WHERE user_id = ?", userID)
	if err != nil {
		return profile, err
	}
	defer rows.Close()

	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.PostID, &post.UserID, &post.PostText, &post.PostDate, &post.LikeCount, &post.DislikeCount); err != nil {
			return profile, err
		}
		profile.Posts = append(profile.Posts, post)
	}
	profile.PostCount = len(profile.Posts)

	// Fetch user's comments and count
	rows, err = db.Query("SELECT comment_id, post_id, user_id, comment_text, comment_date, like_count, dislike_count FROM Comments WHERE user_id = ?", userID)
	if err != nil {
		return profile, err
	}
	defer rows.Close()

	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.CommentID, &comment.PostID, &comment.UserID, &comment.CommentText, &comment.CommentDate, &comment.LikeCount, &comment.DislikeCount); err != nil {
			return profile, err
		}
		profile.Comments = append(profile.Comments, comment)
	}
	profile.CommentCount = len(profile.Comments)

	// Fetch user's liked posts and count
	rows, err = db.Query(`
        SELECT p.post_id, p.user_id, p.post_text, p.post_date, p.like_count, p.dislike_count
        FROM Posts p
        JOIN PostLikes pl ON p.post_id = pl.post_id
        WHERE pl.user_id = ?`, userID)
	if err != nil {
		return profile, err
	}
	defer rows.Close()

	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.PostID, &post.UserID, &post.PostText, &post.PostDate, &post.LikeCount, &post.DislikeCount); err != nil {
			return profile, err
		}
		profile.LikedPosts = append(profile.LikedPosts, post)
	}
	profile.LikedPostCount = len(profile.LikedPosts)

	return profile, nil
}

func ViewCategoriesHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	var categories []Category

	rows, err := db.Query("SELECT category_id, category_name FROM Categories")
	if err != nil {
		http.Error(w, "Error fetching categories", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var category Category
		if err := rows.Scan(&category.CategoryID, &category.CategoryName); err != nil {
			http.Error(w, "Error scanning categories", http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}

	// Pass the categories to the template
	data := struct {
		LoggedInUser string
		Categories   []Category
	}{
		LoggedInUser: username,
		Categories:   categories,
	}

	t, err := template.ParseFiles("templates/view_categories.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		// Log the error instead of sending it to the client, as headers have already been written
		log.Printf("Error executing template: %v", err)
	}
}

func ViewCategoryPostsHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	// Extract the category ID from the URL
	path := strings.TrimPrefix(r.URL.Path, "/category/")
	categoryID, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "Invalid category ID", http.StatusBadRequest)
		return
	}

	// Fetch the category name
	var categoryName string
	err = db.QueryRow("SELECT category_name FROM Categories WHERE category_id = ?", categoryID).Scan(&categoryName)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Category not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Fetch all posts for this category
	rows, err := db.Query(`
        SELECT p.post_id, p.user_id, p.post_text, p.post_date, p.like_count, p.dislike_count, u.username
        FROM Posts p
        JOIN Post_Categories pc ON p.post_id = pc.post_id
        JOIN Users u ON p.user_id = u.user_id
        WHERE pc.category_id = ?
    `, categoryID)
	if err != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.PostID, &post.UserID, &post.PostText, &post.PostDate, &post.LikeCount, &post.DislikeCount, &post.Username)
		if err != nil {
			http.Error(w, "Error scanning posts", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	// Prepare data for the template
	data := struct {
		CategoryName string
		Posts        []Post
		LoggedInUser string
	}{
		CategoryName: categoryName,
		Posts:        posts,
		LoggedInUser: username,
	}

	// Parse and execute the template
	t, err := template.ParseFiles("templates/category_posts.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
	}
}

func PostHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	if r.Method == "POST" {
		fmt.Println("post")
		post_text := r.FormValue("post_text")
		// Get selected categories
		selectedCategories := r.Form["categories"] // Get all selected categories

		if post_text == "" {
			http.Error(w, "Please add some text", http.StatusBadRequest)
			return
		}

		// Start a transaction
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback() // Roll back the transaction if it's not committed

		// Insert the post into the Posts table
		stmt, err := tx.Prepare("INSERT INTO Posts(user_id, post_text) VALUES(?, ?)")
		if err != nil {
			log.Printf("Error preparing SQL statement: %v", err)
			http.Error(w, "Error preparing SQL statement", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		result, err := stmt.Exec(userID, post_text)
		if err != nil {
			log.Printf("Error inserting post: %v", err)
			http.Error(w, "Error inserting post", http.StatusInternalServerError)
			return
		}

		// Get the last inserted post ID
		lastInsertID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Error getting last inserted ID: %v", err)
			http.Error(w, "Error getting last inserted ID", http.StatusInternalServerError)
			return
		}

		// Insert the post-category associations into the Post_Categories table
		for _, categoryName := range selectedCategories {
			var categoryID int
			err := db.QueryRow("SELECT category_id FROM Categories WHERE category_name = ?", categoryName).Scan(&categoryID)
			if err != nil {
				log.Printf("Error getting category ID: %v", err)
				http.Error(w, "Error getting category ID", http.StatusInternalServerError)
				return
			}

			_, err = tx.Exec("INSERT INTO Post_Categories(post_id, category_id) VALUES(?, ?)", lastInsertID, categoryID)
			if err != nil {
				log.Printf("Error inserting post-category association: %v", err)
				http.Error(w, "Error inserting post-category association", http.StatusInternalServerError)
				return
			}
		}

		// Commit the transaction
		err = tx.Commit()
		if err != nil {
			log.Printf("Error committing transaction: %v", err)
			http.Error(w, "Error committing transaction", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/home", http.StatusSeeOther)
	} else {
		// Get the list of categories from the database
		rows, err := db.Query("SELECT category_name FROM Categories")
		if err != nil {
			log.Printf("Error getting categories: %v", err)
			http.Error(w, "Error getting categories", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var categories []Category
		for rows.Next() {
			var category Category
			err := rows.Scan(&category.CategoryName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			categories = append(categories, category)
		}

		// Pass the categories to the template
		data := struct {
			LoggedInUser string
			Categories   []Category
		}{
			LoggedInUser: username,
			Categories:   categories,
		}

		// Render the create_post template
		t, err := template.ParseFiles("templates/create_post.html")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, data)
		if err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
			return
		}
	}
}

func CategoryHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Handle GET request
		renderCategoryForm(w, r)
	case http.MethodPost:
		// Handle POST request
		handleCreateCategory(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getCommentsByPostID(postID int) ([]Comment, error) {
	var comments []Comment
	rows, err := db.Query("SELECT c.comment_id, c.user_id, c.comment_text, c.like_count, c.dislike_count, u.username FROM Comments c JOIN Users u ON c.user_id = u.user_id WHERE c.post_id = ?", postID)
	if err != nil {
		log.Printf("Error getting comments: %v", err)
		return nil, err // Return the error
	}
	defer rows.Close()

	for rows.Next() {
		var comment Comment
		err := rows.Scan(&comment.CommentID, &comment.UserID, &comment.CommentText, &comment.LikeCount, &comment.DislikeCount, &comment.Username)
		if err != nil {
			log.Printf("Error scanning comment: %v", err)
			return nil, err // Return the error
		}
		comments = append(comments, comment)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Error iterating over comments: %v", err)
		return nil, err // Return the error
	}

	return comments, nil
}

func renderCategoryForm(w http.ResponseWriter, r *http.Request) {
	// log.Println("Rendering category creation form")

	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		fmt.Println("guest")
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		username = ""
	}

	popularCategories, err := getPopularCategories()
	if err != nil {
		log.Printf("Error fetching popular categories: %v", err)
		// Instead of handling the error here, we'll pass an empty slice
		popularCategories = []PopularCategory{}
	}

	// Create a struct to hold both the logged-in username and the users slice
	data := struct {
		LoggedInUser    string
		PopularCategory []PopularCategory
	}{
		LoggedInUser:    username,
		PopularCategory: popularCategories,
	}

	t, err := template.ParseFiles("templates/create_category.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// func getPostByID(postID int) (Post, error) {
// 	var post Post
// 	err := db.QueryRow("SELECT post_id, user_id, post_text FROM Posts WHERE post_id = ?", postID).Scan(&post.PostID, &post.UserID, &post.PostText)
// 	if err != nil {
// 		return post, err
// 	}
// 	return post, nil
// }

func getPostByID(postID int) (Post, error) {
	var post Post
	err := db.QueryRow(`
        SELECT p.post_id, p.user_id, u.username, p.post_text, p.post_date, p.like_count, p.dislike_count 
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        WHERE p.post_id = ?`, postID).Scan(
		&post.PostID, &post.UserID, &post.Username, &post.PostText, &post.PostDate, &post.LikeCount, &post.DislikeCount)
	if err != nil {
		return post, err
	}
	return post, nil
}

func handleViewPost(w http.ResponseWriter, r *http.Request) {
	// Extract the post_id from the URL
	postID, err := getPostIDFromURL(r)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		fmt.Println("guest")
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		username = ""
	}

	// Handle like and dislike actions
	if r.Method == http.MethodPost {
		action := r.URL.Path
		if strings.HasPrefix(action, "/like2/") {
			LikeHandler(w, r)
			return
		} else if strings.HasPrefix(action, "/dislike2/") {
			DislikeHandler(w, r)
			return
		}
	}

	// Fetch the post data from the database using postID
	post, err := getPostByID(postID)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Fetch categories for this post
	categories, err := getCategoriesByPostID(postID)
	if err != nil {
		http.Error(w, "Error fetching categories", http.StatusInternalServerError)
		return
	}

	// Fetch comments for the post
	comments, err := getCommentsByPostID(postID)
	if err != nil {
		http.Error(w, "Error fetching comments", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		// Handle POST request
		handleAddComment(w, r, postID)
	}

	// Fetch popular categories
	popularCategories, err := getPopularCategories()
	if err != nil {
		log.Printf("Error fetching popular categories: %v", err)
		// Instead of handling the error here, we'll pass an empty slice
		popularCategories = []PopularCategory{}
	}

	// Render the view_post template
	data := map[string]interface{}{
		"Post":            post,
		"Categories":      categories,
		"Comments":        comments,
		"LoggedInUser":    username,
		"PopularCategory": popularCategories,
	}
	// Parse the template file
	t, err := template.ParseFiles("templates/view_post.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}

	// Execute the template with the data
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

// New function to get categories for a post
func getCategoriesByPostID(postID int) ([]string, error) {
	rows, err := db.Query(`
		SELECT c.category_name 
		FROM Categories c
		JOIN Post_Categories pc ON c.category_id = pc.category_id
		WHERE pc.post_id = ?
	`, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	return categories, nil
}

// func getPostIDFromURL(r *http.Request) (int, error) {
// 	// Extract the post_id from the URL path
// 	pathParts := strings.Split(r.URL.Path, "/")
// 	if len(pathParts) < 3 {
// 		return 0, fmt.Errorf("invalid URL path")
// 	}
// 	postID, err := strconv.Atoi(pathParts[2])
// 	if err != nil {
// 		return 0, fmt.Errorf("invalid post ID")
// 	}
// 	return postID, nil
// }

func handleAddComment(w http.ResponseWriter, r *http.Request, postID int) {
	// Extract post_id from the URL
	// postID, err := getPostIDFromURL(r)
	// if err != nil {
	// 	http.Error(w, "Invalid post ID", http.StatusBadRequest)
	// 	return
	// }

	// Get comment text from the form
	commentText := r.FormValue("comment_text")
	if commentText == "" {
		log.Println("there is no comment text")
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() // Roll back the transaction if it's not committed

	// Insert the category into the Categories table
	result, err := tx.Exec("INSERT INTO Comments(comment_text) VALUES(?)", commentText)
	if err != nil {
		log.Printf("Error inserting comment: %v", err)
		http.Error(w, "Error creating comment", http.StatusInternalServerError)
		return
	}

	// Get the last inserted ID
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last inserted ID: %v", err)
	} else {
		log.Printf("comment created with ID: %d", lastInsertID)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		http.Error(w, "Error creating comment", http.StatusInternalServerError)
		return
	}

	log.Println("comment created successfully")

	// Redirect back to the post page
	http.Redirect(w, r, fmt.Sprintf("/view_post/%d", postID), http.StatusSeeOther)
}

func getPostIDFromURL(r *http.Request) (int, error) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		return 0, fmt.Errorf("invalid URL path")
	}
	postID, err := strconv.Atoi(pathParts[len(pathParts)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid post ID")
	}
	return postID, nil
}
func handleAddCommentAJAX(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	postID, err := getPostIDFromURL(r)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	commentText := r.FormValue("comment_text")
	if commentText == "" {
		http.Error(w, "Comment text is required", http.StatusBadRequest)
		return
	}

	// Insert the comment into the database using SQLite's datetime('now') function
	result, err := db.Exec("INSERT INTO Comments(post_id, user_id, comment_text, comment_date) VALUES(?, ?, ?, datetime('now'))", postID, userID, commentText)
	if err != nil {
		log.Printf("Error inserting comment: %v", err)
		http.Error(w, "Error creating comment", http.StatusInternalServerError)
		return
	}

	commentID, _ := result.LastInsertId()

	// Fetch the newly created comment
	var comment Comment
	err = db.QueryRow(`
        SELECT c.comment_id, c.post_id, c.user_id, c.comment_text, c.comment_date, c.like_count, c.dislike_count, u.username 
        FROM Comments c 
        JOIN Users u ON c.user_id = u.user_id 
        WHERE c.comment_id = ?`, commentID).Scan(
		&comment.CommentID, &comment.PostID, &comment.UserID, &comment.CommentText, &comment.CommentDate, &comment.LikeCount, &comment.DislikeCount, &comment.Username)
	if err != nil {
		log.Printf("Error fetching new comment: %v", err)
		http.Error(w, "Error fetching new comment", http.StatusInternalServerError)
		return
	}

	// Return the comment data as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comment)
}

func handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	log.Println("Processing POST request for category creation")

	categoryName := r.FormValue("category_name")
	if categoryName == "" {
		log.Println("Empty category name submitted")
		http.Error(w, "Please provide a category name", http.StatusBadRequest)
		return
	}

	log.Printf("Attempting to create category: %s", categoryName)

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() // Roll back the transaction if it's not committed

	// Insert the category into the Categories table
	result, err := tx.Exec("INSERT INTO Categories(category_name) VALUES(?)", categoryName)
	if err != nil {
		log.Printf("Error inserting category: %v", err)
		http.Error(w, "Error creating category", http.StatusInternalServerError)
		return
	}

	// Get the last inserted ID
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last inserted ID: %v", err)
	} else {
		log.Printf("Category created with ID: %d", lastInsertID)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		http.Error(w, "Error creating category", http.StatusInternalServerError)
		return
	}

	log.Println("Category created successfully")
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func LikeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the request URL path
	postIDStr := strings.TrimPrefix(r.URL.Path, "/like/")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user has already liked the post
	var existingLikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingLikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//method 1: increment 1 and subtract 1
	// if existingLikes > 0 {
	// 	// User has already liked the post, remove their like
	// 	_, err = db.Exec("DELETE FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID)
	// 	if err != nil {
	// 		http.Error(w, "Database error", http.StatusInternalServerError)
	// 		return
	// 	}

	// 	// Update the like count in the posts table
	// 	_, err = db.Exec("UPDATE posts SET like_count = like_count - 1 WHERE post_id = ?", postID)
	// 	if err != nil {
	// 		http.Error(w, "Database error", http.StatusInternalServerError)
	// 		return
	// 	}
	// } else {
	// 	// User has not liked the post, add their like
	// 	_, err = db.Exec("INSERT INTO PostLikes (user_id, post_id) VALUES (?, ?)", userID, postID)
	// 	if err != nil {
	// 		http.Error(w, "Database error", http.StatusInternalServerError)
	// 		return
	// 	}

	// 	// Update the like count in the posts table
	// 	_, err = db.Exec("UPDATE posts SET like_count = like_count + 1 WHERE post_id = ?", postID)
	// 	if err != nil {
	// 		http.Error(w, "Database error", http.StatusInternalServerError)
	// 		return
	// 	}
	// }

	//method 2: by counting the UserIDs per postID

	if existingLikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else {
		// User has not liked the post, add their like
		_, err = db.Exec("INSERT INTO PostLikes (user_id, post_id) VALUES (?, ?)", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	//if the same user.id is on PostLikes then delete it.
	var existingDisikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingDisikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if existingDisikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}
	// Update the dislike count in the posts table
	_, err = db.Exec("UPDATE posts SET dislike_count = (SELECT COUNT(*) FROM PostDislikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Update the like count in the posts table
	_, err = db.Exec("UPDATE posts SET like_count = (SELECT COUNT(*) FROM PostLikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Redirect to the homepage
	http.Redirect(w, r, "/", http.StatusFound)
}

func DislikeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the request URL path
	postIDStr := strings.TrimPrefix(r.URL.Path, "/dislike/")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user has already disliked the post
	var existingDislikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingDislikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//method 2: by counting the UserIDs per postID
	if existingDislikes > 0 {
		// User has already disliked the post, remove their like
		_, err = db.Exec("DELETE FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else {
		// User has not disliked the post, add their dislike
		_, err = db.Exec("INSERT INTO PostDislikes (user_id, post_id) VALUES (?, ?)", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	//if the same user.id is on PostLikes then delete it.
	var existingLikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingLikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if existingLikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	// Update the like count in the posts table
	_, err = db.Exec("UPDATE posts SET like_count = (SELECT COUNT(*) FROM PostLikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Update the dislike count in the posts table
	_, err = db.Exec("UPDATE posts SET dislike_count = (SELECT COUNT(*) FROM PostDislikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Redirect to the homepage
	http.Redirect(w, r, "/", http.StatusFound)
}

func CommentikeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the request URL path
	commentIDStr := strings.TrimPrefix(r.URL.Path, "/clike/")
	CommentID, err := strconv.Atoi(commentIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user has already liked the post
	var existingLikes int
	err = db.QueryRow("SELECT COUNT(*) FROM CommentLikes WHERE user_id = ? AND comment_id = ?", userID, CommentID).Scan(&existingLikes)
	if err != nil {
		http.Error(w, "Database error1", http.StatusInternalServerError)
		return
	}

	//method 2: by counting the UserIDs per postID

	if existingLikes > 0 {
		// User has already liked the comment, remove their like
		_, err = db.Exec("DELETE FROM CommentLikes WHERE user_id = ? AND comment_id = ?", userID, CommentID)
		if err != nil {
			http.Error(w, "Database error2", http.StatusInternalServerError)
			return
		}
	} else {
		// User has not liked the comment, add their like
		_, err = db.Exec("INSERT INTO CommentLikes (user_id, comment_id) VALUES (?, ?)", userID, CommentID)
		if err != nil {
			http.Error(w, "Database error3", http.StatusInternalServerError)
			return
		}
	}

	//if the same user.id is on PostLikes then delete it.
	var existingDisikes int
	err = db.QueryRow("SELECT COUNT(*) FROM CommentDislikes WHERE user_id = ? AND comment_id = ?", userID, CommentID).Scan(&existingDisikes)
	if err != nil {
		http.Error(w, "Database error4", http.StatusInternalServerError)
		return
	}
	if existingDisikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM CommentDislikes WHERE user_id = ? AND comment_id = ?", userID, CommentID)
		if err != nil {
			http.Error(w, "Database error5", http.StatusInternalServerError)
			return
		}
	}
	// Update the dislike count in the posts table
	_, err = db.Exec("UPDATE comments SET dislike_count = (SELECT COUNT(*) FROM CommentDislikes WHERE comment_id = ?) WHERE comment_id = ?", CommentID, CommentID)
	if err != nil {
		http.Error(w, "Database error6", http.StatusInternalServerError)
		return
	}

	// Update the like count in the posts table
	_, err = db.Exec("UPDATE comments SET like_count = (SELECT COUNT(*) FROM CommentLikes WHERE comment_id = ?) WHERE comment_id = ?", CommentID, CommentID)
	if err != nil {
		http.Error(w, "Database error7", http.StatusInternalServerError)
		return
	}

	// Get the post ID for this comment
	postID, err := getPostIDFromCommentID(CommentID)
	if err != nil {
		log.Printf("Error getting post ID: %v", err)
		http.Error(w, "Database error8", http.StatusInternalServerError)
		return
	}

	// Redirect to the post page
	http.Redirect(w, r, fmt.Sprintf("/view_post/%d", postID), http.StatusFound)
}

func CommentDislikeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the request URL path
	commentIDStr := strings.TrimPrefix(r.URL.Path, "/cdislike/")
	commentID, err := strconv.Atoi(commentIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user has already disliked the post
	var existingDislikes int
	err = db.QueryRow("SELECT COUNT(*) FROM CommentDislikes WHERE user_id = ? AND comment_id = ?", userID, commentID).Scan(&existingDislikes)
	if err != nil {
		http.Error(w, "Database error1", http.StatusInternalServerError)
		return
	}

	//method 2: by counting the UserIDs per commentID
	if existingDislikes > 0 {
		// User has already disliked the post, remove their like
		_, err = db.Exec("DELETE FROM CommentDislikes WHERE user_id = ? AND comment_id = ?", userID, commentID)
		if err != nil {
			http.Error(w, "Database error2", http.StatusInternalServerError)
			return
		}
	} else {
		// User has not disliked the post, add their dislike
		_, err = db.Exec("INSERT INTO CommentDislikes (user_id, comment_id) VALUES (?, ?)", userID, commentID)
		if err != nil {
			http.Error(w, "Database error3", http.StatusInternalServerError)
			return
		}
	}

	//if the same user.id is on PostLikes then delete it.
	var existingLikes int
	err = db.QueryRow("SELECT COUNT(*) FROM CommentLikes WHERE user_id = ? AND comment_id = ?", userID, commentID).Scan(&existingLikes)
	if err != nil {
		http.Error(w, "Database error4", http.StatusInternalServerError)
		return
	}
	if existingLikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM CommentLikes WHERE user_id = ? AND comment_id = ?", userID, commentID)
		if err != nil {
			http.Error(w, "Database error5", http.StatusInternalServerError)
			return
		}
	}

	// Update the like count in the posts table
	_, err = db.Exec("UPDATE comments SET like_count = (SELECT COUNT(*) FROM CommentLikes WHERE comment_id = ?) WHERE comment_id = ?", commentID, commentID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Update the dislike count in the posts table
	_, err = db.Exec("UPDATE comments SET dislike_count = (SELECT COUNT(*) FROM CommentDislikes WHERE comment_id = ?) WHERE comment_id = ?", commentID, commentID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Get the post ID for this comment
	postID, err := getPostIDFromCommentID(commentID)
	if err != nil {
		log.Printf("Error getting post ID: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Redirect to the post page
	http.Redirect(w, r, fmt.Sprintf("/view_post/%d", postID), http.StatusFound)
}

func getPostIDFromCommentID(commentID int) (int, error) {
	var postID int
	err := db.QueryRow("SELECT post_id FROM Comments WHERE comment_id = ?", commentID).Scan(&postID)
	if err != nil {
		return 0, err
	}
	return postID, nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	// if !isAuthenticated(r) {
	// 	http.Redirect(w, r, "/login", http.StatusSeeOther)
	// 	fmt.Println("inauthenticated so we sent you to login")
	// 	return
	// }

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err := db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		// http.Redirect(w, r, "/login", http.StatusSeeOther)
		// return
		fmt.Println("guest")
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		// http.Redirect(w, r, "/login", http.StatusSeeOther)
		username = ""
		// return
	}

	// Query the database for all posts
	rows, err := db.Query(`
        SELECT 
            p.post_id, 
            p.user_id, 
            p.post_text, 
            p.post_date, 
            p.like_count, 
            p.dislike_count, 
            u.username, 
            GROUP_CONCAT(c.category_name) AS categories 
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        JOIN Post_Categories pc ON p.post_id = pc.post_id
        JOIN Categories c ON pc.category_id = c.category_id
        GROUP BY p.post_id
        ORDER BY p.post_date DESC
    `)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		var categoriesString string                                                                                                                          // Declare a variable to hold the categories string
		err := rows.Scan(&post.PostID, &post.UserID, &post.PostText, &post.PostDate, &post.LikeCount, &post.DislikeCount, &post.Username, &categoriesString) // Scan the categories string
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Split the categories string into a slice
		post.Categories = strings.Split(categoriesString, ",") // Split the categories string
		posts = append(posts, post)
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		http.Error(w, "Error iterating over database results", http.StatusInternalServerError)
		return
	}

	// Fetch popular categories
	popularCategories, err := getPopularCategories()
	if err != nil {
		log.Printf("Error fetching popular categories: %v", err)
		// Instead of handling the error here, we'll pass an empty slice
		popularCategories = []PopularCategory{}
	}

	// Create a struct to hold both the logged-in username and the users slice
	data := struct {
		LoggedInUser    string
		Posts           []Post
		PopularCategory []PopularCategory
	}{
		LoggedInUser:    username,
		Posts:           posts,
		PopularCategory: popularCategories,
	}

	// Render the index template
	t, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func getPopularCategories() ([]PopularCategory, error) {
	query := `
    SELECT c.category_id, c.category_name, COUNT(pc.post_id) as post_count
    FROM Categories c
    LEFT JOIN Post_Categories pc ON c.category_id = pc.category_id
    GROUP BY c.category_id, c.category_name
    ORDER BY post_count DESC
    LIMIT 5
    `

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []PopularCategory
	for rows.Next() {
		var cat PopularCategory
		if err := rows.Scan(&cat.CategoryID, &cat.CategoryName, &cat.PostCount); err != nil {
			return nil, err
		}
		categories = append(categories, cat)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return categories, nil
}

func LikeHandler2(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the request URL path
	postIDStr := strings.TrimPrefix(r.URL.Path, "/like2/")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user has already liked the post
	var existingLikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingLikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//method 2: by counting the UserIDs per postID

	if existingLikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else {
		// User has not liked the post, add their like
		_, err = db.Exec("INSERT INTO PostLikes (user_id, post_id) VALUES (?, ?)", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	//if the same user.id is on PostLikes then delete it.
	var existingDisikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingDisikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if existingDisikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}
	// Update the dislike count in the posts table
	_, err = db.Exec("UPDATE posts SET dislike_count = (SELECT COUNT(*) FROM PostDislikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Update the like count in the posts table
	_, err = db.Exec("UPDATE posts SET like_count = (SELECT COUNT(*) FROM PostLikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// After updating the like count, redirect back to the view_post page
	http.Redirect(w, r, fmt.Sprintf("/view_post/%d", postID), http.StatusFound)
}

func DislikeHandler2(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the request URL path
	postIDStr := strings.TrimPrefix(r.URL.Path, "/dislike2/")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the session ID from the cookie
	sessionID, _ := getCookie(r, cookieName)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", sessionID).Scan(&userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user has already disliked the post
	var existingDislikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingDislikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//method 2: by counting the UserIDs per postID
	if existingDislikes > 0 {
		// User has already disliked the post, remove their like
		_, err = db.Exec("DELETE FROM PostDislikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else {
		// User has not disliked the post, add their dislike
		_, err = db.Exec("INSERT INTO PostDislikes (user_id, post_id) VALUES (?, ?)", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	//if the same user.id is on PostLikes then delete it.
	var existingLikes int
	err = db.QueryRow("SELECT COUNT(*) FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID).Scan(&existingLikes)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if existingLikes > 0 {
		// User has already liked the post, remove their like
		_, err = db.Exec("DELETE FROM PostLikes WHERE user_id = ? AND post_id = ?", userID, postID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	// Update the like count in the posts table
	_, err = db.Exec("UPDATE posts SET like_count = (SELECT COUNT(*) FROM PostLikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Update the dislike count in the posts table
	_, err = db.Exec("UPDATE posts SET dislike_count = (SELECT COUNT(*) FROM PostDislikes WHERE post_id = ?) WHERE post_id = ?", postID, postID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// After updating the dislike count, redirect back to the view_post page
	http.Redirect(w, r, fmt.Sprintf("/view_post/%d", postID), http.StatusFound)
}
