document.addEventListener('DOMContentLoaded', () => {
    const likeButtons = document.querySelectorAll('button[id^="like-button-"]');

    likeButtons.forEach(button => {
        button.addEventListener('click', async () => {
            const postId = button.dataset.postId;
            const likeCountElement = document.getElementById(`like-count-${postId}`);

            try {
                const response = await fetch(`/like/${postId}`, {
                    method: 'POST'
                });

                if (response.ok) {
                    const data = await response.json();
                    likeCountElement.textContent = data.like_count;
                } else {
                    // Handle error (e.g., display an error message)
                    console.error('Error liking post:', response.status);
                }
            } catch (error) {
                console.error('Error liking post:', error);
            }
        });
    });
});