function likePost(postId) {
    fetch(`/post/${postId}/like`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const likeButton = document.querySelector(`#like-button-${postId}`);
            const likeCount = document.querySelector(`#like-count-${postId}`);
            const currentLikes = parseInt(likeCount.textContent);
            
            if (data.action === 'like') {
                likeButton.classList.add('liked');
                likeButton.innerHTML = `❤️ <span id="like-count-${postId}">${currentLikes + 1}</span>`;
            } else {
                likeButton.classList.remove('liked');
                likeButton.innerHTML = `🖤 <span id="like-count-${postId}">${currentLikes - 1}</span>`;
            }
        }
    });
}

function followUser(username) {
    fetch(`/user/${username}/follow`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        }
    });
}