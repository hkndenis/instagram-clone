class Lightbox {
    constructor() {
        this.currentIndex = 0;
        this.images = [];
        this.initializeLightbox();
        this.bindEvents();
    }

    initializeLightbox() {
        const lightboxHTML = `
            <div class="lightbox-overlay">
                <div class="lightbox-container">
                    <div class="lightbox-image-container">
                        <img src="" alt="" class="lightbox-image">
                        <div class="lightbox-prev lightbox-nav"><span>&#10094;</span></div>
                        <div class="lightbox-next lightbox-nav"><span>&#10095;</span></div>
                    </div>
                    <div class="lightbox-header">
                        <div class="d-flex align-items-center gap-2">
                            <img src="/static/images/Default_pfp.jpg" alt="User avatar" class="rounded-circle" style="width: 32px; height: 32px; object-fit: cover;">
                            <a href="#" class="lightbox-username text-decoration-none text-dark"></a>
                        </div>
                    </div>
                    <div class="lightbox-bottom-bar">
                        <div class="lightbox-like-section">
                            <button class="lightbox-like-button">🖤</button>
                            <span class="lightbox-like-count">0</span>
                            <button class="lightbox-comment-button" style="border: none; background: none; padding: 0; margin-left: 12px; font-size: 1.5rem; cursor: pointer;">💬</button>
                            <span class="lightbox-comment-count">0</span>
                        </div>
                        <div class="lightbox-comment-section">
                            <input type="text" class="lightbox-comment-input" placeholder="Yorum ekle...">
                            <button class="lightbox-comment-submit" disabled>Paylaş</button>
                        </div>
                    </div>
                </div>
                <div class="lightbox-comment-slide">
                    <div class="lightbox-comments-header">
                        <h4 class="m-0 p-3 border-bottom">Yorumlar</h4>
                        <button class="lightbox-comments-close">&times;</button>
                    </div>
                    <div class="lightbox-comments-list"></div>
                </div>
                <div class="lightbox-close">&times;</div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', lightboxHTML);
        
        this.overlay = document.querySelector('.lightbox-overlay');
        this.image = document.querySelector('.lightbox-image');
        this.prevBtn = document.querySelector('.lightbox-prev');
        this.nextBtn = document.querySelector('.lightbox-next');
        this.closeBtn = document.querySelector('.lightbox-close');
        this.username = document.querySelector('.lightbox-username');
        this.commentsList = document.querySelector('.lightbox-comments-list');
        this.likeButton = document.querySelector('.lightbox-like-button');
        this.likeCount = document.querySelector('.lightbox-like-count');
        this.commentButton = document.querySelector('.lightbox-comment-button');
        this.commentCount = document.querySelector('.lightbox-comment-count');
        this.commentInput = document.querySelector('.lightbox-comment-input');
        this.commentSubmit = document.querySelector('.lightbox-comment-submit');
        this.commentSlide = document.querySelector('.lightbox-comment-slide');
        this.commentsCloseBtn = document.querySelector('.lightbox-comments-close');
        
        // Yorum butonuna tıklama olayı
        this.commentButton.addEventListener('click', () => {
            this.commentSlide.classList.add('active');
            this.loadComments(this.currentPostId);
        });

        // Yorum bölümünü kapatma butonu
        this.commentsCloseBtn.addEventListener('click', () => {
            this.commentSlide.classList.remove('active');
        });
    }

    bindEvents() {
        document.querySelectorAll('.post-image').forEach((img, index) => {
            img.addEventListener('click', () => this.openLightbox(index));
        });

        this.prevBtn.addEventListener('click', () => this.navigate(-1));
        this.nextBtn.addEventListener('click', () => this.navigate(1));
        this.closeBtn.addEventListener('click', () => this.closeLightbox());

        document.addEventListener('keydown', (e) => {
            if (this.overlay.style.display !== 'none') {
                if (e.key === 'ArrowLeft') this.navigate(-1);
                if (e.key === 'ArrowRight') this.navigate(1);
                if (e.key === 'Escape') this.closeLightbox();
            }
        });

        this.overlay.addEventListener('click', (e) => {
            if (e.target === this.overlay) this.closeLightbox();
        });

        this.likeButton.addEventListener('click', () => this.toggleLike());

        this.commentInput.addEventListener('input', () => {
            this.commentSubmit.disabled = !this.commentInput.value.trim();
        });

        this.commentSubmit.addEventListener('click', () => this.submitComment());
    }

    openLightbox(index) {
        this.images = Array.from(document.querySelectorAll('.post-image')).map(img => {
            const card = img.closest('.card');
            const likeBtn = card.querySelector('.like-btn');
            const userLink = card.querySelector('.text-dark') || document.querySelector('.profile-username');
            const avatarImg = card.querySelector('.rounded-circle') || document.querySelector('.profile-avatar');
            
            return {
                src: img.src,
                post_id: likeBtn.dataset.postId,
                caption: img.dataset.caption || '',
                username: userLink.textContent.trim(),
                avatar_url: avatarImg ? avatarImg.src : '/static/images/Default_pfp.jpg',
                like_count: parseInt(card.querySelector('.like-count').textContent),
                has_liked: card.querySelector('.like-btn').firstChild.textContent.includes('❤️')
            };
        });
        
        this.currentIndex = index;
        this.updateLightboxContent();
        this.overlay.style.display = 'flex';
        document.body.style.overflow = 'hidden';
        
        // Yorumları yükle
        this.loadComments(this.images[this.currentIndex].post_id);
    }

    loadComments(postId) {
        if (!postId) return;
        
        fetch(`/post/${postId}/comments`)
            .then(response => response.json())
            .then(data => {
                const comments = data.comments || data;
                this.commentsList.innerHTML = '';
                
                if (!Array.isArray(comments) || comments.length === 0) {
                    this.commentsList.innerHTML = '<div class="text-center text-muted p-3">Henüz yorum yapılmamış.</div>';
                    this.commentCount.textContent = '0';
                    return;
                }
                
                this.commentCount.textContent = comments.length;
                const loggedInUsername = sessionStorage.getItem('username');
                
                comments.forEach(comment => {
                    const commentElement = document.createElement('div');
                    commentElement.className = 'lightbox-comment';
                    commentElement.dataset.commentId = comment.comment_id;
                    
                    const isCommentOwner = comment.username === loggedInUsername;
                    const deleteButton = isCommentOwner ? 
                        `<button class="delete-comment-btn" onclick="lightbox.deleteComment(${comment.comment_id})">×</button>` : '';
                    
                    commentElement.innerHTML = `
                        <div class="d-flex align-items-start">
                            <img src="${comment.avatar_url || '/static/images/Default_pfp.jpg'}" 
                                 alt="${comment.username}" 
                                 class="rounded-circle me-2">
                            <div class="flex-grow-1">
                                <div class="d-flex justify-content-between align-items-center">
                                    <a href="/user/${comment.username}" class="fw-bold text-dark text-decoration-none">
                                        ${comment.username}
                                    </a>
                                    <div class="d-flex align-items-center gap-2">
                                        <small class="text-muted">
                                            ${new Date(comment.created_at).toLocaleDateString('tr-TR')}
                                        </small>
                                        ${deleteButton}
                                    </div>
                                </div>
                                <p class="mb-1 mt-1">${comment.comment_text}</p>
                                <div class="d-flex align-items-center gap-2">
                                    <button class="btn btn-sm comment-like-btn p-0" 
                                            data-comment-id="${comment.comment_id}">
                                        ${comment.has_liked ? '❤️' : '🖤'}
                                    </button>
                                    <small class="comment-like-count">
                                        ${comment.like_count || 0}
                                    </small>
                                </div>
                            </div>
                        </div>
                    `;
                    
                    const likeBtn = commentElement.querySelector('.comment-like-btn');
                    likeBtn.addEventListener('click', () => this.toggleCommentLike(comment.comment_id, likeBtn));
                    
                    this.commentsList.appendChild(commentElement);
                });
            })
            .catch(error => {
                console.error('Yorumlar yüklenirken hata:', error);
                this.commentsList.innerHTML = '<div class="text-center text-danger p-3">Yorumlar yüklenirken bir hata oluştu.</div>';
            });
    }

    deleteComment(commentId) {
        if (!confirm('Bu yorumu silmek istediğinizden emin misiniz?')) {
            return;
        }

        fetch(`/comment/${commentId}/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Yorumu DOM'dan kaldır
                const commentElement = this.commentsList.querySelector(`[data-comment-id="${commentId}"]`);
                if (commentElement) {
                    commentElement.remove();
                    // Yorum sayısını güncelle
                    const currentCount = parseInt(this.commentCount.textContent);
                    this.commentCount.textContent = currentCount - 1;
                }
            } else {
                alert(data.message || 'Yorum silinirken bir hata oluştu');
            }
        })
        .catch(error => {
            console.error('Yorum silinirken hata:', error);
            alert('Yorum silinirken bir hata oluştu');
        });
    }

    async toggleCommentLike(commentId, likeBtn) {
        try {
            const response = await fetch(`/comment/${commentId}/like`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
                }
            });
            const data = await response.json();
            
            if (data.success) {
                const likeCount = likeBtn.nextElementSibling;
                if (data.action === 'like') {
                    likeBtn.textContent = '❤️';
                    likeCount.textContent = parseInt(likeCount.textContent) + 1;
                } else {
                    likeBtn.textContent = '🖤';
                    likeCount.textContent = parseInt(likeCount.textContent) - 1;
                }
            }
        } catch (error) {
            console.error('Yorum beğeni işlemi sırasında hata oluştu:', error);
        }
    }

    async toggleLike() {
        const currentImage = this.images[this.currentIndex];
        const postId = currentImage.post_id;
        try {
            const response = await fetch(`/post/${postId}/like`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
                }
            });
            const data = await response.json();
            
            if (data.success) {
                if (data.action === 'like') {
                    this.likeButton.textContent = '❤️';
                    currentImage.like_count++;
                    currentImage.has_liked = true;
                } else {
                    this.likeButton.textContent = '🖤';
                    currentImage.like_count--;
                    currentImage.has_liked = false;
                }
                this.likeCount.textContent = currentImage.like_count;
                
                // Ana sayfadaki beğeni sayısını da güncelle
                const mainPageLikeBtn = document.querySelector(`[data-post-id="${postId}"]`);
                const mainPageLikeCount = mainPageLikeBtn.querySelector('.like-count');
                mainPageLikeCount.textContent = currentImage.like_count;
                mainPageLikeBtn.firstChild.textContent = currentImage.has_liked ? '❤️' : '🖤';
            }
        } catch (error) {
            console.error('Beğeni işlemi sırasında hata oluştu:', error);
        }
    }

    async submitComment() {
        const comment = this.commentInput.value.trim();
        if (!comment) return;

        const currentImage = this.images[this.currentIndex];
        const postId = currentImage.post_id;
        try {
            const response = await fetch(`/post/${postId}/comments`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
                },
                body: JSON.stringify({ comment_text: comment })
            });
            
            if (response.ok) {
                this.commentInput.value = '';
                this.commentSubmit.disabled = true;
                await this.loadComments(postId);
                
                // Ana sayfadaki yorum sayısını güncelle
                const mainPageCommentCount = document.querySelector(`[data-post-id="${postId}"]`)
                    .closest('.card')
                    .querySelector('.comment-count');
                mainPageCommentCount.textContent = parseInt(mainPageCommentCount.textContent) + 1;
            }
        } catch (error) {
            console.error('Yorum gönderilirken hata oluştu:', error);
        }
    }

    closeLightbox() {
        this.overlay.style.display = 'none';
        document.body.style.overflow = 'auto';
        // Lightbox kapanırken yorum bölümünü de kapat
        this.commentSlide.classList.remove('active');
    }

    navigate(direction) {
        this.currentIndex = (this.currentIndex + direction + this.images.length) % this.images.length;
        this.updateLightboxContent();
        // Yeni posta geçerken yorum bölümünü kapat
        this.commentSlide.classList.remove('active');
    }

    updateLightboxContent() {
        const currentImage = this.images[this.currentIndex];
        this.currentPostId = currentImage.post_id;
        this.image.src = currentImage.src;
        
        const userAvatar = this.overlay.querySelector('.lightbox-header img');
        userAvatar.src = currentImage.avatar_url;
        this.username.href = `/user/${currentImage.username}`;
        this.username.textContent = currentImage.username;
        
        // Caption güncelleme
        let captionElement = this.overlay.querySelector('.lightbox-caption');
        if (!captionElement) {
            captionElement = document.createElement('p');
            captionElement.className = 'lightbox-caption';
            captionElement.style.padding = '10px 16px';
            captionElement.style.margin = '0';
            captionElement.style.borderBottom = '1px solid #dbdbdb';
            const header = this.overlay.querySelector('.lightbox-header');
            header.insertAdjacentElement('afterend', captionElement);
        }
        captionElement.textContent = currentImage.caption;
        
        this.likeButton.innerHTML = currentImage.has_liked ? '❤️' : '🖤';
        this.likeCount.textContent = currentImage.like_count;
        
        fetch(`/post/${currentImage.post_id}/comments`)
            .then(response => response.json())
            .then(data => {
                const comments = data.comments || data;
                this.commentCount.textContent = Array.isArray(comments) ? comments.length : '0';
            })
            .catch(error => {
                console.error('Yorum sayısı alınırken hata:', error);
                this.commentCount.textContent = '0';
            });
    }

    openWithData(data) {
        this.currentPostId = data.post_id;
        this.image.src = data.image_url;
        const userAvatar = this.overlay.querySelector('.lightbox-header img');
        userAvatar.src = data.avatar_url || '/static/images/Default_pfp.jpg';
        this.username.href = `/user/${data.username}`;
        this.username.textContent = data.username;
        
        // Caption'ı ekle
        let captionElement = this.overlay.querySelector('.lightbox-caption');
        if (!captionElement) {
            captionElement = document.createElement('p');
            captionElement.className = 'lightbox-caption';
            captionElement.style.padding = '10px 16px';
            captionElement.style.margin = '0';
            captionElement.style.borderBottom = '1px solid #dbdbdb';
            const header = this.overlay.querySelector('.lightbox-header');
            header.insertAdjacentElement('afterend', captionElement);
        }
        captionElement.textContent = data.caption;
        
        this.likeButton.innerHTML = data.has_liked ? '❤️' : '🖤';
        this.likeCount.textContent = data.like_count;
        this.commentCount.textContent = data.comment_count || '0';
        
        this.loadComments(data.post_id);
        this.overlay.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
}

const lightboxStyles = `
    .lightbox-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        display: none;
        justify-content: center;
        align-items: center;
        z-index: 1000;
    }
    
    .lightbox-container {
        display: flex;
        flex-direction: column;
        max-width: 90%;
        max-height: 90vh;
        background: white;
        border-radius: 8px;
        overflow: hidden;
        width: 1200px;
    }
    
    .lightbox-image-container {
        position: relative;
        background: black;
        min-height: 600px;
        width: 100%;
    }
    
    .lightbox-image {
        width: 100%;
        height: 100%;
        object-fit: contain;
    }
    
    .lightbox-header {
        padding: 12px 16px;
        border-bottom: 1px solid #dbdbdb;
        background: white;
    }
    
    .lightbox-comments {
        position: relative;
        width: 100%;
        display: flex;
        flex-direction: column;
        background: white;
        border-top: 1px solid #dbdbdb;
        max-height: 300px;
    }
    
    .lightbox-comments-list {
        flex: 1;
        overflow-y: auto;
        padding: 16px;
        background-color: white;
        height: calc(100% - 120px);
    }
    
    .lightbox-comment {
        margin-bottom: 12px;
        padding: 8px;
        border-radius: 4px;
        background-color: #fafafa;
        border: 1px solid #efefef;
    }
    
    .lightbox-bottom-bar {
        position: relative;
        bottom: 0;
        left: 0;
        right: 0;
        padding: 12px 16px;
        background-color: white;
        border-top: 1px solid #dbdbdb;
        display: flex;
        align-items: center;
        gap: 16px;
        height: 60px;
    }
    
    .lightbox-like-section {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .lightbox-like-button {
        border: none;
        background: none;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 0;
    }

    .lightbox-like-count {
        font-size: 14px;
        min-width: 20px;
    }
    
    .lightbox-comment-section {
        display: flex;
        align-items: center;
        gap: 8px;
        flex: 1;
        margin-right: 16px;
    }
    
    .lightbox-comment-input {
        flex: 1;
        border: 1px solid #dbdbdb;
        border-radius: 4px;
        outline: none;
        font-size: 14px;
        padding: 8px 12px;
    }
    
    .lightbox-comment-submit {
        border: none;
        background: none;
        color: #0095f6;
        font-weight: 600;
        cursor: pointer;
        padding: 0;
        font-size: 14px;
    }
    
    .lightbox-comment-submit:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    
    .lightbox-nav {
        position: absolute;
        top: 50%;
        transform: translateY(-50%);
        color: white;
        font-size: 24px;
        cursor: pointer;
        width: 40px;
        height: 40px;
        background-color: transparent;
        border-radius: 50%;
        display: flex;
        align-items: center;
        z-index: 10;
        padding: 0;
    }
    
    .lightbox-prev {
        left: 0;
        justify-content: flex-end;
    }
    
    .lightbox-next {
        right: 0;
        justify-content: flex-end;
    }
    
    .lightbox-nav span {
        margin: 0 12px;
    }
    
    .lightbox-close {
        position: fixed;
        top: 20px;
        right: 20px;
        color: white;
        font-size: 30px;
        cursor: pointer;
    }
`;

const styleSheet = document.createElement("style");
styleSheet.textContent = lightboxStyles;
document.head.appendChild(styleSheet);

document.addEventListener('DOMContentLoaded', () => {
    new Lightbox();
}); 