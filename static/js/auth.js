function handleLogin(event) {
    event.preventDefault();
    
    const formData = new FormData(loginForm);
    const data = {
        username: formData.get('username'),
        password: formData.get('password')
    };
    
    fetch('/web/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Session storage'a kullanıcı bilgilerini kaydet
            sessionStorage.setItem('user_id', data.user_id);
            sessionStorage.setItem('username', data.username);
            window.location.href = '/';
        } else {
            showError(loginError, data.message);
        }
    })
    .catch(error => {
        console.error('Giriş hatası:', error);
        showError(loginError, 'Giriş yapılırken bir hata oluştu.');
    });
}

function showError(element, message) {
    element.textContent = message;
    element.style.display = 'block';
} 