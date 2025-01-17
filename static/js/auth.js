function handleLogin(event) {
    event.preventDefault();
    
    const formData = new FormData(loginForm);
    
    fetch('/login', {
        method: 'POST',
        body: formData
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