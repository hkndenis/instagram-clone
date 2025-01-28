from flask import Flask, render_template, request, redirect, url_for, flash,send_file, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
import psycopg2
from psycopg2.extras import RealDictCursor
from functools import wraps
import os
import random
from datetime import datetime, timedelta
import time
from dotenv import load_dotenv
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key')  # Güvenli bir secret key kullanın
csrf = CSRFProtect()
csrf.init_app(app)
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": [
            "http://192.168.18.5:5000",
            "http://localhost:5000", 
            "http://127.0.0.1:5000",
            "http://localhost:19006",  # Web için Expo development portu
            "http://127.0.0.1:19006"   # Web için alternatif port
        ],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_FOLDER = os.path.join(BASE_DIR, 'static')
UPLOAD_FOLDER = os.path.join(STATIC_FOLDER, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Klasörleri oluştur
os.makedirs(STATIC_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# İzinleri ayarla
os.chmod(STATIC_FOLDER, 0o755)
os.chmod(UPLOAD_FOLDER, 0o755)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-size

# .env dosyasını yükle
load_dotenv()

def get_user_by_id(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    
    cur.close()
    conn.close()
    
    return user

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer token'ı ayıkla
            except IndexError:
                return jsonify({'message': 'Token geçersiz!'}), 401
                
        if not token:
            return jsonify({'message': 'Token bulunamadı!'}), 401
            
        try:
            user_id = int(token)  # Basit token kontrolü
            current_user = get_user_by_id(user_id)
            if not current_user:
                return jsonify({'message': 'Geçersiz token!'}), 401
        except:
            return jsonify({'message': 'Geçersiz token!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Session ayarlarını güncelle
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Geliştirme için False, production'da True olmalı

@app.route('/static/<path:filename>')
def serve_static(filename):
    try:
        # Debug için
        print(f"Requested file: {filename}")
        print(f"Static folder: {STATIC_FOLDER}")
        
        return send_from_directory(
            STATIC_FOLDER,
            filename,
            as_attachment=False
        )
    except Exception as e:
        print(f"Serve static error: {str(e)}")
        return str(e), 404
        
    except Exception as e:
        print(f"Dosya servis hatası: {str(e)}")
        return '', 404
    
# Veritabanı bağlantı bilgileri
DB_CONFIG = {
    'dbname': os.environ.get('DB_NAME', 'instagram_clone'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', ''),  # Şifreyi environment variable'dan al
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('PORT', '5432')
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Avatar URL sütununu ekle
        cur.execute("""
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS avatar_url TEXT 
            DEFAULT '/static/images/Default_pfp.jpg'
        """)
        
        # Mevcut NULL, boş veya eski varsayılan avatar_url değerlerini güncelle
        cur.execute("""
            UPDATE users 
            SET avatar_url = '/static/images/Default_pfp.jpg' 
            WHERE avatar_url IS NULL 
            OR avatar_url = '' 
            OR avatar_url = '/static/images/default-avatar.png'
        """)
        
        conn.commit()
    except Exception as e:
        print(f"Veritabanı başlatma hatası: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

# Uygulama başlatıldığında veritabanını başlat
init_db()

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user and (not user['avatar_url'] or user['avatar_url'] == '/static/images/default-avatar.png'):
        user['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    return user

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user and (not user['avatar_url'] or user['avatar_url'] == '/static/images/default-avatar.png'):
        user['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    return user

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""SELECT p.*, u.username, u.avatar_url,
        COUNT(DISTINCT l.like_id) as like_count,
        COUNT(DISTINCT c.comment_id) as comment_count,
        EXISTS(
            SELECT 1 FROM likes 
            WHERE post_id = p.post_id 
            AND user_id = %s
        ) as user_has_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        LEFT JOIN comments c ON p.post_id = c.post_id
        GROUP BY p.post_id, u.username, u.avatar_url
        ORDER BY p.created_at DESC""", (session['user_id'],))
    posts = cur.fetchall()
    
    # Her post için avatar_url kontrolü
    for post in posts:
        if not post['avatar_url'] or post['avatar_url'] == '/static/images/default-avatar.png':
            post['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    cur.close()
    conn.close()
    return render_template('index.html', posts=posts)

@csrf.exempt
@app.route('/api/login', methods=['POST'])  # /login yerine /api/login
def api_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"Mobile login attempt for user: {username}")
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            token = str(user['user_id'])  # Mobil için token kullan
            print(f"Mobile login successful for user: {username}")
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'id': user['user_id'],
                    'username': user['username']
                }
            })
        else:
            print(f"Mobile login failed for user: {username}")
            return jsonify({
                'success': False,
                'message': 'Kullanıcı adı veya şifre hatalı'
            }), 401
            
    except Exception as e:
        print(f"Mobile login error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Giriş sırasında bir hata oluştu'
        }), 400
    
@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@csrf.exempt
@app.route('/web/login', methods=['POST'])
def web_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"Web login attempt for user: {username}")
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['user_id']  # Web için session kullan
            print(f"Web login successful for user: {username}")
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['user_id'],
                    'username': user['username']
                }
            })
        else:
            print(f"Web login failed for user: {username}")
            return jsonify({
                'success': False,
                'message': 'Kullanıcı adı veya şifre hatalı'
            }), 401
            
    except Exception as e:
        print(f"Web login error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Giriş sırasında bir hata oluştu'
        }), 400

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, full_name, avatar_url) VALUES (%s, %s, %s, %s, %s)",
                (username, email, generate_password_hash(password), full_name, '/static/images/Default_pfp.jpg')
            )
            conn.commit()
            flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            conn.rollback()
            flash('Kayıt sırasında bir hata oluştu!', 'error')
        finally:
            cur.close() 
            conn.close()
    
    return render_template('register.html')

@csrf.exempt
@app.route('/web/create-post', methods=['GET', 'POST'])
def web_create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'image' not in request.files:
                flash('Lütfen bir resim seçin', 'danger')
                return redirect(request.url)
            
            image = request.files['image']
            caption = request.form.get('caption', '')
            
            if image and allowed_file(image.filename):
                filename = f"post_{session['user_id']}_{int(time.time())}_{secure_filename(image.filename)}"
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                image.save(filepath)
                
                # Veritabanına kaydet
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO posts (user_id, image_url, caption) VALUES (%s, %s, %s)",
                    (session['user_id'], f'/static/uploads/{filename}', caption)
                )
                conn.commit()
                cur.close()
                conn.close()
                
                flash('Gönderi başarıyla oluşturuldu!', 'success')
                return redirect(url_for('index'))
            
            flash('Geçersiz dosya formatı', 'danger')
            return redirect(request.url)
            
        except Exception as e:
            print(f"Web post oluşturma hatası: {str(e)}")
            flash('Gönderi oluşturulamadı', 'danger')
            return redirect(request.url)
    
    return render_template('create_post.html')

@app.route('/post/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Login required'})
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Beğeni durumunu kontrol et
        cur.execute("""
            SELECT like_id FROM likes 
            WHERE post_id = %s AND user_id = %s
        """, (post_id, session['user_id']))
        
        existing_like = cur.fetchone()
        
        if existing_like:
            # Beğeniyi kaldır
            cur.execute("DELETE FROM likes WHERE like_id = %s", (existing_like[0],))
            action = 'unlike'
        else:
            # Beğeni ekle
            cur.execute(
                "INSERT INTO likes (post_id, user_id) VALUES (%s, %s)",
                (post_id, session['user_id'])
            )
            action = 'like'
            
        conn.commit()
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cur.close()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/post/<int:post_id>/comments', methods=['GET', 'POST'])
def post_comments(post_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Giriş yapmanız gerekiyor'}), 401
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            comment_text = data.get('comment_text')
            
            if not comment_text or not comment_text.strip():
                return jsonify({'success': False, 'message': 'Yorum boş olamaz'}), 400
            
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute("""
                INSERT INTO comments (post_id, user_id, comment_text)
                VALUES (%s, %s, %s)
                RETURNING comment_id, created_at
            """, (post_id, session['user_id'], comment_text))
            
            new_comment = cursor.fetchone()
            
            cursor.execute("""
                SELECT c.*, u.username, u.avatar_url,
                       0 as like_count,
                       false as has_liked
                FROM comments c 
                JOIN users u ON c.user_id = u.user_id
                WHERE c.comment_id = %s
            """, (new_comment['comment_id'],))
            
            comment = cursor.fetchone()
            
            if not comment['avatar_url']:
                comment['avatar_url'] = '/static/images/Default_pfp.jpg'
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'comment': comment
            })
            
        except Exception as e:
            print(f"Hata: {str(e)}")
            return jsonify({'success': False, 'message': 'Bir hata oluştu'}), 500
    
    return get_post_comments(post_id)

@app.route('/my-posts')
def my_posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Kullanıcı bilgilerini getir
    cur.execute("""
        SELECT * FROM users WHERE user_id = %s
    """, (session['user_id'],))
    user = cur.fetchone()
    
    # Takipçi sayısını getir
    cur.execute("""
        SELECT COUNT(*) as follower_count 
        FROM followers 
        WHERE followed_user_id = %s
    """, (session['user_id'],))
    follower_count = cur.fetchone()['follower_count']
    
    # Takip edilen sayısını getir
    cur.execute("""
        SELECT COUNT(*) as following_count 
        FROM followers 
        WHERE follower_user_id = %s
    """, (session['user_id'],))
    following_count = cur.fetchone()['following_count']
    
    # Avatar URL kontrolü
    if not user['avatar_url'] or user['avatar_url'] == '/static/images/default-avatar.png':
        user['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    # Kullanıcının gönderilerini getir
    cur.execute("""
        SELECT p.*, u.username, u.avatar_url,
               COUNT(DISTINCT l.like_id) as like_count,
               COUNT(DISTINCT c.comment_id) as comment_count,
               EXISTS(
                   SELECT 1 FROM likes 
                   WHERE post_id = p.post_id 
                   AND user_id = %s
               ) as user_has_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        LEFT JOIN comments c ON p.post_id = c.post_id
        WHERE p.user_id = %s
        GROUP BY p.post_id, u.username, u.avatar_url
        ORDER BY p.created_at DESC
    """, (session['user_id'], session['user_id']))
    posts = cur.fetchall()
    
    # Her post için avatar_url kontrolü
    for post in posts:
        if not post['avatar_url'] or post['avatar_url'] == '/static/images/default-avatar.png':
            post['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    cur.close()
    conn.close()
    return render_template('my_posts.html', posts=posts, user=user, follower_count=follower_count, following_count=following_count)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Önce postun sahibi olduğundan emin olalım
        cur.execute("SELECT user_id FROM posts WHERE post_id = %s", (post_id,))
        post = cur.fetchone()
        
        if not post or post[0] != session['user_id']:
            flash('Bu gönderiyi silme yetkiniz yok!', 'error')
            return redirect(url_for('my_posts'))
        
        # Önce bağlı beğenileri ve yorumları silelim
        cur.execute("DELETE FROM likes WHERE post_id = %s", (post_id,))
        cur.execute("DELETE FROM comments WHERE post_id = %s", (post_id,))
        
        # Sonra postu silelim
        cur.execute("DELETE FROM posts WHERE post_id = %s", (post_id,))
        conn.commit()
        
        flash('Gönderi başarıyla silindi!', 'success')
    except psycopg2.Error as e:
        conn.rollback()
        flash('Gönderi silinirken bir hata oluştu!', 'error')
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('my_posts'))

@app.route('/popular-users')
def popular_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # En çok takipçisi olan kullanıcılar
    cur.execute("""
        SELECT u.username, u.full_name, 
               COUNT(DISTINCT f.follower_user_id) as follower_count,
               COUNT(DISTINCT p.post_id) as post_count
        FROM users u
        LEFT JOIN followers f ON u.user_id = f.followed_user_id
        LEFT JOIN posts p ON u.user_id = p.user_id
        GROUP BY u.user_id
        ORDER BY follower_count DESC
        LIMIT 10
    """)
    popular_users = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('popular_users.html', users=popular_users)

@app.route('/mutual-followers')
def mutual_followers():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Karşılıklı takipleşenleri getir
    cur.execute("""
        SELECT u.username, u.full_name,
               COUNT(DISTINCT p.post_id) as post_count,
               COUNT(DISTINCT l.like_id) as total_likes_received
        FROM users u
        INNER JOIN followers f1 ON u.user_id = f1.followed_user_id
        INNER JOIN followers f2 ON u.user_id = f2.follower_user_id
        LEFT JOIN posts p ON u.user_id = p.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        WHERE f1.follower_user_id = f2.followed_user_id
        AND f1.followed_user_id = f2.follower_user_id
        AND (f1.follower_user_id = %s OR f1.followed_user_id = %s)
        GROUP BY u.user_id
        ORDER BY total_likes_received DESC
    """, (session['user_id'], session['user_id']))
    mutual_followers = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('mutual_followers.html', mutual_followers=mutual_followers)

@app.route('/trending-posts')
def trending_posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # En çok etkileşim alan gönderileri getir
    cur.execute("""
        SELECT p.*, u.username, u.avatar_url,
               COUNT(DISTINCT l.like_id) as like_count,
               COUNT(DISTINCT c.comment_id) as comment_count,
               (COUNT(DISTINCT l.like_id) + COUNT(DISTINCT c.comment_id)) as total_interactions,
               EXISTS(
                   SELECT 1 FROM likes 
                   WHERE post_id = p.post_id 
                   AND user_id = %s
               ) as user_has_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        LEFT JOIN comments c ON p.post_id = c.post_id
        GROUP BY p.post_id, u.username, u.avatar_url
        HAVING COUNT(DISTINCT l.like_id) + COUNT(DISTINCT c.comment_id) > 0
        ORDER BY total_interactions DESC
        LIMIT 20
    """, (session['user_id'],))
    trending_posts = cur.fetchall()
    
    # Her post için avatar_url kontrolü
    for post in trending_posts:
        if not post['avatar_url'] or post['avatar_url'] == '/static/images/default-avatar.png':
            post['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    cur.close()
    conn.close()
    return render_template('trending_posts.html', posts=trending_posts)

@app.route('/active-commenters')
def active_commenters():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # En aktif yorum yapan kullanıcılar
    cur.execute("""
        SELECT u.username, u.full_name,
               COUNT(c.comment_id) as comment_count
        FROM users u
        JOIN comments c ON u.user_id = c.user_id
        GROUP BY u.user_id
        ORDER BY comment_count DESC
        LIMIT 10
    """)
    active_commenters = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('active_commenters.html', users=active_commenters)

@app.route('/user/<username>')
def user_profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # Kullanıcı bilgilerini al
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    
    if user is None:
        conn.close()
        return "Kullanıcı bulunamadı", 404

    # Gönderi sayısını al
    cursor.execute('SELECT COUNT(*) FROM posts WHERE user_id = %s', (user['user_id'],))
    post_count = cursor.fetchone()['count']

    # Takipçi sayısını al
    cursor.execute('SELECT COUNT(*) FROM followers WHERE followed_user_id = %s', (user['user_id'],))
    follower_count = cursor.fetchone()['count']

    # Takip edilen sayısını al
    cursor.execute('SELECT COUNT(*) FROM followers WHERE follower_user_id = %s', (user['user_id'],))
    following_count = cursor.fetchone()['count']

    # Takip durumunu kontrol et
    cursor.execute('''
        SELECT EXISTS(
            SELECT 1 FROM followers 
            WHERE follower_user_id = %s AND followed_user_id = %s
        )
    ''', (session['user_id'], user['user_id']))
    is_following = cursor.fetchone()['exists']

    # Kullanıcının gönderilerini al
    cursor.execute('''
        SELECT p.*, 
               (SELECT COUNT(*) FROM likes WHERE post_id = p.post_id) as like_count,
                (SELECT COUNT(*) FROM comments WHERE post_id = p.post_id) as comment_count,
                EXISTS(SELECT 1 FROM likes WHERE post_id = p.post_id AND user_id = %s) as user_has_liked
        FROM posts p
        WHERE p.user_id = %s
        ORDER BY p.created_at DESC
    ''', (session['user_id'], user['user_id']))
    posts = cursor.fetchall()

    conn.close()

    return render_template('user_profile.html', 
                         user=user, 
                         posts=posts, 
                         post_count=post_count,
                         follower_count=follower_count,
                         following_count=following_count,
                         is_following=is_following)

@app.route('/user/<username>/follow', methods=['POST'])
def follow_user(username):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Giriş yapmalısınız'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Takip edilecek kullanıcıyı bul
    cursor.execute('SELECT user_id FROM users WHERE username = %s', (username,))
    followed_user = cursor.fetchone()

    if followed_user is None:
        conn.close()
        return jsonify({'success': False, 'message': 'Kullanıcı bulunamadı'}), 404

    # Kendini takip etmeyi engelle
    if followed_user[0] == session['user_id']:
        conn.close()
        return jsonify({'success': False, 'message': 'Kendinizi takip edemezsiniz'}), 400

    try:
        cursor.execute('''
            INSERT INTO followers (follower_user_id, followed_user_id) 
            VALUES (%s, %s)
        ''', (session['user_id'], followed_user[0]))
        conn.commit()
        success = True
        message = 'Kullanıcı takip edildi'
    except psycopg2.Error as e:
        conn.rollback()
        success = False
        message = 'Bir hata oluştu'

    conn.close()
    return jsonify({'success': success, 'message': message})

@app.route('/user/<username>/unfollow', methods=['POST'])
def unfollow_user(username):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Giriş yapmalısınız'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    # Takipten çıkarılacak kullanıcıyı bul
    cursor.execute('SELECT user_id FROM users WHERE username = %s', (username,))
    followed_user = cursor.fetchone()

    if followed_user is None:
        conn.close()
        return jsonify({'success': False, 'message': 'Kullanıcı bulunamadı'}), 404

    try:
        cursor.execute('''
            DELETE FROM followers 
            WHERE follower_user_id = %s AND followed_user_id = %s
        ''', (session['user_id'], followed_user[0]))
        conn.commit()
        success = True
        message = 'Takipten çıkarıldı'
    except psycopg2.Error as e:
        conn.rollback()
        success = False
        message = 'Bir hata oluştu'

        conn.close()
    return jsonify({'success': success, 'message': message})

@app.route('/inactive-users')
def inactive_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Hiç yorum yapmamış kullanıcılar
    cur.execute("""
        SELECT u.username, u.full_name, u.created_at,
               COUNT(DISTINCT p.post_id) as post_count,
               COUNT(DISTINCT f.follower_id) as follower_count
        FROM users u
        LEFT JOIN comments c ON u.user_id = c.user_id
        LEFT JOIN posts p ON u.user_id = p.user_id
        LEFT JOIN followers f ON u.user_id = f.followed_user_id
        WHERE c.comment_id IS NULL
        GROUP BY u.user_id
        ORDER BY u.created_at DESC
    """)
    users = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('inactive_users.html', users=users)

@app.route('/recent-activity')
def recent_activity():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Son 24 saat içindeki aktiviteleri getir
    cur.execute("""
        (SELECT 
            'like' as activity_type,
            u.username,
            p.post_id,
            l.created_at as activity_time,
            NULL as comment_text
        FROM likes l
        JOIN users u ON l.user_id = u.user_id
        JOIN posts p ON l.post_id = p.post_id
        WHERE l.created_at > NOW() - INTERVAL '24 hours')
        
        UNION ALL
        
        (SELECT 
            'comment' as activity_type,
            u.username,
            p.post_id,
            c.created_at as activity_time,
            c.comment_text
        FROM comments c
        JOIN users u ON c.user_id = u.user_id
        JOIN posts p ON c.post_id = p.post_id
        WHERE c.created_at > NOW() - INTERVAL '24 hours')
        
        ORDER BY activity_time DESC
    """)
    activities = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('recent_activity.html', activities=activities)

@app.route('/popular-hashtags')
def popular_hashtags():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # En popüler hashtagleri getir
    cur.execute("""
        WITH hashtags AS (
            SELECT DISTINCT unnest(regexp_matches(lower(caption), '#[a-zA-Z0-9_]+', 'g')) as tag
            FROM posts
        )
        SELECT 
            tag,
            COUNT(*) as usage_count,
            COUNT(DISTINCT p.user_id) as unique_users,
            COUNT(DISTINCT l.like_id) as total_likes
        FROM hashtags h
        JOIN posts p ON lower(p.caption) LIKE '%' || h.tag || '%'
        LEFT JOIN likes l ON p.post_id = l.post_id
        GROUP BY tag
        ORDER BY usage_count DESC
        LIMIT 20
    """)
    hashtags = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('popular_hashtags.html', hashtags=hashtags)

@app.route('/user-engagement')
def user_engagement():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Kullanıcı etkileşim oranlarını getir
    cur.execute("""
        SELECT 
            u.username,
            COUNT(DISTINCT p.post_id) as post_count,
            COUNT(DISTINCT l.like_id) as likes_given,
            COUNT(DISTINCT l2.like_id) as likes_received,
            COUNT(DISTINCT c.comment_id) as comments_made,
            COUNT(DISTINCT c2.comment_id) as comments_received,
            COUNT(DISTINCT f.follower_id) as followers,
            COUNT(DISTINCT f2.follower_id) as following,
            CASE 
                WHEN COUNT(DISTINCT p.post_id) = 0 THEN 0.0
                ELSE (
                    (COUNT(DISTINCT l2.like_id)::float + COUNT(DISTINCT c2.comment_id)::float) / 
                    COUNT(DISTINCT p.post_id)::float
                )::numeric(10,2)
            END as engagement_rate
        FROM users u
        LEFT JOIN posts p ON u.user_id = p.user_id
        LEFT JOIN likes l ON u.user_id = l.user_id
        LEFT JOIN likes l2 ON p.post_id = l2.post_id
        LEFT JOIN comments c ON u.user_id = c.user_id
        LEFT JOIN comments c2 ON p.post_id = c2.post_id
        LEFT JOIN followers f ON u.user_id = f.followed_user_id
        LEFT JOIN followers f2 ON u.user_id = f2.follower_user_id
        GROUP BY u.user_id, u.username
        ORDER BY engagement_rate DESC
    """)
    engagements = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('user_engagement.html', engagements=engagements)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        
        # Yeni şifrenin hash'ini oluştur
        password_hash = generate_password_hash(new_password)
        
        # Veritabanında güncelle
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE username = %s",
            (password_hash, username)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        flash('Şifreniz başarıyla güncellendi!', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')

@app.route('/most-liked-photos')
def most_liked_photos():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # En çok beğeni alan fotoğrafları getir
    cur.execute("""
        SELECT p.*, u.username, u.avatar_url,
               COUNT(DISTINCT l.like_id) as like_count,
               COUNT(DISTINCT c.comment_id) as comment_count,
               EXISTS(
                   SELECT 1 FROM likes 
                   WHERE post_id = p.post_id 
                   AND user_id = %s
               ) as user_has_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        LEFT JOIN comments c ON p.post_id = c.post_id
        GROUP BY p.post_id, u.username, u.avatar_url
        ORDER BY like_count DESC
        LIMIT 20
    """, (session['user_id'],))
    
    most_liked_photos = cur.fetchall()
    
    # Her post için avatar_url kontrolü
    for photo in most_liked_photos:
        if not photo['avatar_url'] or photo['avatar_url'] == '/static/images/default-avatar.png':
            photo['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    cur.close()
    conn.close()
    
    return render_template('most_liked_photos.html', photos=most_liked_photos)

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Giriş yapmanız gerekiyor'})
    
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'Dosya yüklenmedi'})
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Dosya seçilmedi'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Benzersiz bir dosya adı oluştur
        unique_filename = f"avatar_{session['user_id']}_{int(time.time())}_{filename}"
        
        # Uploads klasörü yoksa oluştur
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        # Eski avatar'ı sil (varsa)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT avatar_url FROM users WHERE user_id = %s', (session['user_id'],))
        old_avatar = cur.fetchone()
        if old_avatar and old_avatar[0] and old_avatar[0] != '/static/images/Default_pfp.jpg':
            old_avatar_path = os.path.join(app.root_path, old_avatar[0].lstrip('/'))
            if os.path.exists(old_avatar_path):
                os.remove(old_avatar_path)
        
        # Yeni avatar'ı kaydet
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(avatar_path)
        
        # Veritabanını güncelle
        avatar_url = f'/static/uploads/{unique_filename}'
        cur.execute('UPDATE users SET avatar_url = %s WHERE user_id = %s', (avatar_url, session['user_id']))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Geçersiz dosya türü'})

@app.route('/comment/<int:comment_id>/like', methods=['POST'])
def toggle_comment_like(comment_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Giriş yapmanız gerekiyor'}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Önce beğeni durumunu kontrol et
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1 FROM comment_likes 
                WHERE comment_id = %s AND user_id = %s
            ) as has_liked
        """, (comment_id, session['user_id']))
        
        has_liked = cursor.fetchone()['has_liked']
        
        if has_liked:
            # Beğeniyi kaldır
            cursor.execute("""
                DELETE FROM comment_likes 
                WHERE comment_id = %s AND user_id = %s
            """, (comment_id, session['user_id']))
            action = 'unlike'
        else:
            # Beğeni ekle
            cursor.execute("""
                INSERT INTO comment_likes (comment_id, user_id) 
                VALUES (%s, %s)
            """, (comment_id, session['user_id']))
            action = 'like'
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'action': action
        })
        
    except Exception as e:
        print(f"Hata: {str(e)}")
        return jsonify({'success': False, 'message': 'Bir hata oluştu'}), 500

@app.route('/hashtag/<tag>')
def hashtag_posts(tag):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Debug için tag'i yazdır
    print(f"Aranan hashtag: #{tag}")
    
    # Hashtag'e ait gönderileri getir
    cur.execute("""
        SELECT p.*, u.username, u.avatar_url,
               COUNT(DISTINCT l.like_id) as like_count,
               COUNT(DISTINCT c.comment_id) as comment_count,
               EXISTS(
                   SELECT 1 FROM likes 
                   WHERE post_id = p.post_id 
                   AND user_id = %s
               ) as user_has_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        LEFT JOIN comments c ON p.post_id = c.post_id
        WHERE lower(p.caption) LIKE %s
        GROUP BY p.post_id, u.username, u.avatar_url
        ORDER BY p.created_at DESC
    """, (session['user_id'], f'%#{tag}%'))
    
    posts = cur.fetchall()
    
    # Debug için bulunan post sayısını yazdır
    print(f"Bulunan post sayısı: {len(posts)}")
    for post in posts:
        print(f"Post caption: {post['caption']}")
    
    # Her post için avatar_url kontrolü
    for post in posts:
        if not post['avatar_url'] or post['avatar_url'] == '/static/images/default-avatar.png':
            post['avatar_url'] = '/static/images/Default_pfp.jpg'
    
    cur.close()
    conn.close()
    
    return render_template('hashtag_posts.html', posts=posts, tag=tag)

def get_post_comments(post_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Giriş yapmanız gerekiyor'}), 401
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT c.*, u.username, u.avatar_url,
                   (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.comment_id) as like_count,
                   EXISTS(
                       SELECT 1 FROM comment_likes 
                       WHERE comment_id = c.comment_id AND user_id = %s
                   ) as has_liked
            FROM comments c
            JOIN users u ON c.user_id = u.user_id
            WHERE c.post_id = %s
            ORDER BY c.created_at DESC
        """, (session['user_id'], post_id))
        
        comments = cursor.fetchall()
        
        # Her yorum için avatar_url kontrolü yap
        for comment in comments:
            if not comment['avatar_url']:
                comment['avatar_url'] = '/static/images/Default_pfp.jpg'
        
        cursor.close()
        conn.close()
        
        return jsonify({'comments': comments})
        
    except Exception as e:
        print(f"Hata: {str(e)}")
        return jsonify({'success': False, 'message': 'Bir hata oluştu'}), 500

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Giriş yapmanız gerekiyor'}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Önce yorumun sahibi olduğundan emin olalım
        cursor.execute("""
            SELECT user_id FROM comments 
            WHERE comment_id = %s
        """, (comment_id,))
        
        comment = cursor.fetchone()
        
        if not comment or comment[0] != session['user_id']:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Bu yorumu silme yetkiniz yok'}), 403
        
        # Yorumu sil
        cursor.execute("DELETE FROM comments WHERE comment_id = %s", (comment_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Hata: {str(e)}")
        return jsonify({'success': False, 'message': 'Bir hata oluştu'}), 500
    
@csrf.exempt
@app.route('/api/posts', methods=['GET'])
@token_required
def get_api_posts(current_user):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT p.*, u.username, u.avatar_url,
               COUNT(DISTINCT l.like_id) as like_count,
               COUNT(DISTINCT c.comment_id) as comment_count,
               EXISTS(
                   SELECT 1 FROM likes 
                   WHERE post_id = p.post_id 
                   AND user_id = %s
               ) as user_has_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN likes l ON p.post_id = l.post_id
        LEFT JOIN comments c ON p.post_id = c.post_id
        GROUP BY p.post_id, u.username, u.avatar_url
        ORDER BY p.created_at DESC
    """, (current_user['user_id'],))
    
    posts = cur.fetchall()
    
    # URL'leri düzelt
    for post in posts:
        # Avatar URL'sini düzelt
        if post['avatar_url'] and not post['avatar_url'].startswith('/'):
            post['avatar_url'] = '/' + post['avatar_url']
            
        # Post görüntü URL'sini düzelt
        if post['image_url']:
            # Önce başındaki ve sonundaki boşlukları temizle
            image_url = post['image_url'].strip()
            # Eğer / ile başlamıyorsa ekle
            if not image_url.startswith('/'):
                image_url = '/' + image_url
            # URL'deki çift slash'ları temizle
            image_url = image_url.replace('//', '/')
            post['image_url'] = image_url
    
    cur.close()
    conn.close()
    
    return jsonify(posts)

@csrf.exempt
@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('full_name')
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO users (username, email, password_hash, full_name, avatar_url) VALUES (%s, %s, %s, %s, %s) RETURNING user_id",
            (username, email, generate_password_hash(password), full_name, '/static/images/Default_pfp.jpg')
        )
        
        user_id = cur.fetchone()[0]
        conn.commit()
        
        # Hemen login yap
        token = str(user_id)
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user_id,
                'username': username
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Kayıt sırasında bir hata oluştu'
        }), 400
    
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@csrf.exempt
@app.route('/api/create-post', methods=['POST'])
@token_required
def create_post(current_user):
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'Fotoğraf gerekli'}), 400
            
        image = request.files['image']
        caption = request.form.get('caption', '')
        
        if image and allowed_file(image.filename):
            filename = f"post_{current_user['user_id']}_{int(time.time())}_{secure_filename(image.filename)}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            
            print(f"Saving file to: {filepath}")
            
            try:
                image.save(filepath)
                os.chmod(filepath, 0o644)
                print(f"File saved successfully at: {filepath}")
            except Exception as e:
                print(f"File save error: {str(e)}")
                return jsonify({'error': 'Dosya kaydedilemedi'}), 500

            # Veritabanına kaydet
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            cur.execute(
                "INSERT INTO posts (user_id, image_url, caption) VALUES (%s, %s, %s) RETURNING post_id",
                (current_user['user_id'], f'static/uploads/{filename}', caption)
            )
            
            post_id = cur.fetchone()['post_id']
            conn.commit()
            cur.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'post_id': post_id,
                'message': 'Gönderi oluşturuldu'
            })
            
        return jsonify({'error': 'Geçersiz dosya formatı'}), 400
        
    except Exception as e:
        print(f"Post oluşturma hatası: {str(e)}")
        return jsonify({'error': 'Gönderi oluşturulamadı'}), 500

CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": ["http://192.168.18.5:5000", "http://localhost:5000", "http://127.0.0.1:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
}) 

@csrf.exempt
@app.route('/api/post/<int:post_id>/like', methods=['POST'])
def api_like_post(post_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        token = auth_header.split(' ')[1]
        user_id = int(token)
    except:
        return jsonify({'error': 'Invalid token'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT like_id FROM likes 
            WHERE post_id = %s AND user_id = %s
        """, (post_id, user_id))
        
        existing_like = cur.fetchone()
        
        if existing_like:
            cur.execute("DELETE FROM likes WHERE like_id = %s", (existing_like[0],))
            action = 'unlike'
        else:
            cur.execute(
                "INSERT INTO likes (post_id, user_id) VALUES (%s, %s)",
                (post_id, user_id)
            )
            action = 'like'
            
        conn.commit()
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cur.close()
        conn.close()

@app.route('/api/post/<int:post_id>')
@token_required
def get_post_detail(current_user, post_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Post detaylarını getir
        cur.execute("""
            SELECT p.*, u.username, u.avatar_url,
                   COUNT(DISTINCT l.like_id) as like_count,
                   COUNT(DISTINCT c.comment_id) as comment_count,
                   EXISTS(
                       SELECT 1 FROM likes 
                       WHERE post_id = p.post_id 
                       AND user_id = %s
                   ) as user_has_liked
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            LEFT JOIN likes l ON p.post_id = l.post_id
            LEFT JOIN comments c ON p.post_id = c.post_id
            WHERE p.post_id = %s
            GROUP BY p.post_id, u.username, u.avatar_url
        """, (current_user['user_id'], post_id))
        
        post = cur.fetchone()
        
        if not post:
            return jsonify({'error': 'Post bulunamadı'}), 404
            
        cur.close()
        conn.close()
        
        return jsonify(post)
        
    except Exception as e:
        print(f"Post detayları alınırken hata: {str(e)}")
        return jsonify({'error': 'Post detayları alınamadı'}), 500

@csrf.exempt
@app.route('/api/post/<int:post_id>/comments', methods=['GET', 'POST'])
def api_post_comments(post_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        token = auth_header.split(' ')[1]
        user_id = int(token)
    except:
        return jsonify({'error': 'Invalid token'}), 401
    
    if request.method == 'POST':
        data = request.get_json()
        comment_text = data.get('comment_text')
        
        if not comment_text or not comment_text.strip():
            return jsonify({'success': False, 'message': 'Yorum boş olamaz'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("""
                INSERT INTO comments (post_id, user_id, comment_text)
                VALUES (%s, %s, %s)
                RETURNING comment_id, created_at
            """, (post_id, user_id, comment_text))
            
            new_comment = cursor.fetchone()
            conn.commit()
            
            return jsonify({
                'success': True,
                'comment': new_comment
            })
        except Exception as e:
            conn.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    
    # GET isteği için yorumları getir
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute("""
        SELECT c.*, u.username, u.avatar_url
        FROM comments c
        JOIN users u ON c.user_id = u.user_id
        WHERE c.post_id = %s
        ORDER BY c.created_at DESC
    """, (post_id,))
    
    comments = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return jsonify({'comments': comments})

@app.route('/api/profile')
@token_required
def get_profile(current_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Kullanıcı bilgilerini getir
        cur.execute("""
            SELECT 
                u.user_id,
                u.username,
                u.full_name,
                u.avatar_url,
                u.bio,
                (SELECT COUNT(*) FROM posts WHERE user_id = u.user_id) as posts_count,
                (SELECT COUNT(*) FROM followers WHERE followed_user_id = u.user_id) as followers_count,
                (SELECT COUNT(*) FROM followers WHERE follower_user_id = u.user_id) as following_count
            FROM users u
            WHERE u.user_id = %s
        """, (current_user['user_id'],))
        
        user_data = cur.fetchone()
        
        # Avatar URL kontrolü
        if not user_data['avatar_url']:
            user_data['avatar_url'] = '/static/images/Default_pfp.jpg'
            
        cur.close()
        conn.close()
        
        return jsonify(user_data)
        
    except Exception as e:
        print(f"Profil bilgileri alınırken hata: {str(e)}")
        return jsonify({'error': 'Profil bilgileri alınamadı'}), 500

@app.route('/api/user/posts')
@token_required
def get_user_posts(current_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT p.*, u.username, u.avatar_url,
                   COUNT(DISTINCT l.like_id) as like_count,
                   COUNT(DISTINCT c.comment_id) as comment_count,
                   EXISTS(
                       SELECT 1 FROM likes 
                       WHERE post_id = p.post_id 
                       AND user_id = %s
                   ) as user_has_liked
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            LEFT JOIN likes l ON p.post_id = l.post_id
            LEFT JOIN comments c ON p.post_id = c.post_id
            WHERE p.user_id = %s
            GROUP BY p.post_id, u.username, u.avatar_url
            ORDER BY p.created_at DESC
        """, (current_user['user_id'], current_user['user_id']))
        
        posts = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify(posts)
        
    except Exception as e:
        print(f"Kullanıcı postları alınırken hata: {str(e)}")
        return jsonify({'error': 'Postlar alınamadı'}), 500
    
@app.route('/api/user/<string:username>')
@token_required
def get_user_by_username(current_user, username):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Kullanıcı bilgilerini getir
        cur.execute("""
            SELECT 
                u.user_id,
                u.username,
                u.full_name,
                u.avatar_url,
                u.bio,
                (SELECT COUNT(*) FROM posts WHERE user_id = u.user_id) as posts_count,
                (SELECT COUNT(*) FROM followers WHERE followed_user_id = u.user_id) as followers_count,
                (SELECT COUNT(*) FROM followers WHERE follower_user_id = u.user_id) as following_count,
                EXISTS(
                    SELECT 1 FROM followers 
                    WHERE follower_user_id = %s 
                    AND followed_user_id = u.user_id
                ) as is_following
            FROM users u
            WHERE u.username = %s
        """, (current_user['user_id'], username))
        
        user = cur.fetchone()
        
        if not user:
            return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
            
        # Kullanıcının gönderilerini getir
        cur.execute("""
            SELECT p.*, u.username, u.avatar_url,
                   COUNT(DISTINCT l.like_id) as like_count,
                   COUNT(DISTINCT c.comment_id) as comment_count,
                   EXISTS(
                       SELECT 1 FROM likes 
                       WHERE post_id = p.post_id 
                       AND user_id = %s
                   ) as user_has_liked
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            LEFT JOIN likes l ON p.post_id = l.post_id
            LEFT JOIN comments c ON p.post_id = c.post_id
            WHERE p.user_id = %s
            GROUP BY p.post_id, u.username, u.avatar_url
            ORDER BY p.created_at DESC
        """, (current_user['user_id'], user['user_id']))
        
        posts = cur.fetchall()
        
        # Avatar URL kontrolü
        if not user['avatar_url']:
            user['avatar_url'] = '/static/images/Default_pfp.jpg'
            
        cur.close()
        conn.close()
        
        return jsonify({
            'user': user,
            'posts': posts
        })
        
    except Exception as e:
        print(f"Kullanıcı bilgileri alınırken hata: {str(e)}")
        return jsonify({'error': 'Kullanıcı bilgileri alınamadı'}), 500 

@app.route('/api/search', methods=['GET'])
@token_required
def search_posts():
    query = request.args.get('q', '')
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT p.*, u.username, u.avatar_url,
                   COUNT(DISTINCT l.like_id) as like_count,
                   COUNT(DISTINCT c.comment_id) as comment_count
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            LEFT JOIN likes l ON p.post_id = l.post_id
            LEFT JOIN comments c ON p.post_id = c.post_id
            WHERE u.username ILIKE %s OR p.caption ILIKE %s
            GROUP BY p.post_id, u.username, u.avatar_url
            ORDER BY p.created_at DESC
        """, (f'%{query}%', f'%{query}%'))
        
        results = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify(results)
        
    except Exception as e:
        print(f"Arama yapılırken hata: {str(e)}")
        return jsonify({'error': 'Arama yapılamadı'}), 500 

@csrf.exempt
@app.route('/api/profile/update', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Profil fotoğrafı kontrolü
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and allowed_file(avatar.filename):
                filename = f"avatar_{current_user['user_id']}_{int(time.time())}_{secure_filename(avatar.filename)}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                avatar.save(filepath)
                
                # Veritabanında avatar_url güncelle
                cur.execute(
                    "UPDATE users SET avatar_url = %s WHERE user_id = %s",
                    (f'/static/uploads/{filename}', current_user['user_id'])
                )
        
        # Ad soyad güncelleme
        if 'full_name' in request.form:
            cur.execute(
                "UPDATE users SET full_name = %s WHERE user_id = %s",
                (request.form['full_name'], current_user['user_id'])
            )
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Profil güncellendi'})
        
    except Exception as e:
        print(f"Profil güncelleme hatası: {str(e)}")
        return jsonify({'error': 'Profil güncellenemedi'}), 500
    
@app.route('/api/popular-users')
@token_required
def get_popular_users(current_user):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT u.username, u.full_name, u.avatar_url,
               COUNT(DISTINCT f.follower_user_id) as follower_count,
               COUNT(DISTINCT p.post_id) as post_count
        FROM users u
        LEFT JOIN followers f ON u.user_id = f.followed_user_id
        LEFT JOIN posts p ON u.user_id = p.user_id
        GROUP BY u.user_id, u.username, u.full_name, u.avatar_url
        ORDER BY follower_count DESC
        LIMIT 10
    """)
    
    popular_users = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(popular_users)

@app.route('/api/popular-hashtags')
@token_required
def get_popular_hashtags(current_user):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        WITH hashtags AS (
            SELECT DISTINCT unnest(regexp_matches(lower(caption), '#[a-zA-Z0-9_]+', 'g')) as tag
            FROM posts
        )
        SELECT 
            tag,
            COUNT(*) as usage_count,
            COUNT(DISTINCT l.like_id) as total_likes
        FROM hashtags h
        JOIN posts p ON lower(p.caption) LIKE '%' || h.tag || '%'
        LEFT JOIN likes l ON p.post_id = l.post_id
        GROUP BY tag
        ORDER BY usage_count DESC
        LIMIT 20
    """)
    
    hashtags = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(hashtags)

@app.route('/api/hashtag/<tag>/posts')
@token_required
def get_hashtag_posts(current_user, tag):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT p.*, u.username, u.avatar_url,
                   COUNT(DISTINCT l.like_id) as like_count,
                   COUNT(DISTINCT c.comment_id) as comment_count,
                   EXISTS(
                       SELECT 1 FROM likes 
                       WHERE post_id = p.post_id 
                       AND user_id = %s
                   ) as user_has_liked
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            LEFT JOIN likes l ON p.post_id = l.post_id
            LEFT JOIN comments c ON p.post_id = c.post_id
            WHERE lower(p.caption) LIKE %s
            GROUP BY p.post_id, u.username, u.avatar_url
            ORDER BY p.created_at DESC
        """, (current_user['user_id'], f'%#{tag}%'))
        
        posts = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify(posts)
        
    except Exception as e:
        print(f"Hashtag gönderileri alınırken hata: {str(e)}")
        return jsonify({'error': 'Gönderiler alınamadı'}), 500 

@app.route('/api/post/<int:post_id>', methods=['DELETE'])
@csrf.exempt  # CSRF korumasını devre dışı bırak
@token_required
def mobile_delete_post(current_user, post_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Önce postun sahibi olduğunu kontrol et
        cur.execute("""
            SELECT * FROM posts 
            WHERE post_id = %s AND user_id = %s
        """, (post_id, current_user['user_id']))
        
        post = cur.fetchone()
        if not post:
            return jsonify({'error': 'Post bulunamadı veya silme yetkiniz yok'}), 403
            
        # Önce yorumları ve beğenileri sil
        cur.execute("DELETE FROM comments WHERE post_id = %s", (post_id,))
        cur.execute("DELETE FROM likes WHERE post_id = %s", (post_id,))
        
        # Sonra postu sil
        cur.execute("DELETE FROM posts WHERE post_id = %s", (post_id,))
        conn.commit()
        
        # Dosyayı sil
        try:
            if post['image_url']:
                file_path = os.path.join(BASE_DIR, post['image_url'])
                if os.path.exists(file_path):
                    os.remove(file_path)
        except Exception as e:
            print(f"Dosya silme hatası: {str(e)}")
        
        return jsonify({'success': True, 'message': 'Post silindi'})
        
    except Exception as e:
        print(f"Post silme hatası: {str(e)}")
        return jsonify({'error': 'Post silinemedi'}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    # Statik klasörleri oluştur
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join('static', 'images'), exist_ok=True)
    
    # Klasör izinlerini ayarla
    os.chmod(app.config['UPLOAD_FOLDER'], 0o755)
    os.chmod(os.path.join('static', 'images'), 0o755)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
