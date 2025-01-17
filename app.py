from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import random
from datetime import datetime, timedelta
import time
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key')  # Güvenli bir secret key kullanın
csrf = CSRFProtect(app)

# Veritabanı bağlantı bilgileri
DB_CONFIG = {
    'dbname': os.environ.get('DB_NAME', 'instagram_clone'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', ''),  # Şifreyi environment variable'dan al
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('PORT', '5432')
}

# Dosya yükleme ayarları
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['user_id']
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('index'))
        
        flash('Geçersiz kullanıcı adı veya şifre!', 'error')
        
        cur.close()
        conn.close()
    
    return render_template('login.html')

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

@app.route('/create-post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('Lütfen bir resim seçin!', 'error')
            return redirect(url_for('create_post'))
            
        file = request.files['image']
        caption = request.form.get('caption', '').strip()
        
        if file.filename == '':
            flash('Hiçbir dosya seçilmedi!', 'error')
            return redirect(url_for('create_post'))
            
        if not caption:
            flash('Lütfen bir açıklama yazın!', 'error')
            return redirect(url_for('create_post'))
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Benzersiz bir dosya adı oluştur
            unique_filename = f"post_{session['user_id']}_{int(time.time())}_{filename}"
            
            # Uploads klasörü yoksa oluştur
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            # Dosyayı kaydet
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Veritabanına kaydet
            image_url = f'/static/uploads/{unique_filename}'
            
            conn = get_db_connection()
            cur = conn.cursor()
            
            try:
                cur.execute(
                    "INSERT INTO posts (user_id, image_url, caption) VALUES (%s, %s, %s) RETURNING post_id",
                    (session['user_id'], image_url, caption)
                )
                post_id = cur.fetchone()[0]
                conn.commit()
                flash('Gönderi başarıyla oluşturuldu!', 'success')
            except Exception as e:
                conn.rollback()
                flash('Gönderi oluşturulurken bir hata oluştu!', 'error')
                print(f"Hata: {str(e)}")  # Hata logla
            finally:
                cur.close()
                conn.close()
            
            return redirect(url_for('my_posts'))
        else:
            flash('İzin verilen dosya türleri: png, jpg, jpeg, gif', 'error')
            return redirect(url_for('create_post'))
    
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
            
            # Yorumu ekle
            cursor.execute("""
                INSERT INTO comments (post_id, user_id, comment_text)
                VALUES (%s, %s, %s)
                RETURNING comment_id, created_at
            """, (post_id, session['user_id'], comment_text))
            
            new_comment = cursor.fetchone()
            
            # Yeni eklenen yorumun detaylarını getir
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

if __name__ == '__main__':
    app.run(debug=True) 