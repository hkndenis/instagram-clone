# Instagram Clone

Bu proje, Instagram benzeri bir sosyal medya web uygulamasıdır. Flask framework'ü kullanılarak geliştirilmiştir.

## Özellikler

- Kullanıcı kaydı ve girişi
- Profil fotoğrafı yükleme
- Gönderi paylaşma
- Beğeni ve yorum yapma
- Kullanıcıları takip etme
- Trend gönderiler ve popüler kullanıcılar
- Lightbox görüntüleyici

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/your-username/instagram-clone.git
cd instagram-clone
```

2. Sanal ortam oluşturun ve aktifleştirin:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

4. `.env` dosyası oluşturun:
```bash
cp .env.example .env
```
`.env` dosyasını kendi ayarlarınıza göre düzenleyin.

5. PostgreSQL veritabanı oluşturun ve bağlantı bilgilerini `.env` dosyasına ekleyin.

6. Uygulamayı çalıştırın:
```bash
python app.py
```

## Ortam Değişkenleri

Aşağıdaki ortam değişkenlerini `.env` dosyasında tanımlamanız gerekmektedir:

- `SECRET_KEY`: Flask uygulaması için güvenlik anahtarı
- `DB_NAME`: PostgreSQL veritabanı adı
- `DB_USER`: PostgreSQL kullanıcı adı
- `DB_PASSWORD`: PostgreSQL şifresi
- `DB_HOST`: PostgreSQL sunucu adresi

## Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Bir Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın. 

#deneme