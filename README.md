# 🎫 E-Etkinlik | Flask Tabanlı Etkinlik Yönetim Sistemi

**E-Etkinlik**, bireysel olarak geliştirilmiş bir Flask web uygulamasıdır. Kullanıcıların yerel etkinlikleri keşfetmesini, bilet satın almasını ve ilgi alanlarına göre öneriler almasını sağlar. Aynı zamanda Ticketmaster ve Open-Meteo API’leri ile dinamik veri sunar. Yönetici paneli sayesinde kullanıcı, etkinlik ve duyuru yönetimi yapılabilir.

## 🚀 Özellikler

### 👤 Kullanıcı Tarafı
- 🔐 Kayıt ve Giriş (Yönetici onayı gerektirir)
- 🎭 Etkinlikleri Keşfet (Yerel ve Ticketmaster)
- 🎟️ Bilet Satın Alma (Standart, VIP, Öğrenci)
- ❤️ İlgi Alanlarına Göre Etkinlik Önerileri
- ☀️ Hava Durumu Bilgisi (Open-Meteo API ile)
- 📂 Profil ve Bilet Yönetimi

### 🛠️ Yönetici Tarafı
- ✅ Kullanıcı Onayı ve Yetkilendirme
- 🗂️ Etkinlik Yönetimi (Ekle, Sil, Güncelle)
- 📢 Duyuru Oluşturma ve Yayınlama
- 👑 Başka Kullanıcıları Admin Olarak Atama

---

## 🧩 Kullanılan Teknolojiler

| Teknoloji | Açıklama |
|----------|----------|
| Flask | Python tabanlı web framework |
| MySQL | İlişkisel veritabanı |
| Ticketmaster API | Harici etkinlik verisi |
| Open-Meteo API | Hava durumu tahmini |
| Cachetools | API yanıtlarını önbellekleme |
| Talisman | Güvenlik başlıkları (HTTPS) |
| Werkzeug | Şifreleme ve oturum yönetimi |

---

## 🗄️ Veritabanı Yapısı

### Tablolar
- `users`: Kullanıcı bilgileri
- `events`: Yerel etkinlikler
- `ticketmaster_events`: API'den çekilen etkinlikler
- `tickets`: Satın alınan biletler
- `cart`: Sepet içeriği
- `announcements`: Duyurular

### İlişkiler
- `tickets` ve `cart`, `users` ve `events` tablolarına bağlıdır.
- Ticketmaster etkinlikleri ayrıca `ticketmaster_events` tablosunda tutulur.

---

## 🌐 API Entegrasyonları

### 🎟 Ticketmaster API
- Türkiye’deki müzik, spor ve sanat etkinliklerini çeker.
- `fetch_and_store_ticketmaster_events()` fonksiyonu kullanılır.
- 1 saatlik TTL önbellekleme uygulanır.

### 🌦 Open-Meteo API
- Etkinlik lokasyonlarının hava durumu tahminini sağlar.
- `get_weather_info()` fonksiyonu ile çalışır.
- 10 dakikalık TTL önbellek ile desteklenir.

---

## 🔐 Güvenlik

- Şifreler `generate_password_hash` ile şifrelenir.
- HTTPS güvenliği `Flask-Talisman` ile sağlanır.
- Oturum çerezleri `HttpOnly` ve `Secure` bayrakları ile korunur.
- Parametreli SQL sorguları ile enjeksiyon koruması
- Yönetici işlemleri `is_admin` kontrolü ile sınırlanmıştır.
