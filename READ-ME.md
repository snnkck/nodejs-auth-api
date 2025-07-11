#### PROJEDE NELER VAR ?

Bu bir express ile yapılmış nodejs projesidir. Uygulama için kullanıcı işlemlerini içerir.
Database olarak postgresql kullanılmıştır. Ayrıca orm tarafında prisma ile inşa edilmiştir.
Projede gelişmiş error-handling yapısı mevcuttur. Böylece hata ayıklamada yardımcı olur.

Projede yapılabilir aksiyonlar;

Mevcut auth sisteminizi daha gelişmiş hale getirmek için şu özellikler eklenebilir:
1. Gelişmiş Güvenlik Özellikleri

Two-Factor Authentication (2FA): TOTP, SMS veya email tabanlı
Device Management: Güvenilir cihazları kaydetme
IP Whitelist/Blacklist: Şüpheli IP'leri engelleme
Session Management: Aktif oturumları yönetme
CAPTCHA Integration: Bot saldırılarını önleme

2. Kullanıcı Deneyimi İyileştirmeleri

Social Login: Google, Facebook, GitHub OAuth
Magic Links: Şifresiz giriş
Progressive Registration: Kademeli kayıt
Email Templates: Daha profesyonel email tasarımları
Multi-language Support: Çoklu dil desteği

3. Monitoring ve Analytics

Login Attempts Tracking: Başarısız giriş denemelerini izleme
User Activity Logs: Kullanıcı aktivitelerini loglama
Security Alerts: Şüpheli aktivitelerde bildirim
Performance Metrics: Auth işlemlerinin performansı

4. Gelişmiş Doğrulama

Phone Number Verification: SMS doğrulama
Identity Verification: KYC süreçleri
Document Upload: Kimlik belgesi yükleme
Biometric Authentication: Parmak izi, yüz tanıma

5. API Güvenliği

API Keys: Üçüncü parti entegrasyonlar
Webhook Security: Güvenli webhook işlemleri
CORS Configuration: Gelişmiş CORS ayarları
Request Signing: İstek imzalama

6. Yönetim Paneli

User Management: Kullanıcı yönetimi
Role-Based Access Control: Rol tabanlı erişim
Audit Logs: Denetim logları
System Health: Sistem durumu izleme

7. Performans Optimizasyonları

Caching Strategy: Redis ile cache
Database Optimization: İndeks optimizasyonu
Connection Pooling: Veritabanı bağlantı havuzu
Load Balancing: Yük dengeleme

## Register

- Kullanıcı kayıt isim, email ve parola ile kayıt olur.

- Doğrulama maili gelir. Kullanıcıdan doğrulama linkine tıklanması istenir.

- Client tarafında mailiniz onaylandı haberi kullanıcıya iletilir.

- Onaylanan kullanıcı giriş yapabilir.

## Login

- Kullanıcı email ve parola ile giriş yapabilir.

- Giriş yapan kullanıcıya bir token oluşturulur.

- Bu token protected routelar ile kullanılabilir.

## Şifremi unuttum ? (Forgot Password)

- Kullanıcı kayıtlı ise email adresi yazması istenir.

- Maile gelen link ile kullanıcı yeni parolası girilmesi istenir.

- Girilen yeni parola ile şifre değiştirilir.

## Protected route

- Bu route deneme amaçlıdır.

- Giriş yapan kullanıcılar bu endpointe erişebilir.

