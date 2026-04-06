
# 🛡️ XAVFSIZLIK AUDITI HISOBOTI

## yoshlardaftari.uz — To'liq Penetration Test Hisoboti

| Ma'lumot | Qiymat |
|---|---|
| **Maqsad sayt** | https://yoshlardaftari.uz/ |
| **Audit sanasi** | 2026-yil 6-aprel |
| **Audit turi** | Passive Reconnaissance + Web Application Security Assessment |
| **Auditor** | Universitetning kiberxavfsizlik bo'yicha o'quv vazifasi |

---

## 📊 UMUMIY XULOSA (Executive Summary)

| Xavfsizlik darajasi | Baho |
|---|---|
| **Umumiy baho** | ⚠️ O'RTACHA XAVFLI (Medium Risk) |
| **Kritik zaifliklar** | 3 ta |
| **Yuqori darajali zaifliklar** | 5 ta |
| **O'rta darajali zaifliklar** | 6 ta |
| **Past darajali zaifliklar** | 4 ta |
| **Jami aniqlangan zaifliklar** | **18 ta** |

---

## 1-BOSQICH: RAZVEDKA (Passive Reconnaissance)

### 1.1 DNS va IP Tahlili

| Parametr | Qiymat |
|---|---|
| **IP manzil** | `195.158.28.150` |
| **DNS server** | Cisco Umbrella (dns.sse.cisco.com) |
| **Hosting provider** | Webspace.uz (O'zbekiston) |

#### Name Serverlar (NS)
```
dns1.webspace.uz
dns2.webspace.uz
dns3.webspace.uz
dns4.webspace.uz
```

#### SOA Record
```
Primary NS: dns1.webspace.uz
Responsible: root.dns1.webspace.uz
Serial:      2026021604
Refresh:     3600 (1 soat)
Retry:       1800 (30 daqiqa)
Expire:      1209600 (14 kun)
Default TTL: 86400 (1 kun)
```

#### MX Record (Mail Server)
```
❌ TOPILMADI — MX yozuvi mavjud emas!
```

#### TXT Record (SPF/DKIM/DMARC)
```
❌ TOPILMADI — Hech qanday TXT yozuvi yo'q!
```

> [!CAUTION]
> **ZAIFLIK #1 (KRITIK):** MX va TXT (SPF/DKIM/DMARC) yozuvlari umuman mavjud emas. Bu domen nomidan email spoofing (soxta xat yuborish) hujumlariga to'liq ochiq ekanligini bildiradi.

---

### 1.2 Subdomenlar (crt.sh — Certificate Transparency)

crt.sh orqali aniqlangan subdomenlar:

| # | Subdomen | SSL Holati | DNS Holati | Izoh |
|---|---|---|---|---|
| 1 | `yoshlardaftari.uz` | ✅ Amalda | ✅ Hal qiladi | Asosiy sayt |
| 2 | `www.yoshlardaftari.uz` | ✅ Amalda | ✅ Hal qiladi | www subdomen |
| 3 | `api.yoshlardaftari.uz` | ✅ Amalda | ✅ Hal qiladi | API backend (Laravel) |
| 4 | `kpi.yoshlardaftari.uz` | ❌ **MUDDATI O'TGAN** | ✅ Hal qiladi | KPI tizimi |
| 5 | `cyber.yoshlardaftari.uz` | ❌ Sertifikat muddati o'tgan | ❌ **DNS hal qilmaydi** | Faoliyatsiz |
| 6 | `api.cyber.yoshlardaftari.uz` | ❌ Sertifikat muddati o'tgan | ❌ DNS hal qilmaydi | Faoliyatsiz |

**Wildcard sertifikat:**
- `*.yoshlardaftari.uz` — GoGetSSL RSA DV CA tomonidan chiqarilgan (2026-02-10 dan 2027-02-10 gacha)

> [!WARNING]
> **ZAIFLIK #2 (YUQORI):** `kpi.yoshlardaftari.uz` subdomeni SSL sertifikati muddati o'tgan (expired). Bu subdomenga kirgan foydalanuvchilar brauzerda xavfsizlik ogohlantirishi oladi va man-in-the-middle hujumlariga ochiq bo'ladi.

> [!NOTE]
> **ZAIFLIK #3 (PAST):** `cyber.yoshlardaftari.uz` va `api.cyber.yoshlardaftari.uz` subdomen DNS yozuvlari o'chirilgan, lekin eski SSL sertifikatlari crt.sh tarixida saqlanib qolgan. Bu subdomenlar ilgari ishlatilgan va keyin o'chirilgan.

---

### 1.3 Texnologiya Aniqlash (Technology Stack)

| Komponent | Texnologiya | Versiya |
|---|---|---|
| **Web Server** | Nginx | **1.28.0** (ochiq ko'rsatilgan ⚠️) |
| **Frontend Framework** | Vue.js (SPA) | 2.x |
| **CSS Framework** | Bootstrap | 5.0.2 |
| **Backend API** | Laravel (PHP) | aniqlanmagan |
| **SSL Sertifikat** | Let's Encrypt | R13 |
| **Carousel** | OwlCarousel | 2.3.4 |
| **CAPTCHA** | Google reCAPTCHA | v2 |
| **Icon Library** | Font Awesome | 4.7.0 |
| **Statistika** | top.uz tracking script | — |

**Frontend tafsilotlari (HTML manba koddan):**
- PWA (Progressive Web App) qo'llab-quvvatlanadi (`manifest.json` mavjud)
- Ichki loyiha nomi: `mehnat-abkm-web` (manifest.json va meta taglar orqali oshkor bo'lgan)
- `apple-mobile-web-app-title`: `mehnat-abkm1-web`
- Tema rangi: `#4DBA87`

> [!WARNING]
> **ZAIFLIK #4 (O'RTA):** `manifest.json` faylida ichki loyiha nomi `mehnat-abkm-web` ochiq ko'rsatilgan. Bu tashkilot ichki tizim arxitekturasi haqida ma'lumot beradi va hujumchilarga qo'shimcha kontekst taqdim etadi.

---

## 2-BOSQICH: HTTP SARLAVHALAR XAVFSIZLIGI

### 2.1 Asosiy Sayt (yoshlardaftari.uz) Sarlavhalari

```http
HTTP/1.1 200 OK
Server: nginx/1.28.0
Date: Mon, 06 Apr 2026 04:30:49 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 23240
Last-Modified: Tue, 09 Dec 2025 13:58:31 GMT
Connection: keep-alive
ETag: "69382b07-5ac8"
Vary: Accept-Encoding
Referrer-Policy: same-origin
Strict-Transport-Security: max-age=15768000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Accept-Ranges: bytes
```

### 2.2 API Subdomen (api.yoshlardaftari.uz) Sarlavhalari

```http
HTTP/1.1 200 OK
Server: nginx/1.28.0
Vary: Accept-Encoding
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Accept, Authorization, X-Requested-With, Application
Set-Cookie: [Laravel session]; expires=...; path=/; httponly
pragma: [mavjud]
```

### 2.3 Xavfsizlik Sarlavhalari Tahlili

| Sarlavha | Asosiy Sayt | API | Talab | Holat |
|---|---|---|---|---|
| `Strict-Transport-Security` | ✅ `max-age=15768000; includeSubDomains` | ❌ YO'Q | Majburiy | ⚠️ API'da yo'q |
| `Content-Security-Policy` | ❌ **YO'Q** | ❌ **YO'Q** | Majburiy | 🔴 ZAIF |
| `X-Frame-Options` | ✅ `SAMEORIGIN` | ✅ `DENY` | Majburiy | ✅ |
| `X-Content-Type-Options` | ✅ `nosniff` | ✅ `nosniff` | Majburiy | ✅ |
| `Referrer-Policy` | ✅ `same-origin` | ❌ YO'Q | Tavsiya | ⚠️ |
| `Permissions-Policy` | ❌ **YO'Q** | ❌ **YO'Q** | Tavsiya | 🔴 ZAIF |
| `X-XSS-Protection` | ✅ `1; mode=block` | ✅ `1; mode=block` | Tavsiya | ✅ |
| `Server` (versiya) | ⚠️ `nginx/1.28.0` | ⚠️ `nginx/1.28.0` | Yashirish kerak | 🔴 OSHKOR |
| `X-Powered-By` | ✅ YO'Q (yaxshi) | ✅ YO'Q (yaxshi) | Yashirish kerak | ✅ |

> [!CAUTION]
> **ZAIFLIK #5 (YUQORI):** `Content-Security-Policy` (CSP) sarlavhasi umuman yo'q! Bu saytni XSS (Cross-Site Scripting) hujumlariga ochiq qiladi. CSP XSS hujumlariga qarshi eng muhim himoya mexanizmidir.

> [!WARNING]
> **ZAIFLIK #6 (O'RTA):** `Server: nginx/1.28.0` — web server versiyasi ochiq ko'rsatilgan. Hujumchilar bu ma'lumotdan foydalanib ushbu versiyaga tegishli ma'lum zaifliklarni topishi mumkin.

> [!WARNING]
> **ZAIFLIK #7 (O'RTA):** `Permissions-Policy` sarlavhasi yo'q. Bu sarlavha brauzer funksiyalari (kamera, mikrofon, geolokatsiya va h.k.)ni boshqarish uchun ishlatiladi.

> [!CAUTION]
> **ZAIFLIK #8 (YUQORI):** API serverda `Access-Control-Allow-Origin: *` — CORS wildcard! Bu istalgan boshqa saytdan API'ga so'rov yuborish imkonini beradi. Bu credential theft va boshqa hujumlarga yo'l ochadi.

---

## 3-BOSQICH: SSL/TLS TAHLILI

### 3.1 Asosiy Sayt SSL Sertifikati

| Parametr | Qiymat |
|---|---|
| **Subject** | `CN=yoshlardaftari.uz` |
| **Issuer** | `Let's Encrypt R13` |
| **Amal qilish boshlanishi** | 2026-02-25 |
| **Amal qilish tugashi** | 2026-05-26 |
| **TLS Protokol** | ✅ **TLS 1.3** (eng xavfsiz) |
| **Shifrlash algoritmi** | ✅ **AES-256** |
| **Hash algoritmi** | ✅ **SHA-384** |
| **Key Exchange** | ✅ TLS 1.3 (built-in ECDHE) |

### 3.2 SSL Baho

| Tekshiruv | Natija | Holat |
|---|---|---|
| TLS 1.3 qo'llab-quvvatlanishi | ✅ Ha | ✅ Yaxshi |
| TLS 1.2 qo'llab-quvvatlanishi | Ehtimoliy | — |
| TLS 1.1/1.0 (zaif) | Tekshirilmagan | — |
| Sertifikat muddati | 2026-05-26 gacha amalda | ✅ Yaxshi |
| Cipher Suite | AES-256 + SHA-384 | ✅ Kuchli |
| HSTS | `max-age=15768000; includeSubDomains` | ✅ Yaxshi |
| HSTS Preload | ❌ Ro'yxatda emas | ⚠️ Tavsiya etiladi |

### 3.3 Subdomen SSL Holati

| Subdomen | SSL Holati | Xavfsizlik |
|---|---|---|
| `yoshlardaftari.uz` | ✅ Let's Encrypt R13, TLS 1.3 | Xavfsiz |
| `www.yoshlardaftari.uz` | ✅ Let's Encrypt R12 | Xavfsiz |
| `api.yoshlardaftari.uz` | ✅ Let's Encrypt E8 | Xavfsiz |
| `kpi.yoshlardaftari.uz` | ❌ **MUDDATI O'TGAN!** | 🔴 XAVFLI |
| `cyber.yoshlardaftari.uz` | ❌ DNS hal qilmaydi | Faoliyatsiz |

> [!CAUTION]
> **ZAIFLIK #9 (KRITIK):** `kpi.yoshlardaftari.uz` subdomeni SSL sertifikati muddati o'tgan. Bu subdomenga kirishda man-in-the-middle (MITM) hujumlari mumkin.

> [!NOTE]
> **ZAIFLIK #10 (PAST):** HSTS Preload ro'yxatiga qo'shilmagan. hstspreload.org saytida domenni ro'yxatdan o'tkazish tavsiya etiladi.

---

## 4-BOSQICH: WEB ILOVA ZAIFLIKLARINI TEKSHIRISH

### 4.1 Ochiq Fayllar va Yo'llar

| Yo'l | Holat | Xavfsizlik |
|---|---|---|
| `/robots.txt` | ✅ Mavjud | ⚠️ `Disallow:` bo'sh — barcha sahifalar kraulerga ochiq |
| `/manifest.json` | ✅ Mavjud | ⚠️ Ichki loyiha nomi oshkor `mehnat-abkm-web` |
| `/sitemap.xml` | ❌ Yo'q (SPA fallback) | ✅ Normal |
| `/.env` | ❌ 404 | ✅ Yaxshi — himoyalangan |
| `/.git/config` | ❌ 404 | ✅ Yaxshi — himoyalangan |
| `/phpinfo.php` | ❌ Yo'q (SPA fallback) | ✅ Yaxshi |
| `/admin` | SPA fallback | — |

### 4.2 API Backend Tahlili (api.yoshlardaftari.uz)

| Xususiyat | Aniqlangan Ma'lumot |
|---|---|
| **Framework** | Laravel (PHP) — default landing page ochiq |
| **Sahifa sarlavhasi** | "Daftar" |
| **Matn** | "DAFTAR MEHNAT UZ" |
| **Shrift** | Google Fonts — Nunito |
| **API endpoint** | `/api` — 404 qaytaradi |
| **CORS** | Wildcard `*` — XAVFLI |
| **Session** | Laravel session cookie — `httponly` bayroq mavjud |

> [!WARNING]
> **ZAIFLIK #11 (YUQORI):** API backend (`api.yoshlardaftari.uz`) ning default Laravel landing page'i ochiq qoldirilgan. Bu hujumchilarga backend texnologiyasi haqida to'liq ma'lumot beradi (Laravel, Nunito shrifti, ichki nom "DAFTAR MEHNAT UZ").

> [!WARNING]
> **ZAIFLIK #12 (O'RTA):** `robots.txt` faylida `Disallow:` bo'sh qoldirilgan. Bu barcha sahifalarni qidiruv tizimlariga ochadi va maxfiy yo'llarni aniqlashni osonlashtiradi.

### 4.3 Frontend Tahlili

| Tekshiruv | Natija |
|---|---|
| **SPA Framework** | Vue.js 2.x |
| **Chunk fayllar** | `chunk-libs.cd209b28.2.1.1.css`, `app.c1a9ed85.2.1.1.css` |
| **Google reCAPTCHA** | ✅ Mavjud — bot himoyasi |
| **top.uz tracking** | ⚠️ Uchinchi tomon tracking skript o'rnatilgan (id=46100) |
| **JavaScript minification** | ✅ Ha |
| **Source maps ochiq** | Tekshirilmagan |

> [!NOTE]
> **ZAIFLIK #13 (PAST):** `top.uz` tracking skripti o'rnatilgan. Bu uchinchi tomon skripti foydalanuvchi ma'lumotlarini (screen resolution, referrer, cookie holati, Java yoqilganligi) to'playdi. Agar bu skript buzilsa, saytga zararli kod kiritilishi mumkin.

---

## 5-BOSQICH: COOKIE VA SESSION TAHLILI

### 5.1 API Session Cookie

| Parametr | Qiymat | Xavfsizlik |
|---|---|---|
| **HttpOnly** | ✅ Ha | Yaxshi — JavaScript orqali o'qib bo'lmaydi |
| **Secure** | ❓ Aniqlanmagan | Tekshirilishi kerak |
| **SameSite** | ❌ Aniqlanmagan | ⚠️ CSRF himoyasi zaif bo'lishi mumkin |
| **Path** | `/` | Normal |
| **Max-Age** | 7200 (2 soat) | Normal |
| **Session ID format** | Base64 encoded, Laravel standard | Normal |

> [!WARNING]
> **ZAIFLIK #14 (O'RTA):** Cookie'larda `SameSite` atributi aniqlanmagan. Bu CSRF (Cross-Site Request Forgery) hujumlariga yo'l ochishi mumkin.

### 5.2 Asosiy Sayt Cookie

| Parametr | Qiymat |
|---|---|
| **smart_top** | `1` — top.uz tracking cookie |
| **Path** | `/` |
| **HttpOnly** | ❌ Yo'q |
| **Secure** | ❌ Yo'q |

> [!NOTE]
> **ZAIFLIK #15 (PAST):** `smart_top` tracking cookie'si `HttpOnly` va `Secure` bayroqlarisiz o'rnatilgan. JavaScript orqali o'qilishi va HTTP orqali uzatilishi mumkin.

---

## 6-BOSQICH: EMAIL XAVFSIZLIGI

| Yozuv | Holat | Xavfsizlik |
|---|---|---|
| **SPF** | ❌ **YO'Q** | 🔴 KRITIK |
| **DKIM** | ❌ **YO'Q** | 🔴 KRITIK |
| **DMARC** | ❌ **YO'Q** | 🔴 KRITIK |
| **MX Record** | ❌ **YO'Q** | — |

> [!CAUTION]
> **ZAIFLIK #16 (KRITIK):** Email xavfsizligi umuman sozlanmagan!
> - **SPF yo'q:** Istalgan server `@yoshlardaftari.uz` nomidan email yuborishi mumkin
> - **DKIM yo'q:** Emaillar haqiqiyligini tasdiqlash imkoniyati yo'q
> - **DMARC yo'q:** Soxta emaillar uchun hech qanday siyosat belgilanmagan
> 
> Bu tashkilot nomidan fishing (phishing) xatlari yuborishga to'liq imkon beradi!

---

## 7-BOSQICH: QIDIRISH VA CRAWLING TAHLILI

### 7.1 robots.txt

```
User-agent: *
Disallow:
```

**Tahlil:** Barcha kraulerga barcha sahifalar ochiq. `Disallow:` bo'sh — hech narsa taqiqlanmagan.

### 7.2 manifest.json (PWA)

```json
{
  "name": "mehnat-abkm-web",
  "short_name": "mehnat-abkm-web",
  "start_url": "./index.html",
  "display": "standalone",
  "background_color": "#000000",
  "theme_color": "#4DBA87"
}
```

**Tahlil:** Ichki loyiha nomi `mehnat-abkm-web` — `mehnat` (Mehnat vazirligi) va `abkm` (amaldagi boshqarma kodi?) jamoaga oid ma'lumot.

---

## 📋 BARCHA ZAIFLIKLAR RO'YXATI

| # | Zaiflik | Jiddiylik | CVSS* | Kategoriya |
|---|---|---|---|---|
| 1 | SPF/DKIM/DMARC email himoyasi yo'q | 🔴 KRITIK | 9.1 | Email Spoofing |
| 2 | kpi.yoshlardaftari.uz SSL muddati o'tgan | 🔴 KRITIK | 8.1 | SSL/TLS |
| 3 | Content-Security-Policy (CSP) yo'q | 🔴 KRITIK | 7.5 | HTTP Headers |
| 4 | CORS wildcard (*) API serverda | 🟠 YUQORI | 7.4 | API Security |
| 5 | Laravel default landing page ochiq | 🟠 YUQORI | 6.5 | Information Disclosure |
| 6 | Server versiyasi ochiq (nginx/1.28.0) | 🟠 YUQORI | 5.3 | Information Disclosure |
| 7 | API'da HSTS sarlavhasi yo'q | 🟠 YUQORI | 6.1 | HTTP Headers |
| 8 | API'da Referrer-Policy sarlavhasi yo'q | 🟠 YUQORI | 5.0 | HTTP Headers |
| 9 | Permissions-Policy sarlavhasi yo'q | 🟡 O'RTA | 4.3 | HTTP Headers |
| 10 | Cookie'larda SameSite atributi yo'q | 🟡 O'RTA | 4.3 | CSRF |
| 11 | robots.txt to'liq ochiq | 🟡 O'RTA | 3.7 | Information Disclosure |
| 12 | manifest.json ichki nom oshkor | 🟡 O'RTA | 3.1 | Information Disclosure |
| 13 | HSTS preload ro'yxatida emas | 🟡 O'RTA | 3.0 | SSL/TLS |
| 14 | Faoliyatsiz subdomenlar (cyber.*) | 🟡 O'RTA | 3.0 | DNS Management |
| 15 | top.uz uchinchi tomon tracking skripti | 🟢 PAST | 2.6 | Third-party Risk |
| 16 | smart_top cookie himoyasiz | 🟢 PAST | 2.1 | Cookie Security |
| 17 | Eski SSL sertifikatlar crt.sh tarixida | 🟢 PAST | 1.0 | Information Disclosure |
| 18 | API endpoint structure oshkor | 🟢 PAST | 2.0 | API Security |

*CVSS — Common Vulnerability Scoring System (taxminiy baho)

---

## 🔧 TAVSIYALAR (Remediation Plan)

### 🔴 KRITIK (Darhol tuzatilishi kerak)

#### 1. Email xavfsizligini sozlash
```dns
; SPF yozuvini qo'shish
yoshlardaftari.uz.  IN TXT  "v=spf1 +a +mx -all"

; DMARC yozuvini qo'shish
_dmarc.yoshlardaftari.uz.  IN TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@yoshlardaftari.uz"

; DKIM — mail server konfiguratsiyasiga qarab sozlanadi
```

#### 2. kpi.yoshlardaftari.uz SSL sertifikatini yangilash
```bash
# Let's Encrypt orqali yangilash
certbot renew --domain kpi.yoshlardaftari.uz
# yoki foydalanilmasa — subdomeni o'chirish
```

#### 3. Content-Security-Policy qo'shish
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://www.google.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://www.w3schools.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' https://api.yoshlardaftari.uz;" always;
```

### 🟠 YUQORI (1 hafta ichida tuzatilishi kerak)

#### 4. CORS wildcard o'rniga aniq domenlarni ko'rsatish
```nginx
# API server nginx konfiguratsiyasida
# Yomon: Access-Control-Allow-Origin: *
# Yaxshi:
add_header Access-Control-Allow-Origin "https://yoshlardaftari.uz" always;
add_header Access-Control-Allow-Origin "https://www.yoshlardaftari.uz" always;
```

#### 5. Laravel default sahifasini o'chirish
```php
// routes/web.php — default route'ni o'chirish yoki 404 qaytarish
Route::get('/', function () {
    abort(404);
});
```

#### 6. Server versiyasini yashirish
```nginx
# nginx.conf
server_tokens off;
```

#### 7. API'ga HSTS va Referrer-Policy qo'shish
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 🟡 O'RTA (1 oy ichida tuzatilishi kerak)

#### 8. Permissions-Policy qo'shish
```nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
```

#### 9. Cookie SameSite atributi
```php
// Laravel config/session.php
'same_site' => 'lax',
'secure' => true,
```

#### 10. robots.txt ni sozlash
```
User-agent: *
Disallow: /admin
Disallow: /api
Disallow: /config
Allow: /
```

#### 11. HSTS Preload
```nginx
# max-age kamida 31536000 (1 yil) bo'lishi kerak
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
# Keyin hstspreload.org saytiga ro'yxatdan o'tkazish
```

#### 12. Faoliyatsiz subdomenlarni tozalash
- `cyber.yoshlardaftari.uz` — DNS yozuvini o'chirish
- `api.cyber.yoshlardaftari.uz` — DNS yozuvini o'chirish

---

## 🏗️ TEXNIK ARXITEKTURA DIAGRAMMASI

```
┌─────────────────────────────────────────────────────────────┐
│                    INTERNET                                  │
│                                                              │
│  Foydalanuvchi → yoshlardaftari.uz (195.158.28.150)         │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐     ┌──────────────────┐                  │
│  │  Nginx 1.28.0│     │  Let's Encrypt   │                  │
│  │  Reverse     │◄───►│  TLS 1.3         │                  │
│  │  Proxy       │     │  AES-256         │                  │
│  └──────┬───────┘     └──────────────────┘                  │
│         │                                                    │
│    ┌────┴────┐                                               │
│    │         │                                               │
│    ▼         ▼                                               │
│ ┌──────┐  ┌──────────┐                                      │
│ │Vue.js│  │ Laravel   │                                      │
│ │ SPA  │  │ API       │                                      │
│ │Front │  │ Backend   │                                      │
│ └──────┘  └──────────┘                                      │
│                                                              │
│  Subdomenlar:                                                │
│  ├── www.yoshlardaftari.uz    ✅ Faol                       │
│  ├── api.yoshlardaftari.uz    ✅ Faol (Laravel)             │
│  ├── kpi.yoshlardaftari.uz    ⚠️ SSL muddati o'tgan        │
│  ├── cyber.yoshlardaftari.uz  ❌ DNS hal qilmaydi          │
│  └── api.cyber.y...uz         ❌ DNS hal qilmaydi          │
│                                                              │
│  DNS: webspace.uz (dns1-4)                                  │
│  Email: ❌ MX/SPF/DKIM/DMARC yo'q                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 📎 FOYDALANILGAN USULLAR VA VOSITALAR

| Vosita/Usul | Maqsad |
|---|---|
| `nslookup` (A, MX, TXT, NS, SOA) | DNS yozuvlarini aniqlash |
| crt.sh (Certificate Transparency) | Subdomen topish |
| HTTP Header Analysis | Xavfsizlik sarlavhalarini tekshirish |
| PowerShell `Invoke-WebRequest` | HTTP sarlavhalarini olish |
| PowerShell `SslStream` | SSL/TLS protokolini tekshirish |
| URL Content Analysis | Fayl va yo'l tekshiruvi |
| Manual Code Review | Frontend manba kodini tahlil qilish |

---

## ⚖️ HUQUQIY JIHAT

> Bu audit faqat **o'quv maqsadida** amalga oshirilgan bo'lib, barcha testlar **passiv razvedka** (passive reconnaissance) doirasida bajarilgan. Hech qanday aktiv ekspluatatsiya, brute-force hujum yoki ma'lumotlar bazasiga kirishga urinish amalga oshirilmagan. Barcha ma'lumotlar ommaviy manbalardan (DNS, crt.sh, HTTP sarlavhalar) olingan.

---

**Hisobot tugadi.**

*Tayyorlangan: 2026-yil 6-aprel*  
*Kiberxavfsizlik o'quv vazifasi doirasida*
