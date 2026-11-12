# 🛡️ PINK WEB SCANNER DASHBOARD

> **DISCOVER • ANALYZE • PROTECT • UNDERSTAND**

**Pink Web Scanner** adalah platform Web Application profesional berbasis Python dan Streamlit yang menggabungkan estetika visual **Pink Futuristic Cyber Security** dengan kemampuan audit website mendalam. Platform ini dirancang untuk melakukan analisis HTML, audit SEO transparan, inspeksi konfigurasi keamanan publik, fingerprinting teknologi heuristik, pengujian performa jaringan HTTP, hingga ekspor laporan eksekutif (PDF, CSV, JSON).

---

## 🎨 PALET WARNA & IDENTITAS VISUAL

Aplikasi ini mengusung tema **Cyberpunk Pink Cyber Security** dengan dukungan Glassmorphism, efek neon lembut, dan kontras tinggi:

| Token Warna | Hex Code | Penggunaan |
| :--- | :--- | :--- |
| **Hot Pink** | `#FF4FA3` | Aksen utama, tombol aktif, badge primer |
| **Neon Pink** | `#FF69B4` | Judul, glow effect, teks sorotan |
| **Soft Pink** | `#FFD6E8` | Teks sekunder, label, border lembut |
| **Light Pink** | `#FFF0F6` | Latar belakang Light Mode |
| **Deep Purple** | `#54265E` | Gradient card, header background, aksen |
| **Dark Background** | `#160D19` | Latar belakang utama Dark Mode |
| **Dark Panel** | `#26172B` | Panel glassmorphism & container |
| **White** | `#FFFFFF` | Teks judul utama & kontras |

Tersedia dua mode tema yang dapat dialihkan secara instan:
1. **Pink Dark Mode** (Default)
2. **Pink Light Mode**

---

## 📂 STRUKTUR PROYEK LENGKAP

```text
Web Scan/
│
├── app.py                     # Entry point Streamlit Web App, layout, navigasi & 18 menu
├── scanner.py                 # Core engine scanner, SSRF defense, stream limiter, robots/sitemap
├── seo_analyzer.py            # Parser HTML, Title, Meta, Heading tree, Link, Gambar, Skor SEO
├── security_analyzer.py       # Passive TLS/SSL cert inspector, security headers, cookie audit
├── network_analyzer.py        # Resolusi DNS (A, AAAA, MX, NS, CNAME, TXT), PTR & Geolocation
├── performance_analyzer.py    # Latensi HTTP, payload size, evaluasi caching & kompresi
├── tech_detector.py           # Signature detector CMS, JS framework, CSS, Analytics, Web Server
├── database.py                # SQLite persistence, parameterized queries, history & favorites
├── report_generator.py        # Generator laporan eksekutif PDF, CSV, dan JSON
├── styles.py                  # Custom Cyber Security CSS (Dark/Light themes, glassmorphism)
├── requirements.txt           # Daftar pustaka Python yang dibutuhkan
└── README.md                  # Dokumentasi panduan instalasi, pengujian & deployment
```

---

## 🚀 PANDUAN INSTALASI & MENJALANKAN APLIKASI

### 1. Persyaratan Sistem
- Python 3.10 atau versi lebih baru (Rekomendasi: Python 3.11+).
- Sistem Operasi: Windows 10/11, macOS, atau Linux.

### 2. Membuat Virtual Environment (Disarankan)
Buka terminal (PowerShell di Windows atau Bash di Linux/macOS):

```bash
# Pindah ke direktori proyek
cd "c:\Users\Hype AMD\Downloads\Web Scan"

# Buat virtual environment
python -m venv venv

# Aktivasi virtual environment
# Pada Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Pada Windows Command Prompt (cmd):
.\venv\Scripts\activate.bat
# Pada macOS / Linux:
source venv/bin/activate
```

### 3. Instalasi Dependensi Pustaka
Jalankan perintah berikut di dalam virtual environment:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Isi dari `requirements.txt`:
- `streamlit`: Framework Web App interaktif
- `requests`: HTTP client untuk probing jaringan
- `beautifulsoup4`: Parser DOM HTML
- `pandas`: Manipulasi dan tabulasi data
- `plotly`: Grafik interaktif responsif
- `dnspython`: Resolver DNS record lengkap
- `fpdf2`: Generator laporan PDF profesional

### 4. Menjalankan Aplikasi di VS Code / Terminal
Untuk menjalankan aplikasi Streamlit:

```bash
streamlit run app.py
```

Setelah perintah dijalankan, browser Anda akan otomatis membuka:
👉 `http://localhost:8501`

---

## 📋 18 MENU & FITUR UTAMA

1. **Overview Dashboard:** Total scan, tingkat keberhasilan, rata-rata skor SEO, grafik aktivitas harian, grafik distribusi status HTTP, quick scan target, dan pemindaian terbaru.
2. **Website Scanner:** Pindai URL web lengkap dengan animasi status, domain, final redirect URL, HTTP status, server header, x-powered-by, ukuran dokumen, dan response time.
3. **Title Detector:** Ekstraksi judul website, evaluasi panjang karakter (50-60 karakter), peringatan title kosong, dan simulasi tampilan visual Google SERP.
4. **Meta Analyzer:** Evaluasi meta description, keywords, author, robots, mobile viewport, canonical URL, serta pratinjau kartu media sosial (Facebook Open Graph & Twitter Card).
5. **Heading Analyzer:** Deteksi jumlah tag H1 - H6, visualisasi pohon hierarki heading berindentasi, dan deteksi peringatan kesalahan struktur heading (missing H1, duplicate H1, hierarchy skipping).
6. **Link Analyzer:** Total link internal vs eksternal, pendeteksi link tanpa anchor text, duplicate links, serta filter tabel sampel link.
7. **Image Analyzer:** Total aset gambar, persentase ALT coverage, tabel gambar yang kehilangan atribut ALT, serta grafik distribusi format gambar (.webp, .png, .jpg, .svg).
8. **SEO Audit:** Penilaian skor SEO transparan 0-100 berbasis checklist berbobot dengan grade (A+, A, B, C, D, F) dan rekomendasi perbaikan.
9. **Security Analyzer:** Audit konfigurasi keamanan publik: sertifikat SSL/TLS (issuer, masa berlaku, sisa hari), header keamanan (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), dan audit cookie (Secure, HttpOnly).
10. **IP & DNS Analyzer:** Resolusi alamat IPv4 (A) & IPv6 (AAAA), reverse DNS (PTR), record MX, NS, CNAME, TXT, dan geolokasi publik (Negara, Kota, ISP, ASN).
11. **Technology Detector:** Identifikasi teknologi berdasarkan signature publik: CMS (WordPress, Shopify, Drupal), Framework JS (React, Next.js, Vue, Nuxt, Angular), Framework CSS (Bootstrap, Tailwind CSS), Analytics (Google Analytics, GTM, Hotjar), dan Web Server/CDN (Cloudflare, Nginx, Apache, Vercel).
12. **Performance Analyzer:** Pengukuran latensi respons HTTP, ukuran payload dokumen HTML, evaluasi kompresi (Gzip/Brotli), pemeriksaan header caching (Cache-Control, ETag, Expires), dan rekomendasi optimasi kecepatan.
13. **Robots & Sitemap:** Pengambilan dan parsing `robots.txt` dengan penampil konten berformat, serta pendeteksian `sitemap.xml` beserta penghitungan total URL yang terdaftar.
14. **Scan History:** Penyimpanan riwayat ke database SQLite dengan filter pencarian domain/URL, filter tanggal, kemampuan memuat kembali hasil scan lama, serta opsi hapus aman.
15. **Report Center:** Generator laporan multi-format:
    - **Unduh PDF:** Laporan bergaya Pink Cyber Security siap cetak.
    - **Unduh CSV:** Tabulasi ringkasan metrik.
    - **Unduh JSON:** Data mentah lengkap.
    - **Print View:** Tampilan laporan ramah cetak di peramban.
16. **Comparison Tool:** Komparasi head-to-head dua website (Site A vs Site B) lengkap dengan tabel parameter dan grafik radar perbandingan.
17. **Learning Center:** Modul edukasi komprehensif tentang dasar website, HTML, HTTP/HTTPS, DNS, IP, SSL/TLS, SEO, Security Headers, serta kuis interaktif 3 soal dengan penilaian otomatis.
18. **Settings:** Konfigurasi durasi timeout request, pilihan User-Agent (PinkWebScanner, Chrome, Googlebot), saklar verifikasi SSL, pengalihan tema (Pink Dark / Light), dan informasi developer.

---

## 🔒 KEAMANAN APLIKASI & MITIGASI SSRF

Aplikasi ini menerapkan standar keamanan ketat:
- **Validasi URL:** Hanya protokol `http://` dan `https://` yang diterima.
- **SSRF Defense:** Setiap domain diselesaikan ke alamat IP melalui socket DNS sebelum request dikirimkan. Alamat IP dicek terhadap rentang privat (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `localhost`, `::1`), link-local metadata cloud (`169.254.0.0/16`), dan multicast. Target internal diblokir secara otomatis demi mencegah penyalahgunaan.
- **Port Restriction:** Hanya port web publik standar yang diizinkan (80, 443, 8080, 8443).
- **Stream Limiter:** Pembacaan response dibatasi maksimal 5 MB untuk mencegah serangan denial-of-service (DoS) akibat file raksasa atau zip bomb.
- **Parameterized SQL:** Semua operasi SQLite menggunakan parameterized queries (`?`) untuk mencegah SQL Injection.
- **Passive Inspection Only:** Aplikasi **TIDAK** melakukan brute-force, exploit, atau automated penetration testing.

---

## 🧪 CARA MENGUJI SETIAP FITUR

1. **Uji Scanner:** Masukkan URL `https://github.com` atau klik salah satu preset tombol (`google.com`, `wikipedia.org`). Perhatikan animasi progress bar berjalan hingga 100%.
2. **Uji Navigasi:** Klik menu **Title Detector**, **Meta Analyzer**, dan **Heading Analyzer** di sidebar untuk memverifikasi data target yang baru saja dipindai ditampilkan secara akurat.
3. **Uji SEO Audit:** Buka menu **SEO Audit**, periksa gauge meter skor dan tabel checklist transparan (poin 0-100).
4. **Uji Security:** Buka **Security Analyzer**, amati rincian sertifikat SSL (issuer, hari tersisa) dan tabel kelengkapan security headers.
5. **Uji IP & DNS:** Buka **IP & DNS Analyzer**, amati record A, AAAA, MX, NS, dan koordinat geolokasi ISP.
6. **Uji Report Center:** Buka menu **Report Center**, klik tombol **Unduh PDF**, **Unduh CSV**, dan **Unduh JSON** untuk memastikan file berhasil digenerate.
7. **Uji Komparasi:** Buka **Comparison Tool**, klik tombol **Bandingkan Sekarang** untuk melihat radar chart dan tabel perbedaan dua website.
8. **Uji Tema & Bahasa:** Ubah pilihan **Tema** (Dark/Light) dan **Bahasa** (ID/EN) di sidebar, pastikan seluruh tampilan langsung menyesuaikan palet warna secara instan.

---

## 🌐 CARA DEPLOY KE INTERNET

### Opsi 1: Streamlit Community Cloud (Gratis & Paling Mudah)
1. Unggah seluruh folder proyek ke repositori GitHub Anda (publik atau privat).
2. Kunjungi [share.streamlit.io](https://share.streamlit.io/) dan masuk menggunakan akun GitHub.
3. Klik **New app**, pilih repository, branch `main`, dan set file utama ke `app.py`.
4. Klik **Deploy**! Aplikasi Pink Web Scanner Anda akan aktif dengan domain publik `https://<nama-app>.streamlit.app`.

### Opsi 2: Deploy dengan Docker (Containerized)
Buat file `Dockerfile` pada direktori proyek:
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```
Jalankan container:
```bash
docker build -t pink-web-scanner .
docker run -p 8501:8501 pink-web-scanner
```

---

## 🛠️ TROUBLESHOOTING & PEMECAHAN MASALAH

- **Error `Port 8501 is already in use`:**
  Jalankan Streamlit pada port alternatif:
  ```bash
  streamlit run app.py --server.port 8502
  ```
- **Error `SSRF Protection: Host diselesaikan ke IP privat`:**
  Ini adalah fitur keamanan normal untuk mencegah pemindaian IP internal (seperti `127.0.0.1` atau `192.168.x.x`). Gunakan domain atau IP publik yang sah.
- **Sertifikat SSL Error saat Scanning:**
  Jika website target memiliki sertifikat self-signed, buka menu **Settings** dan nonaktifkan opsi *Verifikasi Sertifikat SSL/TLS saat Request*.

---

*Pink Web Scanner © 2026. Futuristic Cyber Security Suite. All rights reserved.*
