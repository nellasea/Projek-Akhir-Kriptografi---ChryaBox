# CHRYA BOX v2.0
### Private Messaging & Digital Secret Vault

**CHRYA BOX** merupakan aplikasi web keamanan berlapis yang dirancang untuk menyediakan layanan komunikasi rahasia dan penyimpanan dokumen digital terenkripsi. Aplikasi ini mendukung penggunaan melalui desktop maupun perangkat mobile dengan antarmuka yang responsif (*responsive design*).

Sistem mengintegrasikan teknologi kriptografi, autentikasi biometrik, keamanan berbasis USB Dongle, pengelolaan kunci enkripsi, serta pencatatan aktivitas melalui Audit Hash Chain Ledger.

CHRYA BOX dikembangkan dengan pendekatan keamanan berlapis untuk melindungi kerahasiaan data, membatasi akses pengguna, dan menjaga integritas informasi yang tersimpan di dalam sistem.

---

## 1. Fitur dan Arsitektur Sistem

CHRYA BOX terdiri atas beberapa modul utama yang saling terintegrasi untuk mendukung keamanan komunikasi dan pengelolaan data digital.

| Modul | Deskripsi dan Implementasi |
|---|---|
| **A. Face Recognition & Liveness Detection** | Menggunakan OpenCV Zoo YuNet (`face_detection_yunet_2023mar.onnx`) untuk deteksi wajah dan lima landmark wajah, serta SFace 128-D untuk ekstraksi fitur wajah berbasis embedding. Sistem dilengkapi validasi satu wajah, pemeriksaan pencahayaan dan ketajaman gambar, deteksi anti-spoofing permukaan dan replay, serta pembatasan percobaan login (*persistent rate limiting*). Template wajah disimpan menggunakan enkripsi AES-256-GCM dengan format `FC02` dan AAD `user_id`. |
| **B. USB Dongle Security** | Mengimplementasikan mekanisme autentikasi *challenge-response* menggunakan HMAC-SHA256. Sistem memeriksa keberadaan USB secara fisik pada host server dan mendukung pelacakan perangkat berdasarkan Windows Volume Serial Number, meskipun huruf drive berubah. Tersedia fitur registrasi ulang, pencabutan token (*revocation*), serta penanganan USB yang hilang atau rusak. |
| **C. Encryption & Key Management** | Menggunakan kombinasi Vigenère dan AES-256-GCM untuk pesan dan catatan, serta ChaCha20-Poly1305 untuk enkripsi file. Setiap file menggunakan kunci unik yang dilindungi melalui AES-256-GCM. Sistem juga menerapkan LSB Steganography untuk PNG, HKDF-SHA256 untuk pemisahan kunci berdasarkan domain, rotasi kunci melalui `KeyRing`, serta pencadangan `master.key` menggunakan Scrypt dan AES-256-GCM. |
| **D. Contact Management** | Menyediakan pencarian kontak secara langsung berdasarkan `username` dan `full_name`. Pengguna dapat mengirim, membatalkan, menerima, dan menolak undangan kontak, menghapus kontak, serta melakukan pemblokiran dan pembukaan blokir. Sistem mencegah undangan ganda dan mewajibkan status kontak `accepted` sebelum pertukaran pesan maupun file dilakukan. |
| **E. Messaging System** | Mendukung pengelolaan pesan melalui Inbox, Sent, dan Archive. Pengguna dapat mengarsipkan, menyematkan, mencari pesan, membalas pesan dengan tetap mempertahankan enkripsi, menghapus pesan, dan menghapus seluruh percakapan. Sistem menyediakan indikator status pengiriman dan pembacaan pesan beserta waktu baca, serta perlindungan terhadap serangan IDOR. |
| **F. File Vault** | Menyediakan fitur unggah dan unduh dokumen dengan enkripsi ChaCha20-Poly1305. Batas ukuran file adalah 6 MB dengan validasi ekstensi. Pengguna dapat melihat pratinjau gambar, teks/CSV, dan PDF, melakukan pencarian serta pengelompokan file, berbagi file dengan kontak, mencabut akses file, dan menghapus file secara permanen. |
| **G. My Vault** | Merupakan ruang penyimpanan catatan pribadi yang mendukung pembuatan, pembacaan, pengubahan, pencarian, dan penghapusan catatan terenkripsi. Catatan dapat dikelompokkan ke dalam kategori Umum, Pribadi, Kredensial, Pekerjaan, dan Akademik. Setiap catatan hanya dapat diakses oleh pemiliknya. |
| **H. Notification System** | Menyediakan notifikasi dalam aplikasi untuk undangan kontak, pesan baru, file masuk, dan peringatan keamanan. Pengguna dapat menandai notifikasi sebagai telah dibaca, menandai seluruh notifikasi, menghapus notifikasi, serta memfilter notifikasi yang belum dibaca. Sistem juga mendukung pengiriman email melalui SMTP tanpa menyertakan plaintext pesan. |
| **I. Security Center** | Menyediakan pengelolaan keamanan akun, meliputi perubahan password, daftar perangkat yang sedang login, logout dari perangkat tertentu atau seluruh perangkat, riwayat aktivitas login, deteksi login mencurigakan, pengelolaan Passkey WebAuthn, pengaturan ulang template wajah, manajemen USB Key, serta enam Recovery Codes sekali pakai untuk pemulihan akun darurat. |
| **J. Audit Hash Chain Ledger** | Menerapkan pencatatan aktivitas menggunakan rantai hash SHA-256 untuk mendeteksi perubahan data. Sistem mendukung perhitungan Merkle Root, tanda tangan digital Ed25519 pada checkpoint, penyimpanan *external anchoring* di `instance/anchors/`, serta ekspor cadangan audit log dalam format JSON. |
| **K. Database & Infrastructure** | Mendukung SQLite dan MySQL 8+ dengan pengelolaan database terpusat. Sistem menyediakan migrasi skema otomatis melalui Alembic, pencadangan database di `instance/backups/`, pembuatan sertifikat HTTPS TLS lokal melalui `tools/generate_https_cert.py`, validasi Origin/Referer, perlindungan CSRF, serta pencatatan error terstruktur di `instance/logs/chrya_error.log`. |

---

## 2. Teknologi yang Digunakan

Berikut teknologi utama yang digunakan dalam pengembangan CHRYA BOX:

| Kategori | Teknologi |
|---|---|
| Backend | Python |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite, MySQL 8+ |
| Face Recognition | OpenCV YuNet, SFace |
| Cryptography | AES-256-GCM, ChaCha20-Poly1305, HMAC-SHA256, HKDF-SHA256 |
| Steganography | Least Significant Bit (LSB) |
| Key Derivation | Scrypt |
| Authentication | Argon2id, WebAuthn, USB Dongle |
| Digital Signature | Ed25519 |
| Hash Algorithm | SHA-256 |
| Database Migration | Alembic |
| Testing | Pytest |
| Communication | SMTP |

---

## 3. Instalasi dan Konfigurasi

CHRYA BOX dapat dijalankan pada Windows, Linux, maupun macOS selama dependensi dan konfigurasi sistem telah dipenuhi.

### A. Persiapan Environment

Pastikan Python telah terinstal. Selanjutnya, buka terminal pada direktori proyek dan jalankan:

```bash
cd CHRYA_BOX_FullStack
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Perintah tersebut digunakan untuk memasang seluruh dependensi utama dan dependensi pengembangan yang dibutuhkan aplikasi.

### B. Registrasi USB Dongle

USB Dongle digunakan sebagai salah satu faktor autentikasi dalam sistem.

1. Sambungkan flashdisk ke komputer.
2. Pastikan flashdisk terdeteksi oleh sistem operasi.
3. Jalankan perintah registrasi berikut:

```powershell
python tools/enroll_usb.py E:\
```

Proses ini akan membuat file `chrya_usb.key` berukuran 32 byte pada flashdisk dan mencatat digest serta Windows Volume Serial Number ke dalam `instance/dongle_registry.json`.

**Perintah pengelolaan USB:**

- Registrasi atau rotasi USB:

```powershell
python tools/enroll_usb.py --rotate E:\
```

- Pencabutan akses USB yang hilang:

```powershell
python tools/enroll_usb.py --revoke
```

### C. Menjalankan Server

CHRYA BOX menyediakan dua mode akses aplikasi.

**1. Mode HTTP Lokal**

Untuk menjalankan aplikasi pada komputer lokal:

```bash
python app.py
```

Setelah server berjalan, buka browser dan akses:

```text
http://localhost:8765
```

**2. Mode HTTPS untuk Akses Lintas Perangkat**

Mode HTTPS digunakan ketika aplikasi perlu diakses melalui perangkat lain dalam jaringan Wi-Fi atau LAN, khususnya untuk mendukung akses kamera dan WebAuthn.

Buat sertifikat TLS lokal menggunakan perintah:

```powershell
python tools/generate_https_cert.py 192.168.1.10
```

Ganti `192.168.1.10` dengan alamat IP lokal komputer yang menjalankan server.

Selanjutnya, konfigurasi variabel berikut pada file `.env`:

```env
CHRYA_SSL_CERTFILE=path/to/certificate.crt
CHRYA_SSL_KEYFILE=path/to/private.key
```

Setelah konfigurasi selesai, jalankan kembali aplikasi:

```bash
python app.py
```

**Catatan:** Sertifikat *self-signed* perlu dipercaya oleh perangkat klien sebelum digunakan. Konfigurasi HTTPS juga harus sesuai dengan alamat IP dan kebijakan keamanan browser.

### D. Migrasi Database

CHRYA BOX menyediakan mekanisme migrasi database untuk menyesuaikan struktur tabel ketika terjadi perubahan pada aplikasi.

Fungsi `ensure_schema_migrations()` akan dijalankan secara otomatis ketika aplikasi dimulai untuk menangani perubahan skema yang didukung.

Migrasi juga dapat dilakukan secara manual menggunakan Alembic:

```bash
alembic upgrade head
```

---

## 4. Kalibrasi Face Recognition (FAR dan FRR)

Pengujian dan kalibrasi sistem pengenalan wajah dilakukan menggunakan script:

```text
tools/calibrate_face_threshold.py
```

Dataset yang digunakan adalah **Olivetti Faces**, yang terdiri atas 40 individu dengan total 400 citra wajah.

Pengujian mencakup:
- 1.800 pasangan citra dari individu yang sama (*genuine pairs*).
- 78.000 pasangan citra dari individu yang berbeda (*impostor pairs*).

Hasil pengujian berdasarkan variasi threshold ditampilkan pada tabel berikut.

| Maximum Cosine Distance | Minimum Cosine Similarity | False Acceptance Rate (FAR) | False Rejection Rate (FRR) |
|---|---|---|---|
| `0.40` | `0.600` | `0.000%` | `4.111%` |
| `0.45` | `0.550` | `0.029%` | `2.111%` |
| **`0.48` (Aktif)** | **`0.520`** | **`0.085%`** | **`1.500%`** |
| `0.50` | `0.500` | `0.141%` | `1.278%` |
| `0.55` | `0.450` | `0.600%` | `0.389%` |

Threshold yang digunakan dalam konfigurasi sistem adalah:

```python
MAX_MATCH_DISTANCE = 0.48
```

Dengan demikian, sistem menerima kecocokan wajah ketika cosine distance tidak melebihi `0.48`, atau cosine similarity minimal `0.52`.

Berdasarkan hasil pengujian pada dataset tersebut, konfigurasi aktif menghasilkan FAR sebesar `0.085%` dan FRR sebesar `1.500%`.

**Catatan:** Hasil ini merupakan hasil pengujian pada dataset Olivetti Faces, bukan jaminan tingkat akurasi yang sama pada seluruh kondisi penggunaan nyata. Performa pengenalan wajah dapat dipengaruhi oleh pencahayaan, sudut pengambilan gambar, kualitas kamera, dan variasi karakteristik wajah.

---

## 5. Pengujian Otomatis

Pengujian otomatis dilakukan menggunakan Pytest untuk memeriksa fungsi utama dan mekanisme keamanan CHRYA BOX.

Jalankan perintah berikut:

```bash
python -m pytest tests/test_chrya.py -v
```

Berdasarkan hasil pengujian yang didokumentasikan, terdapat **37 test suite komprehensif** yang mencakup berbagai komponen sistem, antara lain:

1. Pengujian algoritma dan mekanisme kriptografi.
2. Pengujian autentikasi tiga faktor.
3. Pengujian pengenalan wajah menggunakan model SFace 128-D.
4. Pengujian anti-spoofing.
5. Pengujian registrasi dan pencabutan USB Dongle.
6. Pengujian pengelolaan kontak.
7. Pengujian pengiriman dan penerimaan pesan.
8. Pengujian File Vault dan My Vault.
9. Pengujian sistem notifikasi dan integrasi SMTP.
10. Pengujian Security Center.
11. Pengujian Audit Hash Chain, Merkle Root, dan tanda tangan digital Ed25519.
12. Pengujian perlindungan terhadap CSRF, IDOR, SQL Injection, dan XSS.

Pengujian ini bertujuan untuk memastikan setiap modul berjalan sesuai dengan fungsi yang dirancang serta membantu mengidentifikasi potensi kesalahan dan celah keamanan.

---

## 6. Batasan dan Pertimbangan Keamanan

Keamanan sistem tidak hanya ditentukan oleh algoritma yang digunakan, tetapi juga oleh implementasi, pengelolaan kunci, perangkat keras, dan lingkungan operasional. Oleh karena itu, terdapat beberapa batasan CHRYA BOX yang perlu dipahami.

### A. Server-Side Encryption (SSE), Bukan End-to-End Encryption (E2EE)

CHRYA BOX menggunakan pendekatan *Server-Side Encryption* (SSE). Proses enkripsi dan dekripsi dilakukan pada sisi server dengan subkunci yang diturunkan melalui HKDF dari `instance/master.key`.

Mekanisme ini memberikan perlindungan terhadap data yang tersimpan di database maupun media penyimpanan (*encryption at rest*).

Namun, sistem belum menerapkan *End-to-End Encryption* (E2EE), karena server masih memiliki akses terhadap kunci master yang diperlukan untuk proses dekripsi.

Dokumentasi lebih lanjut tersedia di:

`docs/SSE_VS_E2EE.md`

### B. Keterbatasan USB Dongle

USB Dongle menggunakan file kunci `chrya_usb.key` berukuran 32 byte yang disimpan pada flashdisk standar.

Karena file tersebut dapat disalin, mekanisme ini masih memiliki risiko duplikasi apabila pihak lain memperoleh akses terhadap file kunci.

Implementasi HMAC-SHA256 dan Windows Volume Serial Number digunakan untuk memverifikasi kepemilikan serta mengidentifikasi perangkat USB. Namun, mekanisme tersebut tidak setara dengan *hardware security key* seperti FIDO2 atau YubiKey yang menggunakan elemen keamanan khusus dengan kunci privat non-ekspor.

Apabila USB hilang atau dicurigai telah disalin, pengguna dapat mencabut akses token melalui fitur **Security Center**.

### C. Keterbatasan Anti-Spoofing Kamera

Sistem menerapkan sejumlah pemeriksaan untuk mengurangi risiko pemalsuan identitas menggunakan kamera, meliputi:

- Validasi keberadaan satu wajah.
- Pemeriksaan pencahayaan dan ketajaman gambar.
- Analisis distribusi gradien wajah.
- Deteksi frame replay identik pada mode burst.

Meskipun demikian, kamera 2D standar pada browser memiliki keterbatasan dalam mendeteksi serangan menggunakan *high-resolution 3D mask* atau layar OLED yang telah dikalibrasi.

Sistem karena itu tetap mewajibkan kombinasi autentikasi Password (Argon2id), USB Key (HMAC-SHA256), dan Face Unlock. Selain itu, WebAuthn/Windows Hello tersedia untuk mendukung autentikasi berbasis perangkat.

### D. Audit Hash Chain Bukan Blockchain Terdistribusi

Modul Audit Hash Chain Ledger menggunakan prinsip rantai hash kriptografis SHA-256, Merkle Root, tanda tangan digital Ed25519 pada checkpoint, dan mekanisme *external anchoring*.

Mekanisme ini digunakan untuk membantu mendeteksi perubahan pada catatan audit dan menjaga integritas riwayat aktivitas.

Namun, implementasinya berjalan pada satu server dan tidak menggunakan jaringan konsensus terdistribusi *peer-to-peer* seperti blockchain publik.

Dengan demikian, CHRYA BOX menggunakan mekanisme **Hash Chain Ledger dengan fitur audit kriptografis**, bukan blockchain terdistribusi.

---

## 7. Lisensi dan Penggunaan

CHRYA BOX dikembangkan sebagai proyek akademik pada bidang Kriptografi dengan fokus pada penerapan algoritma enkripsi, autentikasi berlapis, keamanan penyimpanan data, dan integritas informasi digital.

Beberapa model dan pustaka pihak ketiga digunakan dalam proyek ini, termasuk OpenCV Zoo YuNet dan SFace, dengan ketentuan lisensi masing-masing.

Penggunaan, pengembangan, dan distribusi proyek perlu memperhatikan lisensi komponen pihak ketiga yang digunakan.

---

**CHRYA BOX v2.0 — Private Messaging & Digital Secret Vault**

*Secure Communication. Encrypted Storage. Layered Protection.*
