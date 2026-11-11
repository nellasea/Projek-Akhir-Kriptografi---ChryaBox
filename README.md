# CHRYA BOX v2.0 — Private Messaging & Digital Secret Vault

Aplikasi web keamanan berlapis (*responsive desktop & mobile*) untuk komunikasi rahasia asinkron antarbrankas dan penyimpanan dokumen terenkripsi. Seluruh fitur backend, frontend, database, kriptografi, biometrik, dan audit ledger telah diaudit dan diuji secara menyeluruh.

---

## 1. Ringkasan Arsitektur & Fitur Utama (Revisi Audit v2.0)

| Modul | Implementasi Teknis |
|---|---|
| **A. Face Recognition & Liveness** | Deteksi wajah & 5 landmark menggunakan **OpenCV Zoo YuNet** (`face_detection_yunet_2023mar.onnx`, MIT License) + ekstraksi fitur wajah **SFace 128-D ArcFace-class Embedding** (`face_recognition_sface_2021dec.onnx`, Apache-2.0 License). Dilengkapi validasi satu wajah tunggal, pencahayaan, ketajaman, deteksi anti-spoofing permukaan/replay, *rate limiting* persisten di database, serta enkripsi template `FC02` (AES-256-GCM + AAD `user_id`). |
| **B. USB Dongle Security** | Verifikasi challenge-response **HMAC-SHA256** di browser + pengecekan keberadaan fisik di host server. Mendukung pelacakan otomatis meskipun huruf drive berubah (`C:`..`Z:` + *Windows Volume Serial Number*), registrasi ulang USB, pencabutan (*revocation*) token USB lama, dan penanganan USB hilang/rusak. |
| **C. Encryption & Key Management** | **Vigenère + AES-256-GCM** untuk pesan dan catatan, **ChaCha20-Poly1305** untuk file (dengan kunci unik per file yang di-wrap AES-256-GCM), **LSB Steganography** untuk PNG, dan **HKDF-SHA256 Domain Key Separation** (kunci terpisah untuk `SUBJECT`, `BODY`, `FILE`, `FILENAME`, `NOTE_TITLE`, `NOTE_BODY`, `FACE`, `STEGO`, `USB_SECRET`). Mendukung rotasi kunci (`KeyRing`) dan backup `master.key` terenkripsi (Scrypt + AES-256-GCM). |
| **D. Contact Management** | Pencarian langsung (*live search*) berdasarkan `username` dan `full_name`, status tidak ditemukan, kirim/batalkan/terima/tolak undangan, hapus kontak, *block & unblock*, filter status kontak, pencegahan undangan ganda, dan wajib kontak `accepted` sebelum bertukar pesan/file. |
| **E. Messaging System** | Inbox, Sent, Archive, Unarchive, Pin/Favorit (`★`), pencarian pesan terenkripsi, balas pesan (*reply* mempertahankan enkripsi), hapus pesan tunggal, hapus seluruh percakapan, indikator pengiriman (`✓ Terkirim ke Brankas` / `✓✓ Terbaca` beserta waktu baca), dan proteksi IDOR. |
| **F. File Vault** | Unggah & enkripsi ChaCha20-Poly1305 (maks. 6 MB, validasi ekstensi), unduh & dekripsi utuh, *inline preview* (gambar, teks/CSV, PDF), pencarian & kategori file, berbagi ke kontak, pencabutan akses file (*revoke*), dan penghapusan file permanen. |
| **G. My Vault** | Buat, baca, edit/perbarui, hapus, cari, dan kategorikan catatan pribadi terenkripsi (`Umum`, `Pribadi`, `Kredensial`, `Pekerjaan`, `Akademik`) yang hanya dapat dibuka oleh pemiliknya. |
| **H. Notification System** | Notifikasi *in-app* untuk undangan kontak, pesan baru, file masuk, dan peringatan keamanan; fitur *mark as read*, *mark all as read*, hapus notifikasi, filter belum dibaca, serta integrasi pengiriman email **SMTP** sungguhan (tanpa membocorkan plaintext). |
| **I. Security Center** | Ganti password, daftar perangkat yang sedang login, *logout* semua perangkat / perangkat tertentu, riwayat aktivitas login & deteksi login mencurigakan, manajemen Passkey WebAuthn, hapus/atur ulang template wajah, manajemen USB Key, dan pemulihan akun darurat (*6 single-use Recovery Codes*). |
| **J. Audit Hash Chain Ledger** | Rantai hash **SHA-256** berurutan dengan deteksi modifikasi data, perhitungan **Merkle Root**, tanda tangan digital **Ed25519** pada *checkpoint*, *external anchoring* (`instance/anchors/`), dan ekspor backup audit log JSON. |
| **K. Database & Infrastruktur** | Mendukung **SQLite** dan **MySQL 8+** pada satu database terpusat, migrasi skema otomatis & **Alembic**, hot backup database (`instance/backups/`), generator sertifikat **HTTPS TLS** lokal (`tools/generate_https_cert.py`), validasi ketat Origin/Referer & CSRF, serta *structured error logging* (`instance/logs/chrya_error.log`). |

---

## 2. Instalasi & Menjalankan Aplikasi (Windows / Linux / macOS)

### A. Persiapan Environment
```powershell
cd CHRYA_BOX_FullStack
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

### B. Pendaftaran Flashdisk USB Dongle
Sambungkan flashdisk (misalnya drive `E:\`) lalu daftarkan:
```powershell
python tools/enroll_usb.py E:\
```
Perintah ini membuat `E:\chrya_usb.key` (32 byte) dan mencatat digest beserta *Volume Serial Number* di `instance/dongle_registry.json`.
- Untuk merotasi/mengganti USB dan mencabut akses token USB lama: `python tools/enroll_usb.py --rotate E:\`
- Untuk mencabut USB yang hilang: `python tools/enroll_usb.py --revoke`

### C. Menjalankan Server (HTTP Lokal atau HTTPS Lintas Perangkat)
1. **Mode Standar (`localhost`)**:
   ```powershell
   python app.py
   ```
   Buka `http://localhost:8765`.
2. **Mode HTTPS (untuk Kamera & WebAuthn di HP melalui Wi-Fi/LAN)**:
   Buat sertifikat TLS self-signed untuk IP lokal Anda (mis. `192.168.1.10`):
   ```powershell
   python tools/generate_https_cert.py 192.168.1.10
   ```
   Isi `CHRYA_SSL_CERTFILE` dan `CHRYA_SSL_KEYFILE` di `.env`, lalu jalankan `python app.py`.

### D. Migrasi Database (Alembic)
Saat aplikasi dijalankan, fungsi `ensure_schema_migrations()` otomatis menambahkan kolom/tabel baru tanpa menghapus data lama. Anda juga dapat menjalankan migrasi Alembic secara eksplisit:
```powershell
alembic upgrade head
```

---

## 3. Kalibrasi Threshold Face Recognition (FAR & FRR)

Pengujian dan kalibrasi dilakukan menggunakan `tools/calibrate_face_threshold.py` pada dataset wajah nyata **Olivetti Faces** (40 individu berbeda, 400 citra wajah, **1.800 pasangan pemilik asli** dan **78.000 pasangan impostor/orang berbeda**):

| Max Cosine Distance | Min Cosine Similarity | False Acceptance Rate (FAR) | False Rejection Rate (FRR) |
|---|---|---|---|
| `0.40` | `0.600` | `0.000%` | `4.111%` |
| `0.45` | `0.550` | `0.029%` | `2.111%` |
| **`0.48` (Aktif)** | **`0.520`** | **`0.085%`** | **`1.500%`** |
| `0.50` | `0.500` | `0.141%` | `1.278%` |
| `0.55` | `0.450` | `0.600%` | `0.389%` |

Threshold aktif ditetapkan pada `MAX_MATCH_DISTANCE = 0.48` (`cosine similarity >= 0.52`), yang menolak >99,91% percobaan wajah orang lain sekaligus menjaga kenyamanan pemilik akun.

---

## 4. Menjalankan Pengujian Otomatis

```powershell
python -m pytest tests/test_chrya.py -v
```
Seluruh **37 test suite komprehensif** menguji kriptografi, autentikasi 3 faktor, pencocokan wajah 2 orang berbeda dengan model SFace 128-D, anti-spoofing, pencabutan USB, kontak, pesan, file vault, my vault, notifikasi + pengiriman SMTP nyata, security center, tanda tangan Ed25519 hash chain, hingga ketahanan terhadap CSRF, IDOR, SQL Injection, dan XSS.

---

## 5. Keterbatasan Sistem yang Perlu Dipahami (Dokumentasi Jujur)

1. **Server-Side Encryption (SSE) vs E2EE**: Enkripsi dan dekripsi dilakukan di server menggunakan sub-kunci HKDF yang diturunkan dari `instance/master.key`. Ini melindungi data secara kuat saat disimpan di database/disk (*encryption at rest*), namun bukan *End-to-End Encryption* (E2EE) karena server memegang kunci master. Lihat `docs/SSE_VS_E2EE.md`.
2. **Keterbatasan File-Based USB Token (`chrya_usb.key`)**: File kunci 32-byte pada flashdisk standar dapat disalin (*cloneable*) jika pihak lain memiliki akses fisik ke flashdisk tersebut. Mekanisme ini mendemonstrasikan faktor kepemilikan berbasis tantangan HMAC-SHA256 dan pelacakan serial volume, namun **tidak setara** dengan *hardware security key* FIDO2/YubiKey yang memiliki elemen aman non-ekspor. Untuk mitigasi, pengguna dapat segera mencabut (*revoke*) kunci USB lama di **Security Center** jika flashdisk dicurigai bocor atau hilang.
3. **Anti-Spoofing Kamera**: Sistem memvalidasi 1 wajah tunggal, pencahayaan, ketajaman, distribusi gradien 3D wajah, serta menolak *frame replay* identik pada mode *burst*. Namun, kamera 2D standar pada browser tanpa sensor kedalaman inframerah (IR/ToF) tetap memiliki batasan fisik terhadap serangan *high-resolution 3D mask* atau layar OLED terkalibrasi. Karena itu, faktor Password (Argon2id) dan USB Key (HMAC-SHA256) tetap diwajibkan bersama Face Unlock, dan WebAuthn/Windows Hello tersedia untuk autentikasi berbasis perangkat keras.
4. **Audit Hash Chain vs Distributed Blockchain**: Modul *Blockchain Ledger* mengimplementasikan rantai hash kriptografis SHA-256 dengan Merkle Root, tanda tangan digital Ed25519 pada *checkpoint*, dan *external anchoring* ke file sistem, tetapi berjalan pada satu node server (bukan jaringan konsensus terdistribusi *peer-to-peer*).
#   P r o j e k - A k h i r - K r i p t o g r a f i - - - C h r y a B o x  
 