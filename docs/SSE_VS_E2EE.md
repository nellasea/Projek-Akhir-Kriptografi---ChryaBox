# Dokumentasi Arsitektur Kriptografi: Server-Side Encryption (SSE) vs End-to-End Encryption (E2EE)

Dokumen ini menjelaskan perbedaan mendasar antara **Server-Side Encryption (SSE)** dan **End-to-End Encryption (E2EE)** serta bagaimana **CHRYA BOX v2.0** menerapkan kriptografi berlapis dengan pemisahan kunci domain (*HKDF Domain Key Separation*).

---

## 1. Perbandingan Arsitektur SSE vs E2EE

| Aspek Keamanan | Server-Side Encryption (SSE) — **Diterapkan di CHRYA BOX** | End-to-End Encryption (E2EE) |
|---|---|---|
| **Tempat Enkripsi & Dekripsi** | Dilakukan oleh backend server sebelum disimpan ke database/disk dan saat dikirim ke klien melalui sesi HTTPS yang terautentikasi. | Dilakukan sepenuhnya di perangkat pengirim dan penerima (mis. WebCrypto API di browser). |
| **Pemegang Kunci Dekripsi** | Server mengelola `instance/master.key` dan `instance/keyring.json`. Kunci diturunkan per domain dengan **HKDF-SHA256**. | Hanya perangkat pengguna yang memegang *private key* (mis. ECDH P-256 / X25519). Server hanya menyimpan *public key*. |
| **Perlindungan terhadap Kebocoran Database** | **Ya (Kuat):** jika file SQLite/MySQL atau folder `storage/` bocor tanpa `master.key`, seluruh pesan, catatan, nama file, isi file, dan biometrik tetap berupa ciphertext AEAD yang tidak dapat dibaca. | **Ya (Kuat):** database hanya menyimpan ciphertext. |
| **Perlindungan terhadap Kompromi Server Aktif** | **Terbatas:** administrator server atau penyerang yang menguasai proses server & `master.key` secara bersamaan dapat mendekripsi data. | **Ya (Kuat):** server tidak memiliki *private key* pengguna sehingga tidak dapat membaca pesan meskipun server dikuasai. |
| **Pencarian Server-Side & Multi-Perangkat** | Pengguna dapat login dari perangkat baru dan langsung mencari/membaca arsip pesan setelah lolos 3 faktor autentikasi (Password + USB + Wajah/WebAuthn). | Memerlukan sinkronisasi *private key* antarperangkat (mis. *key wrapping* dengan passphrase atau *QR key transfer*). |

---

## 2. Pemisahan Kunci Domain (HKDF-SHA256) pada CHRYA BOX

Untuk memenuhi prinsip *key separation* (poin audit C.10), CHRYA BOX **tidak** menggunakan `master.key` secara langsung untuk mengenkripsi semua jenis data. Sebaliknya, `crypto_engine.py` menggunakan **HKDF-SHA256** (`derive_subkey(master_key, context, key_id)`) dengan `salt` berbasis versi kunci (`kid`) dan `info` spesifik domain untuk menghasilkan sub-kunci 256-bit yang berbeda secara kriptografis:

1. **`SUBJECT` (`CHRYA-DOMAIN:MESSAGE-SUBJECT:v1`)**: Subjek pesan (Vigenère + AES-256-GCM).
2. **`BODY` (`CHRYA-DOMAIN:MESSAGE-BODY:v1`)**: Isi pesan rahasia (Vigenère + AES-256-GCM).
3. **`FILE` (`CHRYA-DOMAIN:FILE-WRAP:v1`)**: Mengenkripsi (*key wrapping* AES-256-GCM) kunci unik 256-bit per file, sedangkan isi file dienkripsi dengan **ChaCha20-Poly1305**.
4. **`FILENAME` (`CHRYA-DOMAIN:FILE-NAME:v1`)**: Nama asli file di tabel database.
5. **`NOTE_TITLE` & `NOTE_BODY`**: Judul dan isi catatan pribadi di *My Vault*.
6. **`FACE` (`CHRYA-DOMAIN:BIOMETRIC-FACE:v1`)**: Template fitur wajah 128-D SFace (`FC02`), diikat dengan *Additional Authenticated Data* (AAD) `CHRYA-FACE:{user_id}` sehingga template milik satu akun tidak dapat dipindahkan ke akun lain.
7. **`STEGO` (`CHRYA-DOMAIN:STEGANOGRAPHY:v1`)**: Payload rahasia sebelum disisipkan ke piksel PNG menggunakan LSB.
8. **`USB_SECRET` (`CHRYA-DOMAIN:USB-TOKEN:v1`)**: Penyimpanan terenkripsi untuk parameter verifikasi HMAC USB Key per pengguna.
9. **`LEDGER_ED25519_SIGNING`**: Menurunkan pasangan kunci tanda tangan digital **Ed25519** untuk menandatangani *checkpoint* dan *Merkle Root* pada Blockchain Audit Ledger.

---

## 3. Rotasi Kunci (`KeyRing`) dan Backup Master Key

- **Rotasi Kunci (`POST /api/security/keys/rotate`)**: Membuat versi kunci baru (`kid = 2, 3, ...`) yang dibungkus (*wrapped*) secara aman di `instance/keyring.json`. Setiap ciphertext v2 menyimpan metadata `"kid"` dan header file `CHRYAF02` menyimpan 2-byte `kid`, sehingga data lama tetap dapat didekripsi tanpa kehilangan data, sementara data baru otomatis memakai kunci terbaru.
- **Backup Master Key (`POST /api/security/keys/backup`)**: Mengekspor `master.key` beserta `keyring` dalam format JSON terenkripsi menggunakan **Scrypt (`N=16384, r=8, p=1`) + AES-256-GCM** dengan *passphrase* minimal 10 karakter.
