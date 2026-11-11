# CHRYA BOX — Kontak dan Pesan Antarperangkat

Versi: 9 November 2026. Fokus: pencarian pengguna, undangan kontak, dan pesan dua arah melalui **satu server dan satu database**.

## 1. Apa yang berubah?

- Pencarian username/nama langsung dari database (minimal dua karakter; isi formulir diperbarui saat pengguna mengetik).
- Hasil pencarian menampilkan status: tambah kontak, undangan terkirim, undangan masuk, atau sudah terhubung.
- Undangan disimpan dan dapat diterima/ditolak dari akun perangkat lain. Tombol **Kirim pesan** muncul setelah kontak disetujui.
- Pesan disimpan sebagai ciphertext **Vigenère + AES-256-GCM**, masuk ke Inbox penerima, dan dapat dibalas.
- Badges Inbox dan undangan masuk diperbarui melalui pemeriksaan setiap 12 detik saat halaman masih terbuka; ada tombol **Refresh** manual.
- Pencarian tidak mengungkapkan email atau informasi biometrik orang lain.
- Pengecekan Origin memungkinkan akses dari IP privat yang sama dengan server saat pengaturan LAN diaktifkan (bukan wildcard `*`).

## 2. Instal revisi di Windows (jaga akun lama)

1. Matikan server (`Ctrl+C`). Cadangkan folder `instance` terlebih dahulu.
2. Ekstrak ZIP PATCH dan salin `app.py` serta folder `static` ke folder proyek `CHRYA_BOX_FullStack`, pilih *Replace*.
3. **Jangan ganti atau hapus** `.env`, `instance/chrya.sqlite3`, `instance/master.key`, atau USB Key terdaftar.
4. Jika ingin akses melalui HP di jaringan lokal tepercaya, perbarui **hanya** baris berikut di `.env`:

   ```env
   CHRYA_ORIGIN=http://localhost:8765
   CHRYA_HOST=0.0.0.0
   CHRYA_PORT=8765
   CHRYA_ALLOW_PRIVATE_LAN=true
   ```

5. Instal dependensi jika belum ada:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

6. Hubungkan flashdisk yang sudah didaftarkan, lalu jalankan:

   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```

7. Buka `http://localhost:8765` di laptop. Di HP dalam Wi-Fi yang sama, coba `http://IP-LAPTOP:8765` (IP dari `ipconfig`). Izinkan port 8765 di Windows Firewall **hanya untuk jaringan Private** jika diperlukan.

**Catatan krusial:** `http://IP-LAPTOP:8765` dapat membuka halaman, tetapi **kamera dan WebAuthn di HP memerlukan HTTPS**. Jadi, untuk mendaftar/login wajah dari HP, gunakan satu alamat HTTPS yang dapat diakses dari kedua perangkat. Contoh untuk uji coba: jalankan `cloudflared tunnel --url http://localhost:8765` di terminal kedua, salin URL HTTPS yang dihasilkan, ubah `CHRYA_ORIGIN` ke URL tersebut, kemudian restart server. Browser kedua perangkat harus membuka URL HTTPS yang **sama**. Jangan menganggap LAN HTTP sudah mendukung biometrik.

CHRYA BOX demo mengharuskan dongle flashdisk berada di **komputer server**. File `chrya_usb.key` yang digunakan untuk autentikasi browser harus tersedia pada perangkat yang login. Flashdisk biasa dapat disalin sehingga bukan pengganti kunci keamanan FIDO2.

## 3. Contoh alur dua akun

Misal akun A `naya` di laptop dan akun B `bima` di HP:

1. Keduanya membuka **server CHRYA BOX yang sama**, login ke akun sendiri.
2. Akun A membuka **Contacts → Cari username** lalu mengetik `bima`.
3. Klik **Tambah kontak**. Status menjadi **Menunggu persetujuan**.
4. Akun B membuka **Contacts → Undangan masuk** dan klik **Terima**.
5. Akun A dapat klik **Refresh**; di **Kontak terhubung**, pilih **Kirim pesan**.
6. Isi judul dan pesan, klik **Send encrypted message**.
7. Akun B membuka **Inbox**, membaca pesan, lalu klik **Balas pesan**.
8. Balasan tersimpan dan terlihat di Inbox akun A. Jika SMTP belum dikonfigurasi, pesan **tetap tersimpan** meskipun email notifikasi tidak terkirim.

Jika username tidak ditemukan, pastikan kedua akun telah **dibuat di server/database yang sama**. Dua laptop yang masing-masing menjalankan SQLite sendiri memiliki pengguna terpisah. Untuk penggunaan lintas lokasi dengan server yang selalu aktif, gunakan hosting Python dengan satu database pusat, bukan menggabungkan dua database lokal.

## 4. Batasan dan keamanan

- **Bukan chat real-time:** halaman memeriksa pembaruan secara berkala (12 detik), atau bisa di-refresh manual.
- Enkripsi saat penyimpanan terjadi di backend; **bukan end-to-end encryption** karena server memegang kunci master.
- Face Unlock kamera adalah prototipe akademik tanpa perlindungan anti-spoofing kuat. Pengujian sensor dan HTTPS pada HP harus dilakukan dengan perangkat sebenarnya.
- Jangan unggah `.env` yang berisi password SMTP atau `instance/master.key` ke hosting publik. **Jangan menyalin database SQLite ke perangkat masing-masing**, gunakan satu server.
- `CHRYA_HOST=0.0.0.0` membuka port di semua antarmuka jaringan; gunakan hanya jaringan privat tepercaya, aktifkan firewall yang sesuai. Untuk akses internet, gunakan HTTPS dan autentikasi yang sesuai.

## 5. Pengujian yang dilakukan

`python -m pytest tests/test_chrya.py -q`

28 unit/integration tests lulus, termasuk skenario dua klien terpisah: pencarian, undangan, persetujuan, pengiriman pesan terenkripsi, pembacaan dan balasan. Interaksi frontend juga diuji dengan browser Chromium terhadap backend pengujian; kamera/sensor HP fisik belum diuji.
