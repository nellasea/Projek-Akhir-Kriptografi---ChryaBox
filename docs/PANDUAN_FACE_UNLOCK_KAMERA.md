# CHRYA BOX — Face Unlock dengan Kamera Laptop (Demo)

## Yang berubah

CHRYA BOX sekarang menyediakan **Buka Kamera & Verifikasi Wajah** langsung dari halaman login. Tombol ini memakai Web API `navigator.mediaDevices.getUserMedia()` sehingga **Chrome/Edge meminta izin kamera laptop**. Video tampil langsung di CHRYA BOX; tidak mengalihkan ke Google Password Manager. Sidik jari / Windows Hello tetap tersedia dalam pilihan alternatif WebAuthn.

## Instalasi pembaruan di Windows

1. Matikan server lama (`Ctrl+C`) dan **backup** folder `instance` serta file `.env`.
2. Jika memakai PATCH: salin `app.py`, `models.py`, `face_camera.py`, folder `static`, `requirements.txt`, dan perubahan lainnya dari paket patch ke folder `CHRYA_BOX_FullStack` yang sama. **Jangan ganti/hapus folder `instance` atau file `.env` sendiri.**
3. Buka terminal VS Code di folder proyek dan jalankan:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
   ```

   Jika belum memiliki `.venv`:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
   ```

4. Buka **http://localhost:8765** (gunakan `localhost`, jangan `127.0.0.1`, agar cocok dengan `.env`).
5. Pastikan flashdisk yang sebelumnya didaftarkan sebagai dongle **tetap terpasang**. File `chrya_usb.key` tetap digunakan dan tidak dikirim ke server selama verifikasi HMAC browser.

## Pendaftaran wajah akun baru

1. Klik **Daftar**, isi identitas dan password, lalu verifikasi USB Key. **Register wajib melakukan pendaftaran wajah** sebelum akun bisa digunakan untuk login.
2. Pada langkah biometrik pilih **📷 Daftarkan Wajah lewat Kamera**.
3. Saat browser menampilkan pop-up **Izinkan penggunaan kamera**, pilih **Izinkan**.
4. Pastikan hanya **satu wajah** di dalam bingkai, hadap ke depan, dan tekan **Pindai Sekali & Daftarkan Wajah**. Tidak perlu menoleh kanan atau kiri.
5. Server mendeteksi wajah pada satu foto, lalu menyimpan **template fitur wajah yang dienkripsi AES-256-GCM** per pengguna, bukan file foto.
6. Halaman **Pendaftaran Selesai** muncul. Klik **Masuk dengan Face Unlock**; pendaftaran tidak membuat sesi login otomatis.

## Login dengan wajah yang telah terdaftar

1. Username + password -> verifikasi USB Key -> klik **📷 Buka Kamera untuk Login** (bukan tombol pendaftaran).
2. Izinkan webcam, pindai satu kali saat menghadap kamera.
3. Jika wajah sesuai dengan **template yang sudah terdaftar saat Register**, login dilanjutkan ke Dashboard. Wajah berbeda akan ditolak.
4. Jika belum menyelesaikan registrasi, aplikasi hanya menawarkan kelanjutan pendaftaran, bukan login bebas. Untuk akun lama yang hanya punya passkey, verifikasi passkey lama tetap berlaku.

## Akun lama yang sudah memakai passkey

Jika akun telah memiliki **passkey lama**, kamu **tidak** boleh mendaftarkan wajah baru hanya dengan password dan USB Key. Gunakan passkey lama untuk login, lalu buka **Security Center -> Daftarkan / Perbarui Wajah Kamera** dalam 10 menit setelah login. Ini mencegah seseorang dengan akses password dan salinan USB mengambil alih pendaftaran wajah.

## Kalau kamera tidak muncul

- Gunakan **http://localhost:8765** pada laptop yang menjalankan server (bukan `file://` dan bukan alamat LAN HTTP).
- Klik ikon kamera/gembok di kolom alamat Chrome/Edge -> **Site settings -> Camera -> Allow**.
- Windows: **Settings -> Privacy & security -> Camera**, aktifkan akses kamera untuk aplikasi desktop/browser.
- Pastikan kamera tidak sedang dikunci oleh aplikasi lain atau penutup webcam.
- Bila muncul `NotFoundError`, webcam tidak ditemukan. Bila `NotAllowedError`, akses kamera ditolak. Coba browser Edge.
- Untuk browser HP, wajib menggunakan **HTTPS** (bukan alamat IP lokal HTTP biasa).

## Keamanan dan batasan

Fitur ini adalah **prototipe akademik**. Teknologi identifikasi memanfaatkan OpenCV Haar Cascade + deskriptor LBP, dan hanya memeriksa satu foto tanpa liveness. Pendekatan ini **tidak aman menghadapi spoofing dengan foto, video, deepfake, atau replay yang disiapkan secara khusus** dan belum diuji FAR/FRR/ACER. Jangan gunakan sebagai satu-satunya kontrol keamanan aplikasi nyata.

Verifikasi wajah bukan pengganti password dan flashdisk; keduanya tetap diwajibkan. Opsi **WebAuthn / Windows Hello / fingerprint** lebih direkomendasikan untuk akun yang benar-benar memerlukan autentikasi kuat.

Frame JPEG hanya dikirim saat tombol **Pindai Sekali** ditekan, diproses di memori server, dan tidak ditulis sebagai file. Template fitur wajah yang tersimpan di tabel `user_face_templates` merupakan ciphertext AES-256-GCM dengan AAD terkait ID pengguna. Kunci berada di `instance/master.key` — **jangan dibagikan**. Karena video diproses di server, gunakan HTTPS jika dipasang pada server jaringan/internet. Hapus template melalui kebijakan penghapusan akun ketika fitur ini dikembangkan lebih lanjut.

## Pengujian

Automated backend tests mencakup alur pendaftaran/verifikasi, kewajiban password+USB, penolakan pendaftaran wajah pada akun passkey lama tanpa login penuh, dan enkripsi template. **Pengujian langsung webcam dan ketahanan anti-spoofing pada laptop pengguna belum dilakukan di lingkungan pembuat paket.**
