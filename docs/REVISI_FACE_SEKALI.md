# Revisi: Face Unlock satu kali pemindaian (9 November 2026)

- **Register**: isi data akun → verifikasi flashdisk USB → izin kamera → hadapkan wajah ke depan → tekan **Pindai Sekali & Daftarkan Wajah** → selesai, kembali ke Login.
- **Login**: password → USB Key → izin kamera → hadapkan wajah ke depan → tekan **Pindai Sekali & Login** → server mencocokkan fitur wajah dengan template akun.
- **Security Center**: pendaftaran ulang wajah juga menggunakan satu pemindaian.
- Server menolak permintaan berisi 0 maupun lebih dari 1 foto. Tidak ada instruksi menoleh kanan/kiri.
- Data wajah yang disimpan berupa deskriptor LBP terenkripsi AES-GCM; foto JPEG diproses dalam memori dan tidak disimpan sebagai file.
- **Batasan keamanan**: metode satu foto tidak mendeteksi liveness dan mudah diserang dengan foto/video. Password dan USB Key tetap diwajibkan; jangan gunakan metode ini sebagai satu-satunya kontrol keamanan produksi.
- PATCH hanya mengganti `app.py`, `face_camera.py`, `static/app.js`, `static/index.html`, `static/style.css` serta dokumentasi ini. Jangan menimpa `.env` atau folder `instance` pada instalasi lama.
