# CHRYA BOX — Revisi Login Face Unlock / Sidik Jari

## Perubahan tampilan

Pada tab **Masuk**, di bawah input username/email dan password tersedia tombol **Daftarkan Face Unlock / Sidik Jari**.

1. Isikan username/email dan password **akun CHRYA BOX yang sudah terdaftar**.
2. Klik **Daftarkan Face Unlock / Sidik Jari**.
3. Pasang flashdisk CHRYA BOX, pilih file `chrya_usb.key` dan lakukan verifikasi USB.
4. Jika akun belum memiliki passkey, lanjutkan ke pendaftaran autentikator WebAuthn pada perangkat (Windows Hello, Face ID/Touch ID, sidik jari Android, atau PIN perangkat, bergantung pada OS).
5. Jika akun sudah memiliki passkey, gunakan passkey lama untuk login. Untuk menambahkan perangkat lain, buka **Security Center → Tambah perangkat biometrik** dalam 10 menit setelah login.

**Tidak ada cara langsung mendaftarkan perangkat baru pada akun yang sudah mempunyai passkey tanpa memverifikasi passkey lama**, sehingga pendaftaran baru tidak mengurangi keamanan akses.

## Cara memperbarui proyek yang sudah berjalan

1. **Jangan hapus** `.env`, direktori `instance/`, database akun, atau file kunci flashdisk lama.
2. Matikan server (`Ctrl+C`).
3. Salin `app.py` dan folder `static/` dari ZIP patch ini ke folder `CHRYA_BOX_FullStack` lama, setujui Replace.
4. Pastikan `requirements.txt` sudah diinstal: `.venv\Scripts\python.exe -m pip install -r requirements.txt`.
5. Jalankan `.venv\Scripts\python.exe app.py` dan buka `http://localhost:8765` sesuai `.env`.
6. Tekan `Ctrl + Shift + R` (hard reload), lalu klik **Masuk**.

## Persyaratan perangkat

- WebAuthn harus dijalankan pada **origin yang cocok** dengan `.env` (contohnya `CHRYA_ORIGIN=http://localhost:8765`). Jangan menggunakan `127.0.0.1` bila origin diatur ke `localhost`.
- Saat dibuka dari HP gunakan HTTPS publik atau jaringan HTTPS tepercaya; alamat IP lokal HTTP tidak memenuhi syarat secure context.
- Windows Hello perlu diaktifkan melalui **Settings → Accounts → Sign-in options**. Jika laptop tidak punya sensor wajah/sidik jari, Windows Hello dapat menawarkan PIN. Pilihan metode biometrik ditentukan oleh browser/sistem operasi, bukan dipaksakan oleh website.
- CHRYA BOX tidak menyimpan citra wajah maupun pola sidik jari.
- USB flashdisk adalah token file yang bisa disalin, **bukan** autentikator FIDO2 yang tahan kloning.

## Status pengujian

- 18 pengujian otomatis: lulus pada runtime pengembangan.
- Screenshot desktop/mobile: dibuat dari antarmuka aktual HTML/CSS/JavaScript, tanpa perangkat sensor fisik.
- Uji Face ID/Windows Hello/fingerprint secara fisik masih harus dilakukan di laptop/HP yang memiliki autentikator WebAuthn, dengan browser dan origin yang sesuai.
