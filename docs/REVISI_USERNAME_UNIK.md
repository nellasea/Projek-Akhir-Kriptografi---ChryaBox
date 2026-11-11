# Revisi CHRYA BOX — Username Unik (Register)

## Hasil revisi

- Setiap **username hanya untuk satu akun** di seluruh perangkat yang menggunakan **server CHRYA BOX dan database yang sama**.
- Normalisasi username: spasi awal/akhir dihapus, huruf besar diubah menjadi huruf kecil. `Nasca.Example` dan `nasca.example` dianggap sama.
- Saat mengetik di Register, aplikasi meminta status ketersediaan ke `GET /api/auth/username-availability?username=...` pada **server**. Status tampil sebagai **tersedia**, **sudah digunakan**, atau **format salah**.
- Jika username telah digunakan, tombol untuk melanjutkan Register dinonaktifkan; jika permintaan dikirim langsung atau dua perangkat mendaftar hampir bersamaan, endpoint `POST /api/auth/register` tetap menolak dengan **HTTP 409 Conflict**.
- Email yang sudah terdaftar juga ditolak dengan pesan tersendiri.
- Tabel `users` mempertahankan **unique index** `ix_users_username` sebagai perlindungan terakhir atas pendaftaran bersamaan.
- Fitur sebelumnya (Face Unlock saat Register, verifikasi wajah saat Login, USB dongle, database, pesan, file, dan steganografi) tetap digunakan.

## Memasang PATCH (tanpa menghapus akun yang sudah ada)

1. Tutup CHRYA BOX dengan `Ctrl+C` di terminal.
2. Sebaiknya backup dahulu folder `instance` (database, `master.key`, dan konfigurasi dongle) serta `.env`.
3. Ekstrak `CHRYA_BOX_PATCH_Username_Unik.zip` dan salin file/folder `CHRYA_BOX_FullStack` ke folder proyek lama, pilih **Replace**.
4. **Jangan hapus/replace `.env` atau folder `instance`.** PATCH ini tidak menyertakannya.
5. Jalankan `\.venv\Scripts\python.exe app.py` di PowerShell.
6. Buka `http://localhost:8765` dan tekan `Ctrl+Shift+R`. Masuk menu Daftar, isi username; pesan ketersediaan akan tampil otomatis.

Jika menggunakan ZIP full, pastikan database yang dipakai memang database yang sama dengan akun sebelumnya. Paket full tidak berisi database akun lama; **jangan menggantinya tanpa backup**.

## Penting untuk login dari HP atau perangkat lain

Pemeriksaan username berlaku **lintas perangkat hanya jika semua perangkat terhubung ke satu backend dan database bersama**. Jika setiap laptop menjalankan CHRYA BOX terpisah dengan SQLite lokal berbeda, masing-masing akan mempunyai daftar akun yang berbeda. Untuk akses bersama gunakan satu host yang dapat diakses seluruh perangkat, atau server MySQL terpusat dengan kredensial yang sama. Browser menyimpan sesi, bukan daftar username.

## Pengujian

`python -m pytest -q tests/test_chrya.py`

Mencakup dua browser/klien yang memakai satu server, variasi kapital/spasi, username dan email duplikat, validasi format, serta unique index database.
