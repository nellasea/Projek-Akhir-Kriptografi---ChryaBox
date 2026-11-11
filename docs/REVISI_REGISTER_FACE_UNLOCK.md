# CHRYA BOX — Register wajah dulu, Login memakai wajah

## Alur

**Daftar:** Register akun → Verifikasi USB Key → Buka kamera → Ambil satu foto wajah → Template wajah tersimpan terenkripsi → Pendaftaran selesai → Kembali ke Login.

**Masuk:** Username/password benar → Verifikasi USB Key → Kamera wajah → Cocokkan dengan template yang didaftarkan → Dashboard bila cocok.

Jika registrasi belum tuntas, login tidak bisa memberikan sesi valid; pemilik dapat meneruskan pendaftaran. Akun lama yang menggunakan passkey dapat login memakai passkey kemudian mendaftarkan kamera di Security Center.

## Instalasi di proyek lama

1. Tutup server di VS Code dengan `Ctrl + C`.
2. Ekstrak ZIP PATCH dan salin `app.py`, folder `static/`, serta `docs/REVISI_REGISTER_FACE_UNLOCK.md` ke proyek **CHRYA_BOX_FullStack** lama. Pilih **Replace**.
3. **Jangan mengganti** `.env`, database di `instance/`, `instance/master.key`, atau file USB. PATCH tidak membawa file-file ini.
4. Install dependensi bila belum: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
5. Jalankan: `.\.venv\Scripts\python.exe app.py`, buka `http://localhost:8765`, dan hard-refresh (`Ctrl+Shift+R`).

## Pengujian

`python -m pytest -q tests/test_chrya.py` — 30 tes lulus. Pengujian wajah memakai data fitur sintetis dan tidak membuktikan kecocokan maupun ketahanan anti-spoofing pada webcam fisik.

Untuk HP, kamera browser membutuhkan HTTPS; alamat IP lokal HTTP tidak cukup. Metode webcam ini tetap prototipe kuliah, bukan pengamanan biometrik berstandar produksi.
