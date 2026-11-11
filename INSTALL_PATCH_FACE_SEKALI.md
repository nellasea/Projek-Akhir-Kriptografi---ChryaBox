# PATCH — Face Unlock satu kali tanpa menoleh

1. Di VS Code, hentikan CHRYA BOX dengan `Ctrl + C`.
2. Buat cadangan folder `instance/` dan file `.env` lama (jangan membagikannya).
3. Ekstrak ZIP PATCH; salin isi folder `CHRYA_BOX_FullStack/` ke folder proyek lama, pilih **Replace**.
4. PATCH ini hanya mengganti source code dan dokumentasi. **Tidak** memuat `.env`, folder `instance`, database, `master.key`, ataupun file kunci USB.
5. Jalankan ` .\\.venv\\Scripts\\python.exe app.py ` dari folder proyek dan buka `http://localhost:8765` (atau alamat pada `.env`).
6. Refresh halaman paksa (`Ctrl+Shift+R`).
7. Register: hadap kamera, klik **Pindai Sekali & Daftarkan Wajah**.
8. Login: hadap kamera, klik **Pindai Sekali & Login**.

> Perubahan ini menghilangkan pemeriksaan gerakan kepala. Sistem hanya mencocokkan **satu foto**, bukan melakukan verifikasi liveness. Foto/video dapat digunakan untuk spoofing; jangan jadikan satu-satunya faktor keamanan produksi.
