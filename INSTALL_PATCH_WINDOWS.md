# Instalasi PATCH kamera CHRYA BOX di Windows

**JANGAN hapus folder `instance`, database, flashdisk USB Key atau file `.env` lama.** Sebelum mengubah proyek, buat salinan cadangan `instance` dan `.env`.

1. Matikan aplikasi lama dengan Ctrl+C.
2. Ekstrak `CHRYA_BOX_PATCH_Kamera_Face_Unlock.zip`, lalu buka folder `CHRYA_BOX_FullStack` di dalam hasil ekstrak.
3. Salin seluruh isi folder tersebut ke **folder CHRYA_BOX_FullStack milikmu yang sudah terpasang**, dan pilih **Replace** bila diminta. PATCH ini **tidak** membawa file `.env` maupun folder `instance`, sehingga tidak akan menimpa konfigurasi/database yang sebelumnya kamu gunakan.
4. Di terminal PowerShell VS Code, jalankan:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
   ```

   Kalau `.venv` belum ada, jalankan `py -m venv .venv` terlebih dahulu.
5. Buka **http://localhost:8765**, dan setelah login password + USB Key, klik **Buka Kamera & Verifikasi Wajah**.

**Khusus akun lama yang sudah punya passkey:** login dengan metode WebAuthn lama, lalu buka **Security Center -> Daftarkan / Perbarui Wajah Kamera**. Ini mencegah pendaftaran wajah tanpa verifikasi akun lama.

Lihat `docs/PANDUAN_FACE_UNLOCK_KAMERA.md` untuk instruksi lengkap dan keterbatasan biometrik kamera.
