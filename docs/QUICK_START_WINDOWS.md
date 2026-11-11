# CHRYA BOX — Panduan instalasi singkat

1. Buka folder ini melalui VS Code PowerShell.
2. Jalankan `py -m venv .venv`, `.venv\Scripts\activate`, lalu `python -m pip install -r requirements.txt`.
3. Colokkan flashdisk, periksa huruf drive (contohnya E:).
4. Jalankan `python tools\enroll_usb.py E:\` (satu kali untuk satu USB).
5. Jalankan `python app.py`.
6. Buka `http://localhost:8765` pada Chrome/Edge.
7. Daftar akun, pilih `E:\chrya_usb.key`, dan verifikasi Windows Hello/sidik jari/wajah jika tersedia.
8. Buat akun kedua pada profil browser lain; kirim undangan, setujui, kirim pesan.
9. Cabut flashdisk saat sudah login: API vault terkunci (HTTP 423) dan sesi dibatalkan.
10. File `.env` sudah tersedia dan mengarah ke http://localhost:8765. Opsional: edit `.env` untuk MySQL atau notifikasi SMTP. Jika sudah menggunakan `.env` sendiri, jangan ditimpa.

**Catatan:** HP membutuhkan HTTPS domain untuk WebAuthn dan dukungan file picker untuk memilih USB key. Enkripsi pada backend adalah at-rest encryption, bukan end-to-end encryption.
