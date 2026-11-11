-- Untuk database MySQL yang sudah ada; tidak menghapus akun maupun pesan lama.
CREATE TABLE IF NOT EXISTS user_face_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    encrypted_descriptor LONGBLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
