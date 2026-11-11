-- Run as MySQL administrator after replacing the placeholder secret.
-- Do NOT commit an actual production password.
CREATE DATABASE IF NOT EXISTS chrya_box CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- Example: set up user using your own administrative management tool:
-- CREATE USER 'chrya_user'@'localhost' IDENTIFIED BY 'GANTI_DENGAN_PASSWORD_ACAK_PANJANG';
-- GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON chrya_box.* TO 'chrya_user'@'localhost';
-- FLUSH PRIVILEGES;
-- After configuring CHRYA_DATABASE_URL, the app creates tables through SQLAlchemy metadata.
