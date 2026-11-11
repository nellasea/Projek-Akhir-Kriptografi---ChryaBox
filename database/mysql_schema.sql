-- Reference DDL generated from SQLAlchemy models for MySQL 8+ (CHRYA BOX v2.0)
-- App will create and migrate tables automatically on configured database.

CREATE TABLE IF NOT EXISTS users (
	id INTEGER NOT NULL AUTO_INCREMENT,
	full_name VARCHAR(100) NOT NULL,
	username VARCHAR(40) NOT NULL,
	email VARCHAR(190) NOT NULL,
	password_hash VARCHAR(255) NOT NULL,
	handle VARBINARY(64) NOT NULL,
	created_at DATETIME NOT NULL,
	failure_count INTEGER NOT NULL DEFAULT 0,
	locked_until BIGINT NOT NULL DEFAULT 0,
	face_failure_count INTEGER NOT NULL DEFAULT 0,
	face_locked_until BIGINT NOT NULL DEFAULT 0,
	recovery_code_hashes TEXT,
	PRIMARY KEY (id),
	UNIQUE (handle)
);

CREATE UNIQUE INDEX ix_users_email ON users (email);
CREATE UNIQUE INDEX ix_users_username ON users (username);

CREATE TABLE IF NOT EXISTS user_face_templates (
	id INT AUTO_INCREMENT PRIMARY KEY,
	user_id INT NOT NULL UNIQUE,
	encrypted_descriptor LONGBLOB NOT NULL,
	model_version VARCHAR(40) NOT NULL DEFAULT 'sface_2021dec',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_usb_keys (
	id INT AUTO_INCREMENT PRIMARY KEY,
	user_id INT NOT NULL,
	key_id VARCHAR(64) NOT NULL UNIQUE,
	label VARCHAR(80) NOT NULL DEFAULT 'USB Vault Key',
	secret_ciphertext TEXT NOT NULL,
	digest VARCHAR(64) NOT NULL,
	volume_serial VARCHAR(64) NOT NULL DEFAULT '',
	status VARCHAR(20) NOT NULL DEFAULT 'active',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at DATETIME NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_credentials (
	id INTEGER NOT NULL AUTO_INCREMENT,
	user_id INTEGER NOT NULL,
	credential_id BLOB(255) NOT NULL,
	public_key BLOB(1024) NOT NULL,
	sign_count INTEGER NOT NULL DEFAULT 0,
	transports TEXT NOT NULL,
	name VARCHAR(80) NOT NULL DEFAULT 'Platform Passkey',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS auth_flows (
	token_hash VARCHAR(64) NOT NULL,
	user_id INTEGER NOT NULL,
	kind VARCHAR(20) NOT NULL,
	usb_challenge VARCHAR(120),
	usb_verified BOOL NOT NULL,
	web_challenge BLOB(255),
	expires BIGINT NOT NULL,
	PRIMARY KEY (token_hash),
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS sessions (
	token_hash VARCHAR(64) NOT NULL,
	user_id INTEGER NOT NULL,
	csrf VARCHAR(70) NOT NULL,
	expires BIGINT NOT NULL,
	session_id VARCHAR(36) NOT NULL DEFAULT '',
	ip_address VARCHAR(64) NOT NULL DEFAULT '',
	user_agent VARCHAR(255) NOT NULL DEFAULT '',
	device_name VARCHAR(100) NOT NULL DEFAULT 'Web Browser',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_active DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (token_hash),
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS login_history (
	id INTEGER NOT NULL AUTO_INCREMENT,
	user_id INTEGER NULL,
	username_attempted VARCHAR(80) NOT NULL DEFAULT '',
	ip_address VARCHAR(64) NOT NULL DEFAULT '',
	user_agent VARCHAR(255) NOT NULL DEFAULT '',
	device_name VARCHAR(100) NOT NULL DEFAULT '',
	method VARCHAR(60) NOT NULL DEFAULT '',
	status VARCHAR(30) NOT NULL DEFAULT 'success',
	suspicious BOOL NOT NULL DEFAULT 0,
	reason VARCHAR(190) NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS contact_requests (
	id INTEGER NOT NULL AUTO_INCREMENT,
	sender_id INTEGER NOT NULL,
	recipient_id INTEGER NOT NULL,
	status VARCHAR(20) NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(sender_id) REFERENCES users (id),
	FOREIGN KEY(recipient_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS contact_blocks (
	id INTEGER NOT NULL AUTO_INCREMENT,
	user_id INTEGER NOT NULL,
	blocked_id INTEGER NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(blocked_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS messages (
	id INTEGER NOT NULL AUTO_INCREMENT,
	sender_id INTEGER NOT NULL,
	receiver_id INTEGER NOT NULL,
	subject_ciphertext TEXT NOT NULL,
	body_ciphertext TEXT NOT NULL,
	reply_to INTEGER,
	status VARCHAR(20) NOT NULL,
	archived BOOL NOT NULL DEFAULT 0,
	pinned BOOL NOT NULL DEFAULT 0,
	sender_deleted BOOL NOT NULL DEFAULT 0,
	receiver_deleted BOOL NOT NULL DEFAULT 0,
	read_at DATETIME NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(sender_id) REFERENCES users (id),
	FOREIGN KEY(receiver_id) REFERENCES users (id),
	FOREIGN KEY(reply_to) REFERENCES messages (id)
);

CREATE TABLE IF NOT EXISTS vaults (
	id INTEGER NOT NULL AUTO_INCREMENT,
	owner_id INTEGER NOT NULL,
	title_ciphertext TEXT NOT NULL,
	body_ciphertext TEXT NOT NULL,
	category VARCHAR(40) NOT NULL DEFAULT 'Umum',
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(owner_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS files (
	id INTEGER NOT NULL AUTO_INCREMENT,
	owner_id INTEGER NOT NULL,
	receiver_id INTEGER,
	filename_ciphertext TEXT NOT NULL,
	media_type VARCHAR(150) NOT NULL,
	storage_id VARCHAR(80) NOT NULL,
	size_bytes BIGINT NOT NULL,
	category VARCHAR(40) NOT NULL DEFAULT 'Dokumen',
	share_revoked BOOL NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(owner_id) REFERENCES users (id),
	FOREIGN KEY(receiver_id) REFERENCES users (id),
	UNIQUE (storage_id)
);

CREATE TABLE IF NOT EXISTS blockchain_logs (
	id INTEGER NOT NULL AUTO_INCREMENT,
	`index` INTEGER NOT NULL,
	ts VARCHAR(50) NOT NULL,
	actor_id INTEGER NOT NULL,
	action VARCHAR(60) NOT NULL,
	resource VARCHAR(160) NOT NULL,
	previous_hash VARCHAR(64) NOT NULL,
	current_hash VARCHAR(64) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (`index`)
);

CREATE TABLE IF NOT EXISTS ledger_checkpoints (
	id INTEGER NOT NULL AUTO_INCREMENT,
	up_to_index INTEGER NOT NULL,
	block_hash VARCHAR(64) NOT NULL,
	merkle_root VARCHAR(64) NOT NULL,
	signature VARCHAR(200) NOT NULL,
	public_key VARCHAR(120) NOT NULL,
	anchor_path VARCHAR(255) NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS notifications (
	id INTEGER NOT NULL AUTO_INCREMENT,
	user_id INTEGER NOT NULL,
	message_id INTEGER,
	file_id INTEGER,
	category VARCHAR(30) NOT NULL DEFAULT 'general',
	text VARCHAR(220) NOT NULL,
	created_at DATETIME NOT NULL,
	`read` BOOL NOT NULL DEFAULT 0,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(message_id) REFERENCES messages (id),
	FOREIGN KEY(file_id) REFERENCES files (id)
);

CREATE TABLE IF NOT EXISTS email_logs (
	id INTEGER NOT NULL AUTO_INCREMENT,
	recipient VARCHAR(190) NOT NULL,
	sender_name VARCHAR(100) NOT NULL,
	sender_id INTEGER NOT NULL,
	message_id INTEGER,
	file_id INTEGER,
	status VARCHAR(30) NOT NULL,
	error VARCHAR(180) NOT NULL,
	attempts INTEGER NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(sender_id) REFERENCES users (id),
	FOREIGN KEY(message_id) REFERENCES messages (id),
	FOREIGN KEY(file_id) REFERENCES files (id)
);
