"""SQLAlchemy models for CHRYA BOX.
SQLite local database by default; MySQL 8+ via CHRYA_DATABASE_URL.
Includes automatic additive schema migration for existing databases so updates never lose data.
"""
from sqlalchemy import (create_engine, ForeignKey, String, Integer, BigInteger, Text,
                        LargeBinary, Boolean, DateTime, Index, inspect, text)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    full_name: Mapped[str] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(190), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    handle: Mapped[bytes] = mapped_column(LargeBinary(64).with_variant(mysql.VARBINARY(64), 'mysql'), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[int] = mapped_column(BigInteger, default=0)
    face_failure_count: Mapped[int] = mapped_column(Integer, default=0)
    face_locked_until: Mapped[int] = mapped_column(BigInteger, default=0)
    recovery_code_hashes: Mapped[str] = mapped_column(Text, default='[]')


class Credential(Base):
    __tablename__ = 'user_credentials'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(255), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(1024), nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[str] = mapped_column(Text, default='[]')
    name: Mapped[str] = mapped_column(String(80), default='Platform Passkey')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    __table_args__ = (Index('idx_credential_user', 'user_id'),)


class FaceTemplate(Base):
    """Encrypted face embedding descriptor (SFace 128-D or compatible), never a raw camera photo."""
    __tablename__ = 'user_face_templates'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), unique=True, index=True)
    encrypted_descriptor: Mapped[bytes] = mapped_column(LargeBinary().with_variant(mysql.LONGBLOB, 'mysql'))
    model_version: Mapped[str] = mapped_column(String(40), default='sface_2021dec')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class UserUSBKey(Base):
    """Per-account USB key registration with revocation and key ID binding."""
    __tablename__ = 'user_usb_keys'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(80), default='USB Vault Key')
    secret_ciphertext: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(64), index=True)
    volume_serial: Mapped[str] = mapped_column(String(64), default='')
    status: Mapped[str] = mapped_column(String(20), default='active')  # active | revoked | lost
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Flow(Base):
    __tablename__ = 'auth_flows'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    kind: Mapped[str] = mapped_column(String(20))
    usb_challenge: Mapped[str | None] = mapped_column(String(120), nullable=True)
    usb_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    web_challenge: Mapped[bytes | None] = mapped_column(LargeBinary(255), nullable=True)
    expires: Mapped[int] = mapped_column(BigInteger)


class Session(Base):
    __tablename__ = 'sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    csrf: Mapped[str] = mapped_column(String(70))
    expires: Mapped[int] = mapped_column(BigInteger)
    session_id: Mapped[str] = mapped_column(String(36), default='', index=True)
    ip_address: Mapped[str] = mapped_column(String(64), default='')
    user_agent: Mapped[str] = mapped_column(String(255), default='')
    device_name: Mapped[str] = mapped_column(String(100), default='Web Browser')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_active: Mapped[datetime] = mapped_column(DateTime, default=now)


class LoginHistory(Base):
    __tablename__ = 'login_history'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True, index=True)
    username_attempted: Mapped[str] = mapped_column(String(80), default='')
    ip_address: Mapped[str] = mapped_column(String(64), default='')
    user_agent: Mapped[str] = mapped_column(String(255), default='')
    device_name: Mapped[str] = mapped_column(String(100), default='')
    method: Mapped[str] = mapped_column(String(60), default='')
    status: Mapped[str] = mapped_column(String(30), default='success')  # success | failed | blocked
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(190), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class ContactRequest(Base):
    __tablename__ = 'contact_requests'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    status: Mapped[str] = mapped_column(String(20), default='pending')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class ContactBlock(Base):
    __tablename__ = 'contact_blocks'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    blocked_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)


class Message(Base):
    __tablename__ = 'messages'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    receiver_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    subject_ciphertext: Mapped[str] = mapped_column(Text)
    body_ciphertext: Mapped[str] = mapped_column(Text)
    reply_to: Mapped[int | None] = mapped_column(ForeignKey('messages.id'), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default='unread')
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    sender_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    receiver_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class VaultNote(Base):
    __tablename__ = 'vaults'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    title_ciphertext: Mapped[str] = mapped_column(Text)
    body_ciphertext: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(40), default='Umum')
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class VaultFile(Base):
    __tablename__ = 'files'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    receiver_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    filename_ciphertext: Mapped[str] = mapped_column(Text)
    media_type: Mapped[str] = mapped_column(String(150))
    storage_id: Mapped[str] = mapped_column(String(80), unique=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    category: Mapped[str] = mapped_column(String(40), default='Dokumen')
    share_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Ledger(Base):
    __tablename__ = 'blockchain_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    index: Mapped[int] = mapped_column(Integer, unique=True)
    ts: Mapped[str] = mapped_column(String(50))
    actor_id: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(60))
    resource: Mapped[str] = mapped_column(String(160))
    previous_hash: Mapped[str] = mapped_column(String(64))
    current_hash: Mapped[str] = mapped_column(String(64))


class LedgerCheckpoint(Base):
    """Ed25519 digitally signed checkpoint of the SHA-256 audit hash chain."""
    __tablename__ = 'ledger_checkpoints'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    up_to_index: Mapped[int] = mapped_column(Integer, index=True)
    block_hash: Mapped[str] = mapped_column(String(64))
    merkle_root: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(200))
    public_key: Mapped[str] = mapped_column(String(120))
    anchor_path: Mapped[str] = mapped_column(String(255), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Notification(Base):
    __tablename__ = 'notifications'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    message_id: Mapped[int | None] = mapped_column(ForeignKey('messages.id'), nullable=True)
    file_id: Mapped[int | None] = mapped_column(ForeignKey('files.id'), nullable=True)
    category: Mapped[str] = mapped_column(String(30), default='general')
    text: Mapped[str] = mapped_column(String(220))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    read: Mapped[bool] = mapped_column(Boolean, default=False)


class EmailLog(Base):
    __tablename__ = 'email_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    recipient: Mapped[str] = mapped_column(String(190))
    sender_name: Mapped[str] = mapped_column(String(100))
    sender_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    message_id: Mapped[int | None] = mapped_column(ForeignKey('messages.id'), nullable=True)
    file_id: Mapped[int | None] = mapped_column(ForeignKey('files.id'), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default='pending')
    error: Mapped[str] = mapped_column(String(180), default='')
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


_MIGRATION_COLUMNS = [
    ('users', 'face_failure_count', 'INTEGER NOT NULL DEFAULT 0'),
    ('users', 'face_locked_until', 'BIGINT NOT NULL DEFAULT 0'),
    ('users', 'recovery_code_hashes', "TEXT"),
    ('user_credentials', 'name', "VARCHAR(80) NOT NULL DEFAULT 'Platform Passkey'"),
    ('user_credentials', 'created_at', 'DATETIME'),
    ('user_face_templates', 'model_version', "VARCHAR(40) NOT NULL DEFAULT 'sface_2021dec'"),
    ('sessions', 'session_id', "VARCHAR(36) NOT NULL DEFAULT ''"),
    ('sessions', 'ip_address', "VARCHAR(64) NOT NULL DEFAULT ''"),
    ('sessions', 'user_agent', "VARCHAR(255) NOT NULL DEFAULT ''"),
    ('sessions', 'device_name', "VARCHAR(100) NOT NULL DEFAULT 'Web Browser'"),
    ('sessions', 'created_at', 'DATETIME'),
    ('sessions', 'last_active', 'DATETIME'),
    ('messages', 'pinned', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('messages', 'sender_deleted', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('messages', 'receiver_deleted', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('messages', 'read_at', 'DATETIME'),
    ('vaults', 'category', "VARCHAR(40) NOT NULL DEFAULT 'Umum'"),
    ('vaults', 'updated_at', 'DATETIME'),
    ('files', 'category', "VARCHAR(40) NOT NULL DEFAULT 'Dokumen'"),
    ('files', 'share_revoked', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('notifications', 'file_id', 'INTEGER'),
    ('notifications', 'category', "VARCHAR(30) NOT NULL DEFAULT 'general'"),
]


def ensure_schema_migrations(engine):
    """Safely add any missing columns to existing SQLite/MySQL tables without losing data."""
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table_name, col_name, col_ddl in _MIGRATION_COLUMNS:
            if table_name not in existing_tables:
                continue
            cols = {c['name'] for c in insp.get_columns(table_name)}
            if col_name not in cols:
                conn.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {col_name} {col_ddl}'))


def make_session_factory(url):
    if url.startswith('sqlite:'):
        engine = create_engine(url, connect_args={'check_same_thread': False}, pool_pre_ping=True)
    else:
        engine = create_engine(url, pool_pre_ping=True, pool_recycle=1800)
    ensure_schema_migrations(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)
