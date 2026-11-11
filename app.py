"""CHRYA BOX / Private Messaging and Digital Secret Vault.

Development run: python app.py
For biometric on mobile: HTTPS origin required. Standard USB flashdisk is a coursework
possession-token prototype, not non-exportable FIDO2 hardware.
Server-side encryption-at-rest with domain-separated HKDF subkeys: NOT end-to-end encryption
(server holds master keyring; see docs/SSE_VS_E2EE.md).
"""
from __future__ import annotations
import os, json, time, hmac, secrets, hashlib, base64, smtplib, mimetypes, re, logging, shutil
from datetime import datetime, timezone
from pathlib import Path
from email.message import EmailMessage
from urllib.parse import urlparse, quote
from ipaddress import ip_address
from typing import Any
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, or_, and_, func, desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError
from models import (User, Credential, FaceTemplate, UserUSBKey, Flow, Session as UserSession,
                    LoginHistory, ContactRequest, ContactBlock, Message, VaultNote, VaultFile,
                    Ledger, LedgerCheckpoint, Notification, EmailLog, now, make_session_factory,
                    ensure_schema_migrations)
from crypto_engine import (encrypt_text, decrypt_text, encrypt_file, decrypt_file,
                           lsb_embed, lsb_extract, make_hash, b64, ub64,
                           KeyRing, export_master_key_backup, restore_master_key_backup,
                           compute_merkle_root, sign_ledger_checkpoint, verify_ledger_checkpoint)
from usb_dongle import USBGuard, sha256 as usb_sha256, get_volume_serial
from face_camera import (FaceError, check_frames, distance as face_distance,
                         encrypt_template, decrypt_template, MAX_MATCH_DISTANCE)

ROOT = Path(__file__).resolve().parent
INSTANCE = Path(os.environ.get('CHRYA_INSTANCE', str(ROOT / 'instance'))).resolve()
INSTANCE.mkdir(parents=True, exist_ok=True)
(STORAGE := INSTANCE / 'storage').mkdir(exist_ok=True)
(BACKUPS_DIR := INSTANCE / 'backups').mkdir(exist_ok=True)
(ANCHORS_DIR := INSTANCE / 'anchors').mkdir(exist_ok=True)
(LOGS_DIR := INSTANCE / 'logs').mkdir(exist_ok=True)

# Configure structured file + console error logging (K.9)
logger = logging.getLogger('chrya_box')
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(LOGS_DIR / 'chrya_error.log', encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)


def load_simple_env():
    env = ROOT / '.env'
    if not env.is_file():
        return
    for raw in env.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        if k.strip() and k.strip() not in os.environ:
            os.environ[k.strip()] = v.strip().strip('"').strip("'")


load_simple_env()
ORIGIN = os.getenv('CHRYA_ORIGIN', 'http://localhost:8765').rstrip('/')
RP_ID = urlparse(ORIGIN).hostname
if not RP_ID or urlparse(ORIGIN).scheme not in {'http', 'https'}:
    raise RuntimeError('CHRYA_ORIGIN harus URL sah')
if urlparse(ORIGIN).scheme == 'http' and RP_ID not in ('localhost', '127.0.0.1'):
    print('WARNING: Platform WebAuthn pada HP membutuhkan HTTPS, bukan alamat LAN HTTP.')
DB_URL = os.getenv('CHRYA_DATABASE_URL', 'sqlite:///' + str(INSTANCE / 'chrya.sqlite3'))
engine, SessionLocal = make_session_factory(DB_URL)
FACE_FAILURES: dict[str, tuple[int, float]] = {}  # Flow-scoped attempt counts in addition to persistent User DB counts
PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=32768, parallelism=2, hash_len=32, type=Type.ID)


def master_key() -> bytes:
    configured = os.getenv('CHRYA_MASTER_KEY_B64')
    if configured:
        try:
            value = ub64(configured)
        except Exception as e:
            raise RuntimeError('CHRYA_MASTER_KEY_B64 tidak valid') from e
    else:
        keyfile = INSTANCE / 'master.key'
        if not keyfile.is_file():
            try:
                fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(secrets.token_bytes(32))
            except FileExistsError:
                pass
        value = keyfile.read_bytes()
    if len(value) != 32:
        raise RuntimeError('Master key harus 32 byte')
    return value


MASTER = master_key()
KEYRING = KeyRing(INSTANCE, MASTER)
GUARD = USBGuard(INSTANCE)
app = FastAPI(title='CHRYA BOX', version='2.0', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=str(ROOT / 'static')), name='static')


class Failure(Exception):
    def __init__(self, reason: str, code: int = 400):
        self.reason = reason
        self.code = code


@app.exception_handler(Failure)
async def error_handler(request: Request, exc: Failure):
    if exc.code >= 400:
        logger.warning('API Failure %s %s -> %s: %s', request.method, request.url.path, exc.code, exc.reason)
    return JSONResponse({'ok': False, 'error': exc.reason}, status_code=exc.code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception('Unhandled exception on %s %s: %s', request.method, request.url.path, exc)
    return JSONResponse({'ok': False, 'error': 'Terjadi kesalahan internal pada server.'}, status_code=500)


def allowed_browser_origin(request: Request, origin: str) -> bool:
    """Only accept explicit configured origins or same-host private LAN (opt-in)."""
    if origin == ORIGIN:
        return True
    extras = {x.strip().rstrip('/') for x in os.getenv('CHRYA_ALLOWED_ORIGINS', '').split(',') if x.strip()}
    if origin in extras:
        return True
    if os.getenv('CHRYA_ALLOW_PRIVATE_LAN', 'false').strip().lower() != 'true':
        return False
    try:
        parsed = urlparse(origin)
        advertised = urlparse(str(request.base_url).rstrip('/'))
        ip = ip_address(parsed.hostname or '')
        return (parsed.scheme in ('http', 'https')
                and (ip.is_private or ip.is_loopback)
                and parsed.username is None and parsed.password is None
                and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
                and parsed.scheme == advertised.scheme
                and parsed.netloc.lower() == advertised.netloc.lower())
    except (ValueError, TypeError):
        return False


@app.middleware('http')
async def secure_gateway(request: Request, call_next):
    path = request.url.path
    if path.startswith('/api/') and path != '/api/status':
        if GUARD.key() is None:
            with SessionLocal.begin() as db:
                db.query(UserSession).delete(synchronize_session=False)
            return JSONResponse({'ok': False, 'locked': True, 'error': 'USB Vault Key dicabut / tidak terdaftar. Aplikasi terkunci.'}, status_code=423)
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            origin = request.headers.get('origin')
            referer = request.headers.get('referer')
            if origin:
                if not allowed_browser_origin(request, origin.rstrip('/')):
                    logger.warning('Rejected Origin header: %s', origin)
                    return JSONResponse({'ok': False, 'error': 'Origin tidak diizinkan.'}, status_code=403)
            elif referer:
                parsed_ref = urlparse(referer)
                ref_origin = f'{parsed_ref.scheme}://{parsed_ref.netloc}'.rstrip('/')
                if not allowed_browser_origin(request, ref_origin):
                    logger.warning('Rejected Referer header: %s', referer)
                    return JSONResponse({'ok': False, 'error': 'Referer Origin tidak diizinkan.'}, status_code=403)
            try:
                size = int(request.headers.get('content-length', '0'))
                if size > 9 * 1024 * 1024:
                    return JSONResponse({'ok': False, 'error': 'Permintaan terlalu besar.'}, status_code=413)
            except ValueError:
                return JSONResponse({'ok': False, 'error': 'Content-Length salah.'}, status_code=400)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Permissions-Policy'] = 'camera=(self), microphone=()'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self' blob: data:; "
        "object-src 'self' blob: data:; base-uri 'none'; frame-ancestors 'self'"
    )
    return response


def digest(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def timestamp(dt) -> str:
    return dt.isoformat(timespec='minutes') + 'Z' if dt else ''


def utc_iso_seconds() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='seconds') + 'Z'


def me_public(u: User) -> dict:
    return {'id': u.id, 'username': u.username, 'email': u.email, 'full_name': u.full_name}


def contact_public(u: User) -> dict:
    return {'id': u.id, 'username': u.username, 'full_name': u.full_name}


def b64decode_credential(value: str) -> bytes:
    return ub64(value)


def client_meta(request: Request) -> tuple[str, str, str]:
    ip = (request.headers.get('x-forwarded-for') or (request.client.host if request.client else '127.0.0.1')).split(',')[0].strip()[:64]
    ua = (request.headers.get('user-agent') or 'Unknown Browser')[:250]
    device = 'Desktop Browser'
    ua_l = ua.lower()
    if 'iphone' in ua_l or 'ipad' in ua_l:
        device = 'iOS Safari/Mobile'
    elif 'android' in ua_l:
        device = 'Android Browser'
    elif 'edg/' in ua_l:
        device = 'Microsoft Edge (Windows)' if 'windows' in ua_l else 'Microsoft Edge'
    elif 'chrome/' in ua_l:
        device = 'Google Chrome (Windows)' if 'windows' in ua_l else 'Google Chrome'
    elif 'firefox/' in ua_l:
        device = 'Mozilla Firefox'
    elif 'testclient' in ua_l or 'python' in ua_l:
        device = 'Automated Client'
    return ip, ua, device


def record_login_event(db: DBSession, request: Request, *, user_id: int | None, username: str,
                       method: str, status: str, reason: str = '') -> bool:
    """Record login attempt in LoginHistory and detect suspicious anomalies."""
    ip, ua, device = client_meta(request)
    suspicious = False
    if user_id is not None:
        if status == 'failed':
            u = db.get(User, user_id)
            if u and (u.failure_count >= 3 or u.face_failure_count >= 3):
                suspicious = True
        elif status == 'success':
            prev_ips = set(db.scalars(select(LoginHistory.ip_address).where(
                LoginHistory.user_id == user_id, LoginHistory.status == 'success'
            ).limit(20)).all())
            if prev_ips and ip not in prev_ips:
                suspicious = True
                reason = reason or f'Login dari alamat IP baru ({ip})'
                notify(db, user_id, None, f'Peringatan Keamanan: Login terdeteksi dari IP/perangkat baru ({device}, {ip})', category='security')
    db.add(LoginHistory(
        user_id=user_id,
        username_attempted=username[:80],
        ip_address=ip,
        user_agent=ua,
        device_name=device,
        method=method[:60],
        status=status[:30],
        suspicious=suspicious,
        reason=reason[:190],
    ))
    return suspicious


def encrypt_domain_text(text: str, context: str) -> str:
    kid, active = KEYRING.active_key()
    return encrypt_text(text, active, context=context, key_id=kid)


def decrypt_domain_text(envelope: str, context: str) -> str:
    return decrypt_text(envelope, MASTER, context=context, keyring=KEYRING)


def encrypt_domain_file(raw: bytes) -> bytes:
    kid, active = KEYRING.active_key()
    return encrypt_file(raw, active, key_id=kid)


def decrypt_domain_file(blob: bytes) -> bytes:
    return decrypt_file(blob, MASTER, keyring=KEYRING)


def get_flow(db: DBSession, token: Any, consume: bool = False) -> Flow:
    if not isinstance(token, str) or len(token) > 250 or not token:
        raise Failure('Sesi keamanan tidak valid.', 401)
    row = db.get(Flow, digest(token))
    if not row or row.expires < int(time.time()):
        raise Failure('Tantangan kedaluwarsa. Ulangi proses.', 401)
    if consume:
        db.delete(row)
        db.flush()
    return row


def active_user(request: Request, db: DBSession, csrf: bool = False) -> User | None:
    token = request.cookies.get('chrya_sid', '')
    if len(token) < 25:
        return None
    session = db.get(UserSession, digest(token))
    if not session or session.expires <= int(time.time()):
        return None
    if csrf and not hmac.compare_digest(str(request.headers.get('x-csrf-token', '')), session.csrf):
        raise Failure('CSRF token tidak sesuai. Muat ulang halaman.', 403)
    session.last_active = now()
    return db.get(User, session.user_id)


def require_user(request: Request, db: DBSession, csrf: bool = False) -> User:
    user = active_user(request, db, csrf)
    if not user:
        raise Failure('Masuk dengan password, USB Key, dan biometrik terlebih dahulu.', 401)
    return user


def usb_key() -> bytes:
    key = GUARD.key()
    if key is None:
        raise Failure('USB Key dicabut.', 423)
    return key


def user_usb_secrets(db: DBSession, user_id: int) -> list[bytes]:
    """Return valid 32-byte USB keys for a user: active per-user USB keys + host dongle if no personal key forces replacement."""
    rows = db.scalars(select(UserUSBKey).where(UserUSBKey.user_id == user_id)).all()
    active_secrets: list[bytes] = []
    for r in rows:
        if r.status == 'active' and not GUARD.is_digest_revoked(r.digest):
            try:
                raw_b64 = decrypt_domain_text(r.secret_ciphertext, 'USB_SECRET')
                active_secrets.append(ub64(raw_b64))
            except Exception:
                pass
    # Also accept the host USB key unless it was explicitly revoked for this user
    host_k = usb_key()
    host_digest = usb_sha256(host_k)
    revoked_for_user = {r.digest for r in rows if r.status in ('revoked', 'lost')}
    if host_digest not in revoked_for_user and not GUARD.is_digest_revoked(host_digest):
        active_secrets.append(host_k)
    return active_secrets


def accepted_contact(db: DBSession, a: int, b: int) -> bool:
    if a == b:
        return False
    if db.scalar(select(ContactBlock.id).where(
        or_(and_(ContactBlock.user_id == a, ContactBlock.blocked_id == b),
            and_(ContactBlock.user_id == b, ContactBlock.blocked_id == a))
    ).limit(1)):
        return False
    return bool(db.scalar(select(ContactRequest.id).where(
        ContactRequest.status == 'accepted',
        or_(and_(ContactRequest.sender_id == a, ContactRequest.recipient_id == b),
            and_(ContactRequest.sender_id == b, ContactRequest.recipient_id == a))
    ).limit(1)))


def ledger_append(db: DBSession, actor: int, action: str, resource: str) -> Ledger:
    prev = db.scalar(select(Ledger).order_by(Ledger.index.desc()).limit(1))
    index = prev.index + 1 if prev else 0
    previous = prev.current_hash if prev else '0' * 64
    ts = utc_iso_seconds()
    h = make_hash(index, ts, actor, action, resource, previous)
    entry = Ledger(index=index, ts=ts, actor_id=actor, action=action, resource=resource, previous_hash=previous, current_hash=h)
    db.add(entry)
    return entry


def ledger_verify_detailed(db: DBSession) -> dict:
    chain = db.scalars(select(Ledger).order_by(Ledger.index)).all()
    prev = '0' * 64
    tampered_index = None
    reason = ''
    all_hashes: list[str] = []
    for i, b in enumerate(chain):
        expected = make_hash(b.index, b.ts, b.actor_id, b.action, b.resource, b.previous_hash)
        if b.index != i:
            tampered_index = b.index
            reason = f'Urutan blok #{b.index} tidak berurutan (seharusnya #{i}).'
            break
        if b.previous_hash != prev:
            tampered_index = b.index
            reason = f'Previous hash pada blok #{b.index} tidak cocok dengan blok sebelumnya.'
            break
        if b.current_hash != expected:
            tampered_index = b.index
            reason = f'Hash blok #{b.index} tidak cocok dengan isi data (terdeteksi modifikasi data).'
            break
        prev = b.current_hash
        all_hashes.append(b.current_hash)

    checkpoints = db.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.id.desc()).limit(10)).all()
    cp_list = []
    checkpoints_valid = True
    for cp in checkpoints:
        sig_ok = verify_ledger_checkpoint(cp.up_to_index, cp.block_hash, cp.merkle_root, cp.signature, cp.public_key)
        chain_match = True
        if cp.up_to_index < len(chain):
            sub_hashes = [x.current_hash for x in chain[:cp.up_to_index + 1]]
            if chain[cp.up_to_index].current_hash != cp.block_hash or compute_merkle_root(sub_hashes) != cp.merkle_root:
                chain_match = False
        else:
            chain_match = False
        valid_cp = sig_ok and chain_match and (tampered_index is None or tampered_index > cp.up_to_index)
        if not valid_cp:
            checkpoints_valid = False
        cp_list.append({
            'id': cp.id,
            'up_to_index': cp.up_to_index,
            'block_hash': cp.block_hash,
            'merkle_root': cp.merkle_root,
            'signature': cp.signature,
            'public_key': cp.public_key,
            'anchor_path': cp.anchor_path,
            'valid': valid_cp,
            'created_at': timestamp(cp.created_at),
        })

    is_valid = (tampered_index is None) and checkpoints_valid
    return {
        'valid': is_valid,
        'tampered_index': tampered_index,
        'reason': reason or ('Integritas seluruh blok dan signature terverifikasi.' if is_valid else 'Checkpoint tidak cocok dengan rantai blok.'),
        'merkle_root': compute_merkle_root(all_hashes),
        'head_hash': prev,
        'total': len(chain),
        'checkpoints': cp_list,
    }


def ledger_verify(db: DBSession) -> bool:
    return ledger_verify_detailed(db)['valid']


def notify(db: DBSession, recipient_id: int, message_id: int | None, text: str,
           *, file_id: int | None = None, category: str = 'general'):
    if category == 'general':
        if message_id is not None or 'pesan' in text.lower():
            category = 'message'
        elif file_id is not None or 'file' in text.lower():
            category = 'file'
        elif 'undangan' in text.lower() or 'kontak' in text.lower():
            category = 'contact'
    db.add(Notification(user_id=recipient_id, message_id=message_id, file_id=file_id, category=category, text=text[:220]))


def send_email_job(logid: int):
    with SessionLocal.begin() as db:
        entry = db.get(EmailLog, logid)
        if not entry:
            return
        host = os.getenv('SMTP_HOST', '').strip()
        sender = os.getenv('SMTP_FROM', '').strip()
        username = os.getenv('SMTP_USER', '').strip()
        password = os.getenv('SMTP_PASSWORD', '').strip()
        if not all((host, sender, username, password)):
            entry.status = 'not_configured'
            entry.error = 'Konfigurasi SMTP belum diisi'
            return
        entry.attempts += 1
        target = entry.recipient
        msg = EmailMessage()
        msg['From'] = sender
        msg['To'] = target
        kind_label = 'file terenkripsi' if entry.file_id else 'pesan terenkripsi'
        msg['Subject'] = f'CHRYA BOX - Notifikasi {kind_label} baru'
        msg.set_content(
            f'Halo,\n\nAda {kind_label} baru di CHRYA BOX dari {entry.sender_name}.\n\n'
            f'Untuk menjaga kerahasiaan, isi pesan/file tidak ditampilkan melalui email.\n'
            f'Silakan masuk ke {ORIGIN}/ untuk membukanya.\n\nCHRYA BOX'
        )
        try:
            port = int(os.getenv('SMTP_PORT', '587'))
            with smtplib.SMTP(host, port, timeout=9) as smtp:
                if os.getenv('SMTP_STARTTLS', 'true').lower() == 'true':
                    smtp.starttls()
                smtp.login(username, password)
                smtp.send_message(msg)
            entry.status = 'sent'
            entry.error = ''
        except Exception as exc:
            entry.status = 'failed'
            entry.error = f'{type(exc).__name__}: {str(exc)}'[:180]
            logger.error('SMTP send failed for log %s: %s', logid, exc)


@app.get('/', response_class=HTMLResponse)
def home():
    return (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')


@app.get('/api/status')
def status():
    return {'ok': True, **GUARD.status(), 'server': 'CHRYA BOX v2.0', 'origin': ORIGIN, 'key_version': KEYRING.current_kid}


@app.get('/api/me')
def me(request: Request):
    with SessionLocal.begin() as db:
        user = active_user(request, db)
        if not user:
            return {'ok': True, 'authenticated': False}
        sess = db.get(UserSession, digest(request.cookies.get('chrya_sid', '')))
        count = db.scalar(select(func.count()).select_from(Credential).where(Credential.user_id == user.id))
        face_row = valid_face_template(db, user.id)
        usb_count = db.scalar(select(func.count()).select_from(UserUSBKey).where(UserUSBKey.user_id == user.id, UserUSBKey.status == 'active'))
        recovery_codes = json.loads(user.recovery_code_hashes or '[]')
        return {
            'ok': True,
            'authenticated': True,
            'user': me_public(user),
            'csrf': sess.csrf,
            'passkeys': count,
            'face_enrolled': bool(face_row),
            'face_model': face_row.model_version if face_row else None,
            'usb_keys_count': usb_count,
            'recovery_codes_remaining': len(recovery_codes),
        }


def canonical_username(value) -> str:
    return str(value or '').strip().lower()


def username_is_taken(db: DBSession, username: str) -> bool:
    return bool(db.scalar(select(User.id).where(func.lower(User.username) == username).limit(1)))


@app.get('/api/auth/username-availability')
def username_availability(username: str = ''):
    canonical = canonical_username(username)
    if not re.fullmatch(r'[a-z0-9_.]{3,32}', canonical):
        return {
            'ok': True,
            'available': False,
            'username': canonical,
            'message': 'Gunakan 3–32 karakter: huruf, angka, titik, atau underscore.',
        }
    with SessionLocal() as db:
        taken = username_is_taken(db, canonical)
    return {
        'ok': True,
        'available': not taken,
        'username': canonical,
        'message': ('Username sudah terdaftar. Gunakan username lain.' if taken
                    else 'Username tersedia dan bisa digunakan.'),
    }


@app.post('/api/auth/register')
async def register(request: Request):
    p = await request.json()
    username = canonical_username(p.get('username'))
    email = str(p.get('email', '')).strip().lower()
    name = str(p.get('full_name', '')).strip()
    pw = p.get('password', '')
    if not re.fullmatch(r'[a-z0-9_.]{3,32}', username):
        raise Failure('Username harus 3–32 karakter huruf, angka, titik, atau underscore.')
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) or len(email) > 190:
        raise Failure('Masukkan alamat email yang valid.')
    if not 2 <= len(name) <= 100:
        raise Failure('Nama harus 2-100 karakter.')
    if not isinstance(pw, str) or len(pw) < 12 or len(pw) > 256:
        raise Failure('Password minimal 12 karakter (maksimal 256).')
    try:
        with SessionLocal.begin() as db:
            if username_is_taken(db, username):
                raise Failure('Username sudah terdaftar. Silakan ganti username.', 409)
            if db.scalar(select(User.id).where(func.lower(User.email) == email).limit(1)):
                raise Failure('Email sudah digunakan. Gunakan email lain.', 409)
            user = User(
                username=username,
                email=email,
                full_name=name,
                password_hash=PASSWORD_HASHER.hash(pw),
                handle=secrets.token_bytes(32),
            )
            db.add(user)
            db.flush()
            token = secrets.token_urlsafe(32)
            db.add(Flow(token_hash=digest(token), user_id=user.id, kind='register', expires=int(time.time()) + 600))
            ledger_append(db, user.id, 'REGISTER', f'account:{user.id}')
    except IntegrityError as exc:
        with SessionLocal() as check_db:
            if username_is_taken(check_db, username):
                raise Failure('Username sudah terdaftar. Silakan ganti username.', 409) from exc
            if check_db.scalar(select(User.id).where(func.lower(User.email) == email).limit(1)):
                raise Failure('Email sudah digunakan. Gunakan email lain.', 409) from exc
        raise Failure('Akun sudah digunakan. Pilih username dan email lain.', 409) from exc
    return {
        'ok': True,
        'flow': token,
        'stage': 'usb',
        'registration_required': True,
        'message': 'Akun dibuat. Verifikasi USB Key lalu daftarkan wajah melalui kamera untuk menyelesaikan pendaftaran.',
    }


@app.post('/api/auth/start')
async def login_start(request: Request):
    p = await request.json()
    identity = str(p.get('identity', '')).strip().lower()
    password = p.get('password', '')
    with SessionLocal() as db:
        user = db.scalar(select(User).where(or_(User.username == identity, User.email == identity)))
        if not user:
            try:
                PASSWORD_HASHER.verify(PASSWORD_HASHER.hash('password-dummy'), str(password))
            except Exception:
                pass
            record_login_event(db, request, user_id=None, username=identity, method='password', status='failed', reason='Akun tidak ditemukan')
            db.commit()
            raise Failure('Username/email atau password salah.', 401)
        now_ts = int(time.time())
        if user.locked_until > now_ts:
            record_login_event(db, request, user_id=user.id, username=user.username, method='password', status='blocked', reason='Akun terkunci sementara')
            db.commit()
            raise Failure('Terlalu banyak percobaan. Coba lagi dalam 5 menit.', 429)
        if user.face_locked_until > now_ts:
            raise Failure('Face Unlock dikunci sementara karena percobaan gagal berulang. Coba lagi nanti.', 429)
        try:
            PASSWORD_HASHER.verify(user.password_hash, str(password))
        except (VerifyMismatchError, VerificationError):
            user.failure_count += 1
            if user.failure_count >= 5:
                user.locked_until = now_ts + 300
                user.failure_count = 0
                notify(db, user.id, None, 'Peringatan Keamanan: Akun dikunci 5 menit karena 5x gagal login password.', category='security')
            record_login_event(db, request, user_id=user.id, username=user.username, method='password', status='failed', reason='Password salah')
            db.commit()
            raise Failure('Username/email atau password salah.', 401)
        user.failure_count = 0
        user.locked_until = 0
        has_passkey = bool(db.scalar(select(Credential.id).where(Credential.user_id == user.id).limit(1)))
        has_face = bool(valid_face_template(db, user.id))
        is_setup = not (has_passkey or has_face)
        token = secrets.token_urlsafe(32)
        db.add(Flow(token_hash=digest(token), user_id=user.id, kind='register' if is_setup else 'login', expires=now_ts + 600))
        db.commit()
    return {
        'ok': True,
        'flow': token,
        'stage': 'usb',
        'setup': is_setup,
        'face_enrolled': has_face,
        'passkey_enrolled': has_passkey,
        'biometric_action': 'register' if is_setup else 'verify',
        'message': 'Pendaftaran wajah belum selesai. Lanjutkan pendaftaran sebelum login.' if is_setup else 'Verifikasi wajah terdaftar untuk masuk.',
    }


@app.post('/api/auth/usb/challenge')
async def usb_challenge(request: Request):
    p = await request.json()
    with SessionLocal.begin() as db:
        flow = get_flow(db, p.get('flow'))
        nonce = secrets.token_bytes(32)
        flow.usb_challenge = b64(nonce)
        flow.usb_verified = False
        return {'ok': True, 'challenge': b64(nonce), 'filename': 'chrya_usb.key'}


@app.post('/api/auth/usb/verify')
async def usb_verify(request: Request):
    p = await request.json()
    with SessionLocal.begin() as db:
        flow = get_flow(db, p.get('flow'))
        if not flow.usb_challenge:
            raise Failure('Minta challenge USB dahulu.')
        challenge_bytes = ub64(flow.usb_challenge)
        response_hex = str(p.get('response', '')).strip().lower()
        candidates = user_usb_secrets(db, flow.user_id)
        matched = False
        for secret_key in candidates:
            expected = hmac.new(secret_key, challenge_bytes, hashlib.sha256).hexdigest()
            if hmac.compare_digest(response_hex, expected):
                matched = True
                break
        if not matched:
            u = db.get(User, flow.user_id)
            record_login_event(db, request, user_id=flow.user_id, username=u.username if u else '', method='usb_hmac', status='failed', reason='USB Key tidak sesuai atau sudah dicabut')
            raise Failure('USB Key tidak sesuai, sudah dicabut, atau response HMAC salah.', 401)
        flow.usb_verified = True
        flow.usb_challenge = None
        return {'ok': True, 'stage': 'webauthn'}


def webauthn_module():
    try:
        import webauthn
        from webauthn.helpers import structs
        return webauthn, structs
    except ImportError:
        raise Failure('Pustaka WebAuthn belum diinstal. Jalankan pip install -r requirements.txt.', 503)


@app.post('/api/auth/webauthn/options')
async def passkey_options(request: Request):
    p = await request.json()
    with SessionLocal.begin() as db:
        flow = get_flow(db, p.get('flow'))
        if not flow.usb_verified:
            raise Failure('Verifikasi USB Key harus berhasil terlebih dahulu.', 403)
        if flow.kind == 'register':
            raise Failure('Pendaftaran akun harus melalui kamera wajah pada halaman Register. Sidik jari dapat ditambahkan setelah login.', 403)
        user = db.get(User, flow.user_id)
        credentials = db.scalars(select(Credential).where(Credential.user_id == user.id)).all()
        wa, s = webauthn_module()
        challenge = secrets.token_bytes(32)
        flow.web_challenge = challenge
        if not credentials:
            raise Failure('Akun belum memiliki biometrik terdaftar.', 403)
        options = wa.generate_authentication_options(
            rp_id=RP_ID,
            challenge=challenge,
            timeout=60000,
            allow_credentials=[s.PublicKeyCredentialDescriptor(id=c.credential_id) for c in credentials],
            user_verification=s.UserVerificationRequirement.REQUIRED,
        )
        return {'ok': True, 'kind': flow.kind, 'publicKey': json.loads(wa.options_to_json(options))}


@app.post('/api/security/passkey/options')
async def add_passkey_options(request: Request):
    with SessionLocal.begin() as db:
        user = require_user(request, db, csrf=True)
        sid = request.cookies.get('chrya_sid', '')
        logged = db.get(UserSession, digest(sid))
        if not logged or int(time.time()) > logged.expires - 28800 + 600:
            raise Failure('Untuk menambah perangkat, logout lalu login kembali (maksimal 10 menit setelah login).', 403)
        wa, st = webauthn_module()
        registered = db.scalars(select(Credential).where(Credential.user_id == user.id)).all()
        token = secrets.token_urlsafe(32)
        challenge = secrets.token_bytes(32)
        db.add(Flow(
            token_hash=digest(token), user_id=user.id, kind='add_passkey',
            usb_verified=True, web_challenge=challenge, expires=int(time.time()) + 180,
        ))
        opts = wa.generate_registration_options(
            rp_id=RP_ID, rp_name='CHRYA BOX', user_id=user.handle, user_name=user.username,
            user_display_name=user.full_name, challenge=challenge, timeout=60000,
            authenticator_selection=st.AuthenticatorSelectionCriteria(
                authenticator_attachment=st.AuthenticatorAttachment.PLATFORM,
                user_verification=st.UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[st.PublicKeyCredentialDescriptor(id=c.credential_id) for c in registered],
        )
        return {'ok': True, 'kind': 'register', 'flow': token, 'publicKey': json.loads(wa.options_to_json(opts))}


@app.post('/api/security/passkey/verify')
async def add_passkey_verify(request: Request):
    payload = await request.json()
    credential = payload.get('credential')
    name = str(payload.get('name', 'Platform Passkey')).strip()[:80] or 'Platform Passkey'
    if not isinstance(credential, dict):
        raise Failure('Respons autentikator tidak valid.')
    with SessionLocal.begin() as db:
        user = require_user(request, db, csrf=True)
        logged = db.get(UserSession, digest(request.cookies.get('chrya_sid', '')))
        if not logged or int(time.time()) > logged.expires - 28800 + 600:
            raise Failure('Sesi untuk menambah perangkat telah kedaluwarsa. Silakan login kembali.', 403)
        flow = get_flow(db, payload.get('flow'))
        if flow.kind != 'add_passkey' or flow.user_id != user.id or not flow.web_challenge:
            raise Failure('Permintaan pendaftaran perangkat tidak sah.', 403)
        wa, st = webauthn_module()
        try:
            verified = wa.verify_registration_response(
                credential=credential, expected_challenge=flow.web_challenge,
                expected_origin=ORIGIN, expected_rp_id=RP_ID, require_user_verification=True,
            )
        except Exception as exc:
            raise Failure('Pendaftaran perangkat biometrik gagal.', 401) from exc
        if db.scalar(select(Credential.id).where(Credential.credential_id == bytes(verified.credential_id))):
            raise Failure('Perangkat ini sudah terdaftar.', 409)
        db.add(Credential(
            user_id=user.id,
            credential_id=bytes(verified.credential_id),
            public_key=bytes(verified.credential_public_key),
            sign_count=verified.sign_count,
            transports=json.dumps(credential.get('response', {}).get('transports', [])),
            name=name,
        ))
        db.delete(flow)
        ledger_append(db, user.id, 'PASSKEY_ADDED', f'user:{user.id}')
        total = db.scalar(select(func.count()).select_from(Credential).where(Credential.user_id == user.id))
        return {'ok': True, 'message': 'Perangkat biometrik berhasil didaftarkan.', 'count': total}


@app.post('/api/auth/webauthn/verify')
async def passkey_verify(request: Request):
    p = await request.json()
    credential = p.get('credential')
    if not isinstance(credential, dict):
        raise Failure('Respons autentikator tidak valid.')
    with SessionLocal.begin() as db:
        flow = get_flow(db, p.get('flow'))
        if not flow.usb_verified or not flow.web_challenge:
            raise Failure('Alur keamanan belum lengkap.', 403)
        if flow.kind == 'register':
            raise Failure('Selesaikan pendaftaran akun melalui kamera wajah terlebih dahulu.', 403)
        wa, s = webauthn_module()
        try:
            raw_id = ub64(credential['id'])
        except (KeyError, TypeError, ValueError) as exc:
            raise Failure('Credential ID salah.') from exc
        c = db.scalar(select(Credential).where(Credential.user_id == flow.user_id, Credential.credential_id == raw_id))
        if not c:
            raise Failure('Credential tidak terdaftar.', 401)
        try:
            result = wa.verify_authentication_response(
                credential=credential, expected_challenge=flow.web_challenge,
                expected_origin=ORIGIN, expected_rp_id=RP_ID,
                credential_public_key=c.public_key, credential_current_sign_count=c.sign_count,
                require_user_verification=True,
            )
        except Exception as exc:
            u = db.get(User, flow.user_id)
            record_login_event(db, request, user_id=flow.user_id, username=u.username if u else '', method='webauthn', status='failed', reason='Verifikasi passkey gagal')
            raise Failure('Verifikasi biometrik gagal (login).', 401) from exc
        c.sign_count = result.new_sign_count
        sid, data = new_auth_response(db, request, flow, 'webauthn')
    reply = JSONResponse(data)
    reply.set_cookie('chrya_sid', sid, httponly=True, secure=ORIGIN.startswith('https://'), samesite='strict', max_age=28800, path='/')
    return reply


# --- Webcam Face Unlock with SFace 128-D Embedding + Liveness + 1-Face-1-Account + Persistent Rate Limiting ---
def valid_face_template(db: DBSession, user_id: int) -> FaceTemplate | None:
    """Return user's FaceTemplate only if it is an authentic SFace 128-D (FC02) template; purge legacy LBP (FC01) templates."""
    row = db.scalar(select(FaceTemplate).where(FaceTemplate.user_id == user_id))
    if not row:
        return None
    blob = bytes(row.encrypted_descriptor or b'')
    if not blob.startswith(b'FC02') or row.model_version == 'legacy_256':
        db.delete(row)
        db.flush()
        return None
    return row


def ensure_face_unique_across_accounts(db: DBSession, features, current_user_id: int) -> None:
    """Enforce strict 1-Face-1-Account policy: reject enrollment if this face embedding already matches another account."""
    other_rows = db.scalars(select(FaceTemplate).where(FaceTemplate.user_id != current_user_id)).all()
    for other in other_rows:
        blob = bytes(other.encrypted_descriptor or b'')
        if not blob.startswith(b'FC02'):
            continue
        try:
            other_vec = decrypt_template(blob, other.user_id, MASTER)
            dist = face_distance(features, other_vec)
        except Exception:
            continue
        if dist <= MAX_MATCH_DISTANCE:
            raise FaceError('Wajah ini sudah terdaftar pada akun lain. Kebijakan keamanan: 1 wajah hanya untuk 1 akun.')


def face_challenge(flow: Flow) -> str:
    direction = 'front'
    flow.web_challenge = f'face:{direction}:{secrets.token_hex(16)}'.encode('utf-8')
    return direction


def face_failed(db: DBSession, token: str, user_id: int | None = None):
    key = digest(token)
    count, expiry = FACE_FAILURES.get(key, (0, 0.0))
    if expiry < time.time():
        count = 0
    FACE_FAILURES[key] = (count + 1, time.time() + 600)
    if user_id is not None:
        user = db.get(User, user_id)
        if user:
            user.face_failure_count = (user.face_failure_count or 0) + 1
            if user.face_failure_count >= 5:
                user.face_locked_until = int(time.time()) + 300
                user.face_failure_count = 0
                notify(db, user.id, None, 'Peringatan Keamanan: Face Unlock dikunci 5 menit karena 5x gagal verifikasi wajah.', category='security')


def face_attempts_check(db: DBSession, token: str, user_id: int | None = None):
    count, expires = FACE_FAILURES.get(digest(token), (0, 0.0))
    if expires > time.time() and count >= 5:
        raise Failure('Terlalu banyak percobaan kamera. Mulai login kembali.', 429)
    if user_id is not None:
        user = db.get(User, user_id)
        if user and (user.face_locked_until or 0) > int(time.time()):
            raise Failure('Face Unlock akun dikunci sementara (5 menit) karena terlalu banyak percobaan gagal.', 429)


def recent_session(db: DBSession, request: Request, *, password: str | None = None) -> User:
    user = require_user(request, db, csrf=True)
    sid = request.cookies.get('chrya_sid', '')
    logged = db.get(UserSession, digest(sid))
    if not logged:
        raise Failure('Sesi tidak ditemukan.', 401)
    # Allow either a fresh session (<10 min since login) OR explicit password re-authentication
    if int(time.time()) > logged.expires - 28800 + 600:
        if password:
            try:
                PASSWORD_HASHER.verify(user.password_hash, str(password))
            except (VerifyMismatchError, VerificationError) as exc:
                raise Failure('Password konfirmasi salah.', 401) from exc
        else:
            raise Failure('Untuk operasi keamanan sensitif ini, masukkan password konfirmasi atau login ulang (maksimal 10 menit).', 403)
    return user


def new_auth_response(db: DBSession, request: Request, flow: Flow, method: str) -> tuple[str, dict]:
    user = db.get(User, flow.user_id)
    if not user:
        raise Failure('Akun tidak ditemukan.', 401)
    user.face_failure_count = 0
    user.face_locked_until = 0
    db.delete(flow)
    sid = secrets.token_urlsafe(40)
    csrf = secrets.token_hex(24)
    ip, ua, device = client_meta(request)
    session_uuid = secrets.token_hex(12)
    db.add(UserSession(
        token_hash=digest(sid),
        user_id=user.id,
        csrf=csrf,
        expires=int(time.time()) + 28800,
        session_id=session_uuid,
        ip_address=ip,
        user_agent=ua,
        device_name=device,
    ))
    suspicious = record_login_event(db, request, user_id=user.id, username=user.username, method=method, status='success')
    ledger_append(db, user.id, 'LOGIN', f'verified:password+usb+{method}')
    return sid, {'ok': True, 'user': me_public(user), 'csrf': csrf, 'suspicious_login': suspicious}


@app.post('/api/auth/face/options')
async def camera_options(request: Request):
    p = await request.json()
    token = p.get('flow')
    with SessionLocal.begin() as db:
        flow = get_flow(db, token)
        if not flow.usb_verified:
            raise Failure('Password dan USB Key harus diverifikasi sebelum kamera.', 403)
        face_attempts_check(db, token, flow.user_id)
        existing = valid_face_template(db, flow.user_id)
        if flow.kind == 'login' and not existing:
            raise Failure('Wajah belum terdaftar. Login dengan passkey lama, lalu daftarkan kamera di Security Center.', 403)
        if flow.kind not in ('register', 'login'):
            raise Failure('Alur kamera tidak sesuai.', 403)
        return {
            'ok': True,
            'kind': 'register' if flow.kind == 'register' else 'verify',
            'direction': face_challenge(flow),
            'model': 'YuNet + SFace (128-D ArcFace Embedding)',
            'notice': 'Hadapkan tepat satu wajah ke kamera dengan pencahayaan cukup, lalu pindai sekali.',
        }


@app.post('/api/auth/face/verify')
async def camera_verify(request: Request):
    p = await request.json()
    token = p.get('flow')
    with SessionLocal() as db:
        flow = get_flow(db, token)
        if not flow.usb_verified or not flow.web_challenge or not flow.web_challenge.startswith(b'face:'):
            raise Failure('Selesaikan password, USB Key, dan buka kamera terlebih dahulu.', 403)
        face_attempts_check(db, token, flow.user_id)
        direction = flow.web_challenge.decode('utf-8').split(':')[1]
        user = db.get(User, flow.user_id)
        try:
            features = check_frames(p.get('frames'), direction)
            record = valid_face_template(db, flow.user_id)
            if flow.kind == 'register':
                if record:
                    raise FaceError('Wajah sudah didaftarkan untuk akun ini.')
                ensure_face_unique_across_accounts(db, features, flow.user_id)
                db.add(FaceTemplate(
                    user_id=flow.user_id,
                    encrypted_descriptor=encrypt_template(features, flow.user_id, MASTER),
                    model_version='sface_2021dec',
                ))
                ledger_append(db, flow.user_id, 'FACE_REGISTERED', f'user:{flow.user_id}')
            elif flow.kind == 'login':
                if not record:
                    raise FaceError('Akun belum memiliki data wajah SFace. Silakan daftarkan wajah terlebih dahulu.')
                known = decrypt_template(record.encrypted_descriptor, flow.user_id, MASTER)
                score = face_distance(features, known)
                if score > MAX_MATCH_DISTANCE:
                    raise FaceError('Wajah tidak cocok dengan pemilik akun. Akses ditolak.')
            else:
                raise FaceError('Alur autentikasi tidak dikenal.')
        except FaceError as exc:
            face_failed(db, token, flow.user_id)
            record_login_event(db, request, user_id=flow.user_id, username=user.username if user else '', method='face_unlock', status='failed', reason=str(exc))
            db.commit()
            raise Failure(str(exc), 401) from exc

        if flow.kind == 'register':
            db.delete(flow)
            ledger_append(db, flow.user_id, 'FACE_ENROLLMENT_COMPLETE', f'user:{flow.user_id}')
            result = {
                'ok': True,
                'registered': True,
                'message': 'Pendaftaran wajah berhasil. Sekarang masuk dan verifikasi wajah yang sudah kamu daftarkan.',
            }
            sid = None
        else:
            sid, result = new_auth_response(db, request, flow, 'face-sface')
        db.commit()
    FACE_FAILURES.pop(digest(token), None)
    reply = JSONResponse(result)
    if sid:
        reply.set_cookie('chrya_sid', sid, httponly=True, secure=ORIGIN.startswith('https://'),
                         samesite='strict', max_age=28800, path='/')
    return reply


@app.post('/api/security/face/options')
async def security_camera_options(request: Request):
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    with SessionLocal.begin() as db:
        user = recent_session(db, request, password=p.get('password'))
        token = secrets.token_urlsafe(32)
        flow = Flow(token_hash=digest(token), user_id=user.id, kind='add_face',
                    usb_verified=True, expires=int(time.time()) + 180)
        db.add(flow)
        return {
            'ok': True,
            'flow': token,
            'kind': 'register',
            'direction': face_challenge(flow),
            'notice': 'Daftarkan atau perbarui template wajah (SFace 128-D). Foto tidak disimpan.',
        }


@app.post('/api/security/face/verify')
async def security_camera_verify(request: Request):
    p = await request.json()
    token = p.get('flow')
    with SessionLocal() as db:
        user = recent_session(db, request, password=p.get('password'))
        flow = get_flow(db, token)
        if flow.kind != 'add_face' or flow.user_id != user.id or not flow.web_challenge or not flow.web_challenge.startswith(b'face:'):
            raise Failure('Sesi pendaftaran kamera tidak sah.', 403)
        face_attempts_check(db, token, user.id)
        try:
            features = check_frames(p.get('frames'), flow.web_challenge.decode('utf-8').split(':')[1])
            ensure_face_unique_across_accounts(db, features, user.id)
        except FaceError as exc:
            face_failed(db, token, user.id)
            db.commit()
            raise Failure(str(exc), 400) from exc
        record = db.scalar(select(FaceTemplate).where(FaceTemplate.user_id == user.id))
        ciphertext = encrypt_template(features, user.id, MASTER)
        model_ver = 'sface_2021dec'
        if record:
            record.encrypted_descriptor = ciphertext
            record.model_version = model_ver
            record.created_at = now()
        else:
            db.add(FaceTemplate(user_id=user.id, encrypted_descriptor=ciphertext, model_version=model_ver))
        db.delete(flow)
        ledger_append(db, user.id, 'FACE_ENROLLED', f'user:{user.id}')
        db.commit()
    FACE_FAILURES.pop(digest(token), None)
    return {'ok': True, 'message': 'Wajah kamera berhasil didaftarkan/diperbarui. Gunakan Verifikasi Wajah pada login berikutnya.'}


@app.delete('/api/security/face')
async def delete_face_template(request: Request):
    """Delete / reset stored biometric face template (A.7, I.6)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    with SessionLocal.begin() as db:
        user = recent_session(db, request, password=p.get('password'))
        record = db.scalar(select(FaceTemplate).where(FaceTemplate.user_id == user.id))
        if not record:
            raise Failure('Template wajah belum terdaftar.', 404)
        db.delete(record)
        ledger_append(db, user.id, 'FACE_TEMPLATE_DELETED', f'user:{user.id}')
    return {'ok': True, 'message': 'Template wajah berhasil dihapus. Silakan daftarkan ulang wajah Anda.'}


@app.post('/api/auth/logout')
async def logout(request: Request):
    with SessionLocal.begin() as db:
        user = require_user(request, db, csrf=True)
        token = request.cookies.get('chrya_sid', '')
        db.query(UserSession).filter(UserSession.token_hash == digest(token)).delete()
        ledger_append(db, user.id, 'LOGOUT', f'user:{user.id}')
    r = JSONResponse({'ok': True})
    r.delete_cookie('chrya_sid', path='/')
    return r


# --- STATS & DASHBOARD ---
@app.get('/api/stats')
def stats(request: Request):
    with SessionLocal() as db:
        u = require_user(request, db)
        uid = u.id
        accepted = db.scalars(select(ContactRequest).where(
            ContactRequest.status == 'accepted',
            or_(ContactRequest.sender_id == uid, ContactRequest.recipient_id == uid)
        )).all()
        contacts_count = len({r.recipient_id if r.sender_id == uid else r.sender_id for r in accepted})
        unread_count = db.scalar(select(func.count()).select_from(Message).where(
            Message.receiver_id == uid, Message.receiver_deleted == False, Message.status == 'unread'
        ))
        unread_notifs = db.scalar(select(func.count()).select_from(Notification).where(
            Notification.user_id == uid, Notification.read == False
        ))
        latest_notif = db.scalar(select(Notification).where(
            Notification.user_id == uid, Notification.read == False
        ).order_by(Notification.id.desc()).limit(1))
        latest_msg = db.scalar(select(Message).where(
            Message.receiver_id == uid, Message.receiver_deleted == False
        ).order_by(Message.id.desc()).limit(1))
        return {
            'ok': True,
            'inbox': db.scalar(select(func.count()).select_from(Message).where(Message.receiver_id == uid, Message.receiver_deleted == False)),
            'sent': db.scalar(select(func.count()).select_from(Message).where(Message.sender_id == uid, Message.sender_deleted == False)),
            'unread': unread_count,
            'pending_invites': db.scalar(select(func.count()).select_from(ContactRequest).where(ContactRequest.recipient_id == uid, ContactRequest.status == 'pending')),
            'unread_notifications': unread_notifs,
            'latest_notification': {
                'id': latest_notif.id,
                'text': latest_notif.text,
                'category': latest_notif.category or 'general',
                'message_id': latest_notif.message_id,
                'file_id': latest_notif.file_id,
            } if latest_notif else None,
            'latest_message_id': latest_msg.id if latest_msg else 0,
            'contacts': contacts_count,
            'files': db.scalar(select(func.count()).select_from(VaultFile).where(
                or_(VaultFile.owner_id == uid, and_(VaultFile.receiver_id == uid, VaultFile.share_revoked == False))
            )),
            'notes': db.scalar(select(func.count()).select_from(VaultNote).where(VaultNote.owner_id == uid)),
        }


# --- D. CONTACT MANAGEMENT (Search, Filter, Invite, Cancel, Accept/Reject, Delete, Block/Unblock) ---
@app.get('/api/contacts')
def contacts(request: Request, q: str = '', status_filter: str = 'all'):
    with SessionLocal() as db:
        u = require_user(request, db)
        uid = u.id
        requests = db.scalars(select(ContactRequest).where(
            or_(ContactRequest.sender_id == uid, ContactRequest.recipient_id == uid)
        ).order_by(ContactRequest.id.desc())).all()
        blocks = db.scalars(select(ContactBlock).where(
            or_(ContactBlock.user_id == uid, ContactBlock.blocked_id == uid)
        )).all()
        ids = {r.sender_id for r in requests} | {r.recipient_id for r in requests} | {b.blocked_id for b in blocks} | {b.user_id for b in blocks}
        ids.discard(uid)
        people = {p.id: contact_public(p) for p in db.scalars(select(User).where(User.id.in_(ids))).all()} if ids else {}
        latest = {}
        for r in requests:
            other = r.recipient_id if r.sender_id == uid else r.sender_id
            latest.setdefault(other, r)
        blocked_by_me = {b.blocked_id for b in blocks if b.user_id == uid}
        blocked_me = {b.user_id for b in blocks if b.blocked_id == uid}
        blocked_ids = blocked_by_me | blocked_me

        items = []
        seen_pair_status = set()
        for r in requests:
            other = r.recipient_id if r.sender_id == uid else r.sender_id
            if other not in people:
                continue
            key_pair = (other, r.status, 'outgoing' if r.sender_id == uid else 'incoming')
            if key_pair in seen_pair_status:
                continue
            seen_pair_status.add(key_pair)
            item_obj = {
                'id': r.id,
                'person': people[other],
                'direction': 'outgoing' if r.sender_id == uid else 'incoming',
                'status': 'blocked' if other in blocked_ids else r.status,
                'connected': accepted_contact(db, uid, other),
                'blocked_by_me': other in blocked_by_me,
            }
            if status_filter != 'all' and item_obj['status'] != status_filter:
                continue
            items.append(item_obj)

        blocked_list = [
            {'user_id': bid, 'person': people[bid]}
            for bid in blocked_by_me if bid in people
        ]

        search_results = []
        term = q.strip().lstrip('@').lower()[:40]
        if len(term) >= 1:
            esc = chr(92)
            literal = term.replace(esc, esc + esc).replace('%', esc + '%').replace('_', esc + '_')
            pattern = '%' + literal + '%'
            results = db.scalars(select(User).where(
                User.id != uid,
                or_(User.username.ilike(pattern, escape=esc), User.full_name.ilike(pattern, escape=esc))
            ).order_by(User.username.asc()).limit(20)).all()
            for person in results:
                if person.id in blocked_me:
                    continue
                relationship = latest.get(person.id)
                relation = 'none'
                if person.id in blocked_by_me:
                    relation = 'blocked'
                elif accepted_contact(db, uid, person.id):
                    relation = 'accepted'
                elif relationship:
                    if relationship.status == 'pending':
                        relation = 'pending_outgoing' if relationship.sender_id == uid else 'pending_incoming'
                    elif relationship.status in ('rejected', 'blocked'):
                        relation = relationship.status
                search_results.append({**contact_public(person), 'relation': relation})
        return {
            'ok': True,
            'items': items,
            'blocked': blocked_list,
            'search': search_results,
            'query': term,
            'not_found': bool(len(term) >= 1 and len(search_results) == 0),
        }


@app.post('/api/contacts/request')
async def send_invite(request: Request):
    p = await request.json()
    username = str(p.get('username', '')).strip().lower()
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        target = db.scalar(select(User).where(User.username == username))
        if not target or target.id == u.id:
            raise Failure('Kontak tidak ditemukan.')
        if db.scalar(select(ContactBlock.id).where(
            or_(and_(ContactBlock.user_id == u.id, ContactBlock.blocked_id == target.id),
                and_(ContactBlock.user_id == target.id, ContactBlock.blocked_id == u.id))
        )):
            raise Failure('Kontak ini diblokir.')
        if db.scalar(select(ContactRequest.id).where(
            or_(and_(ContactRequest.sender_id == u.id, ContactRequest.recipient_id == target.id),
                and_(ContactRequest.sender_id == target.id, ContactRequest.recipient_id == u.id)),
            ContactRequest.status.in_(['pending', 'accepted'])
        ).limit(1)):
            raise Failure('Undangan aktif/relasi kontak sudah ada.')
        req = ContactRequest(sender_id=u.id, recipient_id=target.id, status='pending')
        db.add(req)
        db.flush()
        notify(db, target.id, None, f'{u.username} mengirim undangan kontak', category='contact')
        ledger_append(db, u.id, 'INVITATION_SENT', f'request:{req.id}')
    return {'ok': True, 'request_id': req.id, 'message': 'Undangan terkirim.'}


@app.post('/api/contacts/respond')
async def respond_invite(request: Request):
    p = await request.json()
    action = p.get('action')
    if action not in ('accept', 'reject', 'block'):
        raise Failure('Pilihan tidak valid.')
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        req = db.get(ContactRequest, p.get('id'))
        if not req or req.recipient_id != u.id or req.status != 'pending':
            raise Failure('Undangan tidak ditemukan / tidak memiliki izin.', 403)
        req.status = {'accept': 'accepted', 'reject': 'rejected', 'block': 'blocked'}[action]
        if action == 'block':
            if not db.scalar(select(ContactBlock.id).where(ContactBlock.user_id == u.id, ContactBlock.blocked_id == req.sender_id)):
                db.add(ContactBlock(user_id=u.id, blocked_id=req.sender_id))
        notify(db, req.sender_id, None, f'{u.username} merespons undangan: {action}', category='contact')
        ledger_append(db, u.id, 'INVITATION_' + action.upper(), f'request:{req.id}')
    return {'ok': True}


@app.post('/api/contacts/cancel')
async def cancel_invite(request: Request):
    """Cancel an outgoing pending contact invitation (D.5)."""
    p = await request.json()
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        req = db.get(ContactRequest, p.get('id'))
        if not req or req.sender_id != u.id or req.status != 'pending':
            raise Failure('Undangan keluar tidak ditemukan atau sudah diproses.', 404)
        db.delete(req)
        ledger_append(db, u.id, 'INVITATION_CANCELLED', f'request:{p.get("id")}')
    return {'ok': True, 'message': 'Undangan kontak dibatalkan.'}


@app.delete('/api/contacts/{other_user_id}')
def remove_contact(other_user_id: int, request: Request):
    """Remove an accepted contact relationship (D.4)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        rows = db.scalars(select(ContactRequest).where(
            or_(and_(ContactRequest.sender_id == u.id, ContactRequest.recipient_id == other_user_id),
                and_(ContactRequest.sender_id == other_user_id, ContactRequest.recipient_id == u.id))
        )).all()
        if not rows:
            raise Failure('Relasi kontak tidak ditemukan.', 404)
        for r in rows:
            db.delete(r)
        ledger_append(db, u.id, 'CONTACT_REMOVED', f'user:{other_user_id}')
    return {'ok': True, 'message': 'Kontak berhasil dihapus.'}


@app.post('/api/contacts/block')
async def block_contact(request: Request):
    p = await request.json()
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        target = db.get(User, p.get('user_id'))
        if not target or target.id == u.id:
            raise Failure('Pengguna tidak valid.')
        if not db.scalar(select(ContactBlock.id).where(ContactBlock.user_id == u.id, ContactBlock.blocked_id == target.id)):
            db.add(ContactBlock(user_id=u.id, blocked_id=target.id))
        rows = db.scalars(select(ContactRequest).where(
            or_(and_(ContactRequest.sender_id == u.id, ContactRequest.recipient_id == target.id),
                and_(ContactRequest.sender_id == target.id, ContactRequest.recipient_id == u.id))
        )).all()
        for r in rows:
            r.status = 'blocked'
        ledger_append(db, u.id, 'CONTACT_BLOCKED', f'user:{target.id}')
    return {'ok': True}


@app.post('/api/contacts/unblock')
async def unblock_contact(request: Request):
    """Unblock a previously blocked user (D.7)."""
    p = await request.json()
    target_id = int(p.get('user_id') or 0)
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        blocks = db.scalars(select(ContactBlock).where(ContactBlock.user_id == u.id, ContactBlock.blocked_id == target_id)).all()
        if not blocks:
            raise Failure('Pengguna tidak ada dalam daftar blokir.', 404)
        for b in blocks:
            db.delete(b)
        rows = db.scalars(select(ContactRequest).where(
            or_(and_(ContactRequest.sender_id == u.id, ContactRequest.recipient_id == target_id),
                and_(ContactRequest.sender_id == target_id, ContactRequest.recipient_id == u.id)),
            ContactRequest.status == 'blocked'
        )).all()
        for r in rows:
            db.delete(r)
        ledger_append(db, u.id, 'CONTACT_UNBLOCKED', f'user:{target_id}')
    return {'ok': True, 'message': 'Blokir pengguna telah dibuka.'}


# --- E. MESSAGING SYSTEM (Compose, Inbox, Sent, Archive, Unarchive, Pin, Search, Delete Msg/Conversation, Delivery/Read Status) ---
def message_public(db: DBSession, m: Message, uid: int, include_body: bool = False) -> dict:
    person = db.get(User, m.receiver_id if m.sender_id == uid else m.sender_id)
    delivery_state = 'read' if m.status == 'read' else 'delivered'
    data = {
        'id': m.id,
        'sender_id': m.sender_id,
        'receiver_id': m.receiver_id,
        'person': me_public(person) if person else {'id': 0, 'username': 'deleted', 'full_name': 'Unknown', 'email': ''},
        'subject': decrypt_domain_text(m.subject_ciphertext, 'SUBJECT'),
        'created_at': timestamp(m.created_at),
        'read_at': timestamp(m.read_at),
        'status': m.status,
        'delivery_indicator': '✓✓ Terbaca' if delivery_state == 'read' else '✓ Terkirim ke Brankas',
        'archived': bool(m.archived),
        'pinned': bool(m.pinned),
        'reply_to': m.reply_to,
    }
    if include_body:
        data['body'] = decrypt_domain_text(m.body_ciphertext, 'BODY')
    return data


@app.post('/api/messages')
async def compose(request: Request, background: BackgroundTasks):
    p = await request.json()
    username = str(p.get('recipient', '')).strip().lower()
    title = str(p.get('subject', '')).strip()
    body = str(p.get('body', '')).strip()
    if not 1 <= len(title) <= 150 or not 1 <= len(body) <= 12000:
        raise Failure('Judul 1-150 dan pesan 1-12000 karakter.')
    reply = p.get('reply_to')
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        receiver = db.scalar(select(User).where(User.username == username))
        if not receiver or not accepted_contact(db, u.id, receiver.id):
            raise Failure('Penerima harus merupakan kontak yang sudah disetujui.', 403)
        if reply:
            root = db.get(Message, int(reply))
            if not root or u.id not in (root.sender_id, root.receiver_id) or receiver.id not in (root.sender_id, root.receiver_id):
                raise Failure('Pesan yang dibalas bukan milik percakapan ini.', 403)
        obj = Message(
            sender_id=u.id,
            receiver_id=receiver.id,
            subject_ciphertext=encrypt_domain_text(title, 'SUBJECT'),
            body_ciphertext=encrypt_domain_text(body, 'BODY'),
            reply_to=int(reply) if reply else None,
        )
        db.add(obj)
        db.flush()
        notify(db, receiver.id, obj.id, f'Pesan rahasia baru dari {u.username}', category='message')
        log = EmailLog(sender_id=u.id, recipient=receiver.email, sender_name=u.username, message_id=obj.id)
        db.add(log)
        db.flush()
        logid = log.id
        mid = obj.id
        ledger_append(db, u.id, 'MESSAGE_SENT', f'message:{mid}')
    background.add_task(send_email_job, logid)
    return {'ok': True, 'message_id': mid, 'notice': 'Pesan terenkripsi disimpan; notifikasi email diproses secara terpisah.'}


@app.get('/api/messages')
def list_messages(request: Request, box: str = 'inbox', q: str = ''):
    if box not in ('inbox', 'sent', 'archive', 'pinned'):
        raise Failure('Kotak pesan tidak dikenal.')
    term = q.strip().lower()
    with SessionLocal() as db:
        u = require_user(request, db)
        if box == 'inbox':
            query = select(Message).where(Message.receiver_id == u.id, Message.receiver_deleted == False, Message.archived == False)
        elif box == 'sent':
            query = select(Message).where(Message.sender_id == u.id, Message.sender_deleted == False)
        elif box == 'archive':
            query = select(Message).where(Message.receiver_id == u.id, Message.receiver_deleted == False, Message.archived == True)
        else:  # pinned
            query = select(Message).where(
                or_(and_(Message.receiver_id == u.id, Message.receiver_deleted == False),
                    and_(Message.sender_id == u.id, Message.sender_deleted == False)),
                Message.pinned == True
            )
        rows = db.scalars(query.order_by(Message.pinned.desc(), Message.id.desc()).limit(100)).all()
        items = []
        for m in rows:
            item = message_public(db, m, u.id, include_body=bool(term))
            if term:
                haystack = f"{item['subject']} {item.get('body', '')} {item['person']['username']} {item['person']['full_name']}".lower()
                if term not in haystack:
                    continue
                item.pop('body', None)
            items.append(item)
        return {'ok': True, 'items': items, 'box': box, 'query': q}


@app.get('/api/messages/{mid}')
def read_message(mid: int, request: Request):
    with SessionLocal.begin() as db:
        u = require_user(request, db)
        m = db.get(Message, mid)
        if not m or u.id not in (m.sender_id, m.receiver_id):
            raise Failure('Pesan tidak ditemukan / akses ditolak.', 404)
        if (m.sender_id == u.id and m.sender_deleted) or (m.receiver_id == u.id and m.receiver_deleted):
            raise Failure('Pesan telah dihapus.', 404)
        if m.receiver_id == u.id and m.status == 'unread':
            m.status = 'read'
            m.read_at = now()
            for notif in db.scalars(select(Notification).where(
                Notification.user_id == u.id, Notification.message_id == mid, Notification.read == False
            )).all():
                notif.read = True
            ledger_append(db, u.id, 'MESSAGE_READ', f'message:{mid}')
        result = message_public(db, m, u.id, True)
        return {'ok': True, 'message': result}


@app.post('/api/messages/{mid}/archive')
def archive_message(mid: int, request: Request):
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        m = db.get(Message, mid)
        if not m or m.receiver_id != u.id:
            raise Failure('Tidak boleh mengarsipkan pesan orang lain.', 403)
        m.archived = True
        ledger_append(db, u.id, 'MESSAGE_ARCHIVED', f'message:{mid}')
    return {'ok': True}


@app.post('/api/messages/{mid}/unarchive')
def unarchive_message(mid: int, request: Request):
    """Unarchive an archived message back to Inbox (E.4)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        m = db.get(Message, mid)
        if not m or m.receiver_id != u.id:
            raise Failure('Tidak boleh memindahkan pesan orang lain.', 403)
        m.archived = False
        ledger_append(db, u.id, 'MESSAGE_UNARCHIVED', f'message:{mid}')
    return {'ok': True}


@app.post('/api/messages/{mid}/pin')
def toggle_pin_message(mid: int, request: Request):
    """Pin or unpin (favorite) a message (E.5)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        m = db.get(Message, mid)
        if not m or u.id not in (m.sender_id, m.receiver_id):
            raise Failure('Pesan tidak ditemukan.', 404)
        m.pinned = not bool(m.pinned)
        ledger_append(db, u.id, 'MESSAGE_PINNED' if m.pinned else 'MESSAGE_UNPINNED', f'message:{mid}')
        pinned_state = m.pinned
    return {'ok': True, 'pinned': pinned_state}


@app.delete('/api/messages/{mid}')
def delete_message(mid: int, request: Request):
    """Delete a message for the current user, and purge from DB if both sides deleted (E.2)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        m = db.get(Message, mid)
        if not m or u.id not in (m.sender_id, m.receiver_id):
            raise Failure('Pesan tidak ditemukan.', 404)
        if m.sender_id == u.id:
            m.sender_deleted = True
        if m.receiver_id == u.id:
            m.receiver_deleted = True
        if m.sender_deleted and m.receiver_deleted:
            db.query(Notification).filter(Notification.message_id == mid).update({'message_id': None})
            db.query(EmailLog).filter(EmailLog.message_id == mid).update({'message_id': None})
            db.query(Message).filter(Message.reply_to == mid).update({'reply_to': None})
            db.delete(m)
        ledger_append(db, u.id, 'MESSAGE_DELETED', f'message:{mid}')
    return {'ok': True}


@app.delete('/api/conversations/{username}')
def delete_conversation(username: str, request: Request):
    """Delete entire conversation history with a contact for the current user (E.3)."""
    peer_username = username.strip().lower()
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        peer = db.scalar(select(User).where(User.username == peer_username))
        if not peer:
            raise Failure('Kontak tidak ditemukan.', 404)
        rows = db.scalars(select(Message).where(
            or_(and_(Message.sender_id == u.id, Message.receiver_id == peer.id),
                and_(Message.sender_id == peer.id, Message.receiver_id == u.id))
        )).all()
        count = 0
        for m in rows:
            if m.sender_id == u.id and not m.sender_deleted:
                m.sender_deleted = True
                count += 1
            if m.receiver_id == u.id and not m.receiver_deleted:
                m.receiver_deleted = True
                count += 1
        ledger_append(db, u.id, 'CONVERSATION_DELETED', f'peer:{peer.id}:count:{count}')
    return {'ok': True, 'deleted_count': count}


# --- G. MY VAULT (Encrypted Notes: Create, Read, Update/Edit, Delete, Search, Category) ---
@app.get('/api/notes')
def notes(request: Request, q: str = '', category: str = ''):
    term = q.strip().lower()
    cat_filter = category.strip()
    with SessionLocal() as db:
        u = require_user(request, db)
        query = select(VaultNote).where(VaultNote.owner_id == u.id)
        if cat_filter and cat_filter.lower() != 'semua':
            query = query.where(VaultNote.category == cat_filter)
        rows = db.scalars(query.order_by(VaultNote.id.desc())).all()
        items = []
        for n in rows:
            title = decrypt_domain_text(n.title_ciphertext, 'NOTE_TITLE')
            body = decrypt_domain_text(n.body_ciphertext, 'NOTE_BODY')
            cat = n.category or 'Umum'
            if term and term not in f'{title} {body} {cat}'.lower():
                continue
            items.append({
                'id': n.id,
                'title': title,
                'body': body,
                'category': cat,
                'created_at': timestamp(n.created_at),
                'updated_at': timestamp(n.updated_at or n.created_at),
            })
        return {'ok': True, 'items': items}


@app.post('/api/notes')
async def add_note(request: Request):
    p = await request.json()
    title = str(p.get('title', '')).strip()
    body = str(p.get('body', '')).strip()
    category = str(p.get('category', 'Umum')).strip()[:40] or 'Umum'
    if not 1 <= len(title) <= 100 or not 1 <= len(body) <= 10000:
        raise Failure('Judul 1-100 karakter dan catatan maksimal 10000 karakter.')
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        n = VaultNote(
            owner_id=u.id,
            title_ciphertext=encrypt_domain_text(title, 'NOTE_TITLE'),
            body_ciphertext=encrypt_domain_text(body, 'NOTE_BODY'),
            category=category,
        )
        db.add(n)
        db.flush()
        ledger_append(db, u.id, 'NOTE_SAVED', f'note:{n.id}')
    return {'ok': True, 'note_id': n.id}


@app.put('/api/notes/{nid}')
async def update_note(nid: int, request: Request):
    """Edit an existing encrypted note in My Vault (G.1)."""
    p = await request.json()
    title = str(p.get('title', '')).strip()
    body = str(p.get('body', '')).strip()
    category = str(p.get('category', 'Umum')).strip()[:40] or 'Umum'
    if not 1 <= len(title) <= 100 or not 1 <= len(body) <= 10000:
        raise Failure('Judul 1-100 karakter dan catatan maksimal 10000 karakter.')
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        n = db.get(VaultNote, nid)
        if not n or n.owner_id != u.id:
            raise Failure('Catatan tidak ditemukan.', 404)
        n.title_ciphertext = encrypt_domain_text(title, 'NOTE_TITLE')
        n.body_ciphertext = encrypt_domain_text(body, 'NOTE_BODY')
        n.category = category
        n.updated_at = now()
        ledger_append(db, u.id, 'NOTE_UPDATED', f'note:{nid}')
    return {'ok': True, 'note_id': nid}


@app.delete('/api/notes/{nid}')
def delete_note(nid: int, request: Request):
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        n = db.get(VaultNote, nid)
        if not n or n.owner_id != u.id:
            raise Failure('Catatan tidak ditemukan.', 404)
        db.delete(n)
        ledger_append(db, u.id, 'NOTE_DELETED', f'note:{nid}')
    return {'ok': True}


# --- F. FILE VAULT (Upload, Encrypt, Download, Preview, Search, Delete, Category, Share & Revoke) ---
ALLOWED_EXT = {'.pdf', '.docx', '.xlsx', '.png', '.jpg', '.jpeg', '.txt', '.zip', '.csv', '.pptx'}


def infer_file_category(ext: str, explicit: str = '') -> str:
    if explicit and explicit.strip():
        return explicit.strip()[:40]
    ext = ext.lower()
    if ext in ('.png', '.jpg', '.jpeg'):
        return 'Gambar'
    if ext in ('.zip',):
        return 'Arsip'
    if ext in ('.xlsx', '.csv'):
        return 'Spreadsheet'
    return 'Dokumen'


@app.post('/api/files')
async def upload_file(request: Request, background: BackgroundTasks, file: UploadFile = File(...),
                      recipient: str = Form(default=''), category: str = Form(default='')):
    original = Path(file.filename or '').name
    suffix = Path(original).suffix.lower()
    if not original or len(original) > 200 or suffix not in ALLOWED_EXT:
        raise Failure('Format file tidak diizinkan.')
    raw = await file.read(6 * 1024 * 1024 + 1)
    if len(raw) > 6 * 1024 * 1024 or not raw:
        raise Failure('Ukuran file maksimal 6 MB dan tidak boleh kosong.')
    storedid = secrets.token_hex(20)
    blob = encrypt_domain_file(raw)
    location = STORAGE / storedid
    location.write_bytes(blob)
    cat = infer_file_category(suffix, category)
    try:
        with SessionLocal.begin() as db:
            u = require_user(request, db, True)
            receiver = None
            if recipient.strip():
                receiver = db.scalar(select(User).where(User.username == recipient.strip().lower()))
                if not receiver or not accepted_contact(db, u.id, receiver.id):
                    raise Failure('Penerima file harus kontak yang disetujui.', 403)
            obj = VaultFile(
                owner_id=u.id,
                receiver_id=receiver.id if receiver else None,
                storage_id=storedid,
                filename_ciphertext=encrypt_domain_text(original, 'FILENAME'),
                media_type=mimetypes.guess_type(original)[0] or 'application/octet-stream',
                size_bytes=len(raw),
                category=cat,
                share_revoked=False,
            )
            db.add(obj)
            db.flush()
            ledger_append(db, u.id, 'FILE_ENCRYPTED', f'file:{obj.id}')
            if receiver:
                notify(db, receiver.id, None, f'{u.username} mengirim file rahasia ({cat})', file_id=obj.id, category='file')
                log = EmailLog(sender_id=u.id, recipient=receiver.email, sender_name=u.username, file_id=obj.id)
                db.add(log)
                db.flush()
                logid = log.id
            else:
                logid = None
            fileid = obj.id
    except Exception:
        location.unlink(missing_ok=True)
        raise
    if logid:
        background.add_task(send_email_job, logid)
    return {'ok': True, 'file_id': fileid, 'message': 'File telah terenkripsi dengan ChaCha20-Poly1305.'}


@app.get('/api/files')
def list_files(request: Request, q: str = '', category: str = ''):
    term = q.strip().lower()
    cat_filter = category.strip()
    with SessionLocal() as db:
        u = require_user(request, db)
        rows = db.scalars(select(VaultFile).where(
            or_(VaultFile.owner_id == u.id, and_(VaultFile.receiver_id == u.id, VaultFile.share_revoked == False))
        ).order_by(VaultFile.id.desc())).all()
        user_ids = {f.owner_id for f in rows} | {f.receiver_id for f in rows if f.receiver_id}
        people = {p.id: p.username for p in db.scalars(select(User).where(User.id.in_(user_ids))).all()} if user_ids else {}
        items = []
        for f in rows:
            fname = decrypt_domain_text(f.filename_ciphertext, 'FILENAME')
            cat = f.category or 'Dokumen'
            if cat_filter and cat_filter.lower() != 'semua' and cat != cat_filter:
                continue
            if term and term not in f'{fname} {cat}'.lower():
                continue
            items.append({
                'id': f.id,
                'filename': fname,
                'category': cat,
                'media_type': f.media_type,
                'size_bytes': f.size_bytes,
                'receiver_id': f.receiver_id,
                'receiver_username': people.get(f.receiver_id, '') if f.receiver_id else '',
                'owner_id': f.owner_id,
                'owner_username': people.get(f.owner_id, ''),
                'share_revoked': bool(f.share_revoked),
                'created_at': timestamp(f.created_at),
            })
        return {'ok': True, 'items': items}


def _authorized_file_access(db: DBSession, u: User, fid: int) -> VaultFile:
    f = db.get(VaultFile, fid)
    if not f:
        raise Failure('File tidak ditemukan atau akses ditolak.', 404)
    if u.id == f.owner_id:
        return f
    if u.id == f.receiver_id and not f.share_revoked:
        return f
    raise Failure('File tidak ditemukan atau akses telah dicabut.', 404)


@app.get('/api/files/{fid}/download')
def file_download(fid: int, request: Request):
    with SessionLocal.begin() as db:
        u = require_user(request, db)
        f = _authorized_file_access(db, u, fid)
        original = decrypt_domain_text(f.filename_ciphertext, 'FILENAME')
        blob = (STORAGE / f.storage_id).read_bytes()
        plain = decrypt_domain_file(blob)
        ledger_append(db, u.id, 'FILE_DECRYPTED', f'file:{fid}')
    return Response(content=plain, media_type='application/octet-stream', headers={
        'Content-Disposition': "attachment; filename*=UTF-8''" + quote(original, safe=''),
        'Cache-Control': 'no-store',
    })


def _extract_document_text_preview(ext: str, plain: bytes, original: str) -> str:
    """Extract readable text preview from DOCX, XLSX, PPTX, ZIP, or PDF without external dependencies."""
    import io
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        if ext == '.docx' and zipfile.is_zipfile(io.BytesIO(plain)):
            with zipfile.ZipFile(io.BytesIO(plain)) as zf:
                xml_bytes = zf.read('word/document.xml')
            root = ET.fromstring(xml_bytes)
            paragraphs = []
            for p in root.iter():
                if p.tag.endswith('}p'):
                    texts = [t.text for t in p.iter() if t.tag.endswith('}t') and t.text]
                    if texts:
                        paragraphs.append(''.join(texts))
            out = '\n'.join(paragraphs).strip()
            return out[:8192] if out else f'Dokumen Word ({original}) tidak memiliki teks paragraf.'
        if ext == '.pptx' and zipfile.is_zipfile(io.BytesIO(plain)):
            with zipfile.ZipFile(io.BytesIO(plain)) as zf:
                slide_files = sorted(n for n in zf.namelist() if n.startswith('ppt/slides/slide') and n.endswith('.xml'))
                slides_text = []
                for idx, sname in enumerate(slide_files, 1):
                    root = ET.fromstring(zf.read(sname))
                    words = [t.text.strip() for t in root.iter() if t.tag.endswith('}t') and t.text and t.text.strip()]
                    if words:
                        slides_text.append(f'[Slide {idx}]\n' + ' '.join(words))
            out = '\n\n'.join(slides_text).strip()
            return out[:8192] if out else f'Presentasi PowerPoint ({original}, {len(slide_files)} slide).'
        if ext == '.xlsx' and zipfile.is_zipfile(io.BytesIO(plain)):
            with zipfile.ZipFile(io.BytesIO(plain)) as zf:
                strings = []
                if 'xl/sharedStrings.xml' in zf.namelist():
                    root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
                    strings = [t.text for t in root.iter() if t.tag.endswith('}t') and t.text]
            out = ' | '.join(strings).strip()
            return out[:8192] if out else f'Spreadsheet Excel ({original}, {len(plain)} byte) terverifikasi utuh.'
        if ext == '.zip' and zipfile.is_zipfile(io.BytesIO(plain)):
            with zipfile.ZipFile(io.BytesIO(plain)) as zf:
                listing = [f'• {info.filename} ({info.file_size} byte)' for info in zf.infolist()[:60]]
            return f'Isi Arsip ZIP ({original}):\n' + ('\n'.join(listing) if listing else '(Arsip kosong)')
    except Exception:
        pass
    return f'Berkas {original} ({len(plain)} byte) terverifikasi utuh dengan ChaCha20-Poly1305. Klik Download untuk membuka di aplikasi terkait.'


@app.get('/api/files/{fid}/inline')
def file_inline(fid: int, request: Request):
    """Stream decrypted file inline (for native browser PDF/image viewer in iframe or new tab)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db)
        f = _authorized_file_access(db, u, fid)
        original = decrypt_domain_text(f.filename_ciphertext, 'FILENAME')
        blob = (STORAGE / f.storage_id).read_bytes()
        plain = decrypt_domain_file(blob)
        ext = Path(original).suffix.lower()
        media = f.media_type or mimetypes.guess_type(original)[0] or 'application/octet-stream'
        if ext == '.pdf':
            media = 'application/pdf'
        elif ext == '.png':
            media = 'image/png'
        elif ext in ('.jpg', '.jpeg'):
            media = 'image/jpeg'
        elif ext in ('.txt', '.csv'):
            media = 'text/plain; charset=utf-8'
    return Response(content=plain, media_type=media, headers={
        'Content-Disposition': "inline; filename*=UTF-8''" + quote(original, safe=''),
        'Cache-Control': 'private, no-store',
        'X-Frame-Options': 'SAMEORIGIN',
    })


@app.get('/api/files/{fid}/preview')
def file_preview(fid: int, request: Request):
    """Decrypt and return inline preview metadata/content for images, text, PDF, or Office/ZIP (F.3)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db)
        f = _authorized_file_access(db, u, fid)
        original = decrypt_domain_text(f.filename_ciphertext, 'FILENAME')
        blob = (STORAGE / f.storage_id).read_bytes()
        plain = decrypt_domain_file(blob)
        media = f.media_type or mimetypes.guess_type(original)[0] or 'application/octet-stream'
        ext = Path(original).suffix.lower()
    inline_url = f'/api/files/{fid}/inline'
    if ext in ('.txt', '.csv'):
        text_preview = plain[:8192].decode('utf-8', errors='replace')
        return {'ok': True, 'id': fid, 'kind': 'text', 'filename': original, 'media_type': media,
                'inline_url': inline_url, 'content': text_preview}
    elif ext in ('.png', '.jpg', '.jpeg'):
        data_uri = f'data:{media};base64,' + base64.b64encode(plain).decode('ascii')
        return {'ok': True, 'id': fid, 'kind': 'image', 'filename': original, 'media_type': media,
                'inline_url': inline_url, 'data_uri': data_uri}
    elif ext == '.pdf':
        data_uri = 'data:application/pdf;base64,' + base64.b64encode(plain).decode('ascii')
        return {'ok': True, 'id': fid, 'kind': 'pdf', 'filename': original, 'media_type': 'application/pdf',
                'inline_url': inline_url, 'data_uri': data_uri, 'size_bytes': len(plain)}
    else:
        extracted = _extract_document_text_preview(ext, plain, original)
        return {'ok': True, 'id': fid, 'kind': 'text', 'filename': original, 'media_type': media,
                'inline_url': inline_url, 'size_bytes': len(plain), 'content': extracted}


@app.post('/api/files/{fid}/share')
async def share_file(fid: int, request: Request, background: BackgroundTasks):
    """Share or re-share an existing encrypted file with an accepted contact (F.5)."""
    p = await request.json()
    recipient_name = str(p.get('recipient', '')).strip().lower()
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        f = db.get(VaultFile, fid)
        if not f or f.owner_id != u.id:
            raise Failure('Hanya pemilik file yang dapat mengatur pembagian file.', 403)
        receiver = db.scalar(select(User).where(User.username == recipient_name))
        if not receiver or not accepted_contact(db, u.id, receiver.id):
            raise Failure('Penerima harus merupakan kontak yang sudah disetujui.', 403)
        f.receiver_id = receiver.id
        f.share_revoked = False
        notify(db, receiver.id, None, f'{u.username} membagikan file rahasia kepada Anda', file_id=f.id, category='file')
        log = EmailLog(sender_id=u.id, recipient=receiver.email, sender_name=u.username, file_id=f.id)
        db.add(log)
        db.flush()
        logid = log.id
        ledger_append(db, u.id, 'FILE_SHARED', f'file:{fid}:to:{receiver.id}')
    background.add_task(send_email_job, logid)
    return {'ok': True, 'message': f'Akses file diberikan kepada @{recipient_name}.'}


@app.post('/api/files/{fid}/revoke')
def revoke_file_access(fid: int, request: Request):
    """Revoke recipient's access to a shared file (F.6)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        f = db.get(VaultFile, fid)
        if not f or f.owner_id != u.id:
            raise Failure('Hanya pemilik file yang dapat mencabut akses.', 403)
        f.share_revoked = True
        f.receiver_id = None
        ledger_append(db, u.id, 'FILE_ACCESS_REVOKED', f'file:{fid}')
    return {'ok': True, 'message': 'Akses penerima terhadap file telah dicabut.'}


@app.delete('/api/files/{fid}')
def delete_file(fid: int, request: Request):
    """Delete an encrypted file from File Vault and remove its ciphertext blob from disk (F.1)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        f = db.get(VaultFile, fid)
        if not f or f.owner_id != u.id:
            raise Failure('File tidak ditemukan atau Anda bukan pemiliknya.', 404)
        storage_id = f.storage_id
        db.query(EmailLog).filter(EmailLog.file_id == fid).update({'file_id': None})
        db.query(Notification).filter(Notification.file_id == fid).update({'file_id': None})
        db.delete(f)
        ledger_append(db, u.id, 'FILE_DELETED', f'file:{fid}')
    (STORAGE / storage_id).unlink(missing_ok=True)
    return {'ok': True, 'message': 'File terenkripsi berhasil dihapus.'}


# --- STEGANOGRAPHY ---
@app.post('/api/stego/embed')
async def stego_embed(request: Request, image: UploadFile = File(...), secret: str = Form(...)):
    if not 1 <= len(secret) <= 1000:
        raise Failure('Pesan stego 1 sampai 1000 karakter.')
    raw = await image.read(8 * 1024 * 1024)
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        try:
            png = lsb_embed(raw, secret, MASTER)
        except ValueError as exc:
            raise Failure(str(exc), 400) from exc
        ledger_append(db, u.id, 'STEGO_EMBED', f'bytes:{len(png)}')
    return Response(png, media_type='image/png', headers={'Content-Disposition': 'attachment; filename="chrya_stego.png"'})


@app.post('/api/stego/extract')
async def stego_extract(request: Request, image: UploadFile = File(...)):
    raw = await image.read(8 * 1024 * 1024)
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        try:
            secret = lsb_extract(raw, MASTER, keyring=KEYRING)
        except ValueError as exc:
            raise Failure(str(exc), 400) from exc
        ledger_append(db, u.id, 'STEGO_EXTRACT', 'image:verified')
    return {'ok': True, 'message': secret}


# --- J. BLOCKCHAIN AUDIT LEDGER (Hash Chain Verification, Ed25519 Signed Checkpoints, Backup & External Anchor) ---
@app.get('/api/ledger')
def blockchain(request: Request, actor_only: bool = False):
    with SessionLocal() as db:
        u = require_user(request, db)
        verification = ledger_verify_detailed(db)
        query = select(Ledger).order_by(Ledger.index.desc())
        if actor_only:
            query = query.where(Ledger.actor_id == u.id)
        rows = db.scalars(query.limit(100)).all()
        return {
            'ok': True,
            **verification,
            'items': [{
                'index': x.index,
                'ts': x.ts,
                'actor': x.actor_id,
                'action': x.action,
                'resource': x.resource,
                'previous_hash': x.previous_hash,
                'hash': x.current_hash,
            } for x in rows],
        }


@app.post('/api/ledger/checkpoint')
def create_ledger_checkpoint(request: Request):
    """Create an Ed25519 digitally signed checkpoint and write an external anchor file (J.2, J.5)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        ver = ledger_verify_detailed(db)
        if not ver['valid']:
            raise Failure('Tidak dapat membuat checkpoint: rantai audit saat ini tidak valid / terdeteksi perubahan data.', 409)
        chain = db.scalars(select(Ledger).order_by(Ledger.index)).all()
        if not chain:
            raise Failure('Belum ada blok pada audit ledger.')
        head = chain[-1]
        merkle = compute_merkle_root([b.current_hash for b in chain])
        signed = sign_ledger_checkpoint(head.index, head.current_hash, merkle, MASTER)
        anchor_file = ANCHORS_DIR / f'anchor_block_{head.index}_{int(time.time())}.json'
        anchor_doc = {
            'system': 'CHRYA BOX SHA-256 Hash Chain Anchor',
            'created_by_user': u.id,
            'timestamp': utc_iso_seconds(),
            **signed,
        }
        anchor_file.write_text(json.dumps(anchor_doc, indent=2), encoding='utf-8')
        cp = LedgerCheckpoint(
            up_to_index=head.index,
            block_hash=head.current_hash,
            merkle_root=merkle,
            signature=signed['signature'],
            public_key=signed['public_key'],
            anchor_path=anchor_file.name,
        )
        db.add(cp)
        db.flush()
        cp_id = cp.id
    return {
        'ok': True,
        'checkpoint_id': cp_id,
        'up_to_index': head.index,
        'merkle_root': merkle,
        'signature': signed['signature'],
        'anchor_file': anchor_file.name,
        'message': f'Checkpoint blok #{head.index} berhasil ditandatangani (Ed25519) dan di-anchor.',
    }


@app.get('/api/ledger/export')
def export_ledger_backup(request: Request):
    """Download signed JSON backup of the entire audit log and checkpoints (J.3)."""
    with SessionLocal() as db:
        require_user(request, db)
        ver = ledger_verify_detailed(db)
        chain = db.scalars(select(Ledger).order_by(Ledger.index)).all()
        payload = {
            'exported_at': utc_iso_seconds(),
            'integrity_valid': ver['valid'],
            'merkle_root': ver['merkle_root'],
            'total_blocks': len(chain),
            'blocks': [{
                'index': b.index, 'ts': b.ts, 'actor_id': b.actor_id,
                'action': b.action, 'resource': b.resource,
                'previous_hash': b.previous_hash, 'current_hash': b.current_hash,
            } for b in chain],
            'checkpoints': ver['checkpoints'],
        }
    raw = json.dumps(payload, indent=2).encode('utf-8')
    return Response(raw, media_type='application/json', headers={
        'Content-Disposition': 'attachment; filename="chrya_ledger_backup.json"',
        'Cache-Control': 'no-store',
    })


# --- H. NOTIFICATION SYSTEM (Read, Mark All Read, Delete, Filter Unread, SMTP Retry) ---
@app.get('/api/notifications')
def notifications(request: Request, unread_only: bool = False):
    with SessionLocal() as db:
        u = require_user(request, db)
        query = select(Notification).where(Notification.user_id == u.id)
        if unread_only:
            query = query.where(Notification.read == False)
        rows = db.scalars(query.order_by(Notification.id.desc()).limit(60)).all()
        logs = db.scalars(select(EmailLog).where(EmailLog.sender_id == u.id).order_by(EmailLog.id.desc()).limit(25)).all()
        unread_count = db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id == u.id, Notification.read == False))
        return {
            'ok': True,
            'unread_count': unread_count,
            'items': [{
                'id': n.id,
                'text': n.text,
                'category': n.category or 'general',
                'message_id': n.message_id,
                'file_id': n.file_id,
                'read': bool(n.read),
                'created_at': timestamp(n.created_at),
            } for n in rows],
            'email_logs': [{
                'id': l.id,
                'recipient': l.recipient,
                'status': l.status,
                'error': l.error,
                'attempts': l.attempts,
                'created_at': timestamp(l.created_at),
            } for l in logs],
        }


@app.post('/api/notifications/{nid}/read')
def mark_notification_read(nid: int, request: Request):
    """Mark a single notification as read (H.1)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        n = db.get(Notification, nid)
        if not n or n.user_id != u.id:
            raise Failure('Notifikasi tidak ditemukan.', 404)
        n.read = True
    return {'ok': True}


@app.post('/api/notifications/read-all')
def mark_all_notifications_read(request: Request):
    """Mark all notifications of the current user as read (H.2)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        db.query(Notification).filter(Notification.user_id == u.id, Notification.read == False).update({'read': True})
    return {'ok': True}


@app.delete('/api/notifications/{nid}')
def delete_notification(nid: int, request: Request):
    """Delete a notification (H.3)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        n = db.get(Notification, nid)
        if not n or n.user_id != u.id:
            raise Failure('Notifikasi tidak ditemukan.', 404)
        db.delete(n)
    return {'ok': True}


@app.post('/api/notifications/email/{logid}/retry')
def retry_email(logid: int, request: Request, background: BackgroundTasks):
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        log = db.get(EmailLog, logid)
        if not log or log.sender_id != u.id:
            raise Failure('Tidak berwenang mengirim ulang email ini.', 403)
        if log.status == 'sent' or log.attempts >= 3:
            raise Failure('Email sudah terkirim atau batas percobaan tercapai.')
        log.status = 'pending'
    background.add_task(send_email_job, logid)
    return {'ok': True, 'message': 'Permintaan kirim ulang notifikasi diterima.'}


# --- I. SECURITY CENTER & KEY / DATABASE MANAGEMENT ---
@app.get('/api/security/overview')
def security_overview(request: Request):
    """Return active sessions, login history, passkeys, USB keys, face status, and key rotation info."""
    with SessionLocal.begin() as db:
        u = require_user(request, db)
        cur_hash = digest(request.cookies.get('chrya_sid', ''))
        now_ts = int(time.time())
        sessions = db.scalars(select(UserSession).where(
            UserSession.user_id == u.id, UserSession.expires > now_ts
        ).order_by(UserSession.last_active.desc())).all()
        history = db.scalars(select(LoginHistory).where(
            LoginHistory.user_id == u.id
        ).order_by(LoginHistory.id.desc()).limit(25)).all()
        creds = db.scalars(select(Credential).where(Credential.user_id == u.id).order_by(Credential.id.desc())).all()
        usb_keys = db.scalars(select(UserUSBKey).where(UserUSBKey.user_id == u.id).order_by(UserUSBKey.id.desc())).all()
        face = valid_face_template(db, u.id)
        recovery_list = json.loads(u.recovery_code_hashes or '[]')
        return {
            'ok': True,
            'active_sessions': [{
                'session_id': s.session_id or s.token_hash[:12],
                'device_name': s.device_name or 'Web Browser',
                'ip_address': s.ip_address or '127.0.0.1',
                'user_agent': s.user_agent or '',
                'created_at': timestamp(s.created_at),
                'last_active': timestamp(s.last_active),
                'is_current': s.token_hash == cur_hash,
            } for s in sessions],
            'login_history': [{
                'id': h.id,
                'ip_address': h.ip_address,
                'device_name': h.device_name,
                'method': h.method,
                'status': h.status,
                'suspicious': bool(h.suspicious),
                'reason': h.reason,
                'created_at': timestamp(h.created_at),
            } for h in history],
            'passkeys': [{
                'id': c.id,
                'name': c.name or f'Passkey #{c.id}',
                'sign_count': c.sign_count,
                'created_at': timestamp(c.created_at),
            } for c in creds],
            'usb_keys': [{
                'id': k.id,
                'key_id': k.key_id,
                'label': k.label,
                'volume_serial': k.volume_serial,
                'status': k.status,
                'created_at': timestamp(k.created_at),
                'revoked_at': timestamp(k.revoked_at),
            } for k in usb_keys],
            'face': {
                'enrolled': bool(face),
                'model_version': face.model_version if face else None,
                'created_at': timestamp(face.created_at) if face else '',
            },
            'recovery_codes_remaining': len(recovery_list),
            'key_management': {
                'current_kid': KEYRING.current_kid,
                'total_key_versions': len(KEYRING.keys),
                'domains': ['SUBJECT', 'BODY', 'FILE', 'NOTE_TITLE', 'NOTE_BODY', 'FACE', 'STEGO', 'USB_SECRET'],
            },
        }


@app.post('/api/security/password')
async def change_password(request: Request):
    """Change user password with current password verification and revoke other sessions (I.1)."""
    p = await request.json()
    current_pw = str(p.get('current_password', ''))
    new_pw = str(p.get('new_password', ''))
    if len(new_pw) < 12 or len(new_pw) > 256:
        raise Failure('Password baru minimal 12 karakter (maksimal 256).')
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        try:
            PASSWORD_HASHER.verify(u.password_hash, current_pw)
        except (VerifyMismatchError, VerificationError) as exc:
            raise Failure('Password saat ini salah.', 401) from exc
        if current_pw == new_pw:
            raise Failure('Password baru tidak boleh sama dengan password lama.')
        u.password_hash = PASSWORD_HASHER.hash(new_pw)
        cur_hash = digest(request.cookies.get('chrya_sid', ''))
        db.query(UserSession).filter(UserSession.user_id == u.id, UserSession.token_hash != cur_hash).delete()
        ledger_append(db, u.id, 'PASSWORD_CHANGED', f'user:{u.id}')
    return {'ok': True, 'message': 'Password berhasil diperbarui dan sesi perangkat lain telah dikeluarkan.'}


@app.post('/api/security/sessions/logout-all')
def logout_all_devices(request: Request):
    """Revoke all active login sessions across all devices (I.2)."""
    p = {}
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        cur_hash = digest(request.cookies.get('chrya_sid', ''))
        keep_current = request.query_params.get('keep_current', 'false').lower() == 'true'
        q = db.query(UserSession).filter(UserSession.user_id == u.id)
        if keep_current:
            q = q.filter(UserSession.token_hash != cur_hash)
        deleted = q.delete()
        ledger_append(db, u.id, 'LOGOUT_ALL_DEVICES', f'user:{u.id}:sessions:{deleted}')
    r = JSONResponse({'ok': True, 'revoked': deleted, 'message': 'Seluruh sesi perangkat berhasil dikeluarkan.'})
    if not keep_current:
        r.delete_cookie('chrya_sid', path='/')
    return r


@app.delete('/api/security/sessions/{session_id}')
def revoke_specific_session(session_id: str, request: Request):
    """Revoke a specific logged-in device session (I.3)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        rows = db.scalars(select(UserSession).where(UserSession.user_id == u.id)).all()
        target = next((s for s in rows if s.session_id == session_id or s.token_hash.startswith(session_id)), None)
        if not target:
            raise Failure('Sesi perangkat tidak ditemukan.', 404)
        db.delete(target)
        ledger_append(db, u.id, 'SESSION_REVOKED', f'session:{session_id[:12]}')
    return {'ok': True, 'message': 'Sesi perangkat berhasil dihentikan.'}


@app.delete('/api/security/passkey/{cid}')
def delete_passkey(cid: int, request: Request):
    """Delete a registered WebAuthn passkey (I.5)."""
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        cred = db.get(Credential, cid)
        if not cred or cred.user_id != u.id:
            raise Failure('Passkey tidak ditemukan.', 404)
        db.delete(cred)
        ledger_append(db, u.id, 'PASSKEY_DELETED', f'cred:{cid}')
    return {'ok': True, 'message': 'Passkey berhasil dihapus.'}


# --- B & I.8: USB KEY MANAGEMENT (Re-registration, Revocation of Old USB, Lost/Damaged USB Handling) ---
@app.post('/api/security/usb/issue')
async def issue_user_usb_key(request: Request):
    """Generate a new 32-byte USB key for the user, optionally revoking old keys, and return it for saving to flashdisk (B.4, B.5, I.8)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    label = str(p.get('label', 'Personal USB Vault Key')).strip()[:80] or 'Personal USB Vault Key'
    revoke_old = bool(p.get('revoke_old', True))
    sync_host_drive = str(p.get('host_drive', '')).strip()
    with SessionLocal.begin() as db:
        u = recent_session(db, request, password=p.get('password'))
        if revoke_old:
            old_keys = db.scalars(select(UserUSBKey).where(UserUSBKey.user_id == u.id, UserUSBKey.status == 'active')).all()
            for ok in old_keys:
                ok.status = 'revoked'
                ok.revoked_at = now()
        raw_token = secrets.token_bytes(32)
        vol_serial = get_volume_serial(INSTANCE)
        if sync_host_drive:
            drive_path = Path(sync_host_drive)
            if drive_path.is_dir():
                (drive_path / 'chrya_usb.key').write_bytes(raw_token)
                vol_serial = get_volume_serial(drive_path)
        key_id = secrets.token_hex(8)
        uk = UserUSBKey(
            user_id=u.id,
            key_id=key_id,
            label=label,
            secret_ciphertext=encrypt_domain_text(b64(raw_token), 'USB_SECRET'),
            digest=usb_sha256(raw_token),
            volume_serial=vol_serial,
            status='active',
        )
        db.add(uk)
        db.flush()
        ledger_append(db, u.id, 'USB_KEY_ISSUED', f'key_id:{key_id}')
    return {
        'ok': True,
        'key_id': key_id,
        'label': label,
        'key_b64': b64(raw_token),
        'filename': 'chrya_usb.key',
        'message': 'Kunci USB baru berhasil dibuat. Simpan file chrya_usb.key ke flashdisk Anda.',
    }


@app.post('/api/security/usb/rotate-host')
async def rotate_host_usb_dongle(request: Request):
    """Re-enroll/rotate the server host USB dongle and revoke the old dongle digest (B.4, B.5)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    with SessionLocal.begin() as db:
        u = recent_session(db, request, password=p.get('password'))
        reg = GUARD._read_registry()
        target_dir = Path(p.get('drive') or Path(reg.get('path', str(INSTANCE / 'chrya_usb.key'))).parent)
        info = GUARD.rotate_or_replace(target_dir)
        raw_token = ( Path(info['path']) ).read_bytes()
        ledger_append(db, u.id, 'HOST_USB_ROTATED', f"key_id:{info['key_id']}")
    return {
        'ok': True,
        **info,
        'key_b64': b64(raw_token),
        'message': 'USB Dongle host berhasil diregistrasi ulang dan token USB lama telah dicabut.',
    }


@app.post('/api/security/usb/{kid}/revoke')
async def revoke_user_usb_key(kid: int, request: Request):
    """Revoke a specific USB key or report it lost/damaged so it can never be used again (B.5, B.6)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    reason_status = 'lost' if p.get('reason') == 'lost' else 'revoked'
    with SessionLocal.begin() as db:
        u = require_user(request, db, True)
        row = db.get(UserUSBKey, kid)
        if not row or row.user_id != u.id:
            raise Failure('Kunci USB tidak ditemukan.', 404)
        row.status = reason_status
        row.revoked_at = now()
        ledger_append(db, u.id, f'USB_KEY_{reason_status.upper()}', f'key_id:{row.key_id}')
    return {'ok': True, 'status': reason_status, 'message': f'USB Key ({row.key_id}) telah ditandai {reason_status} dan dicabut aksesnya.'}


# --- I.7 & B.6: ACCOUNT RECOVERY & LOST USB / BIOMETRIC RESET ---
@app.post('/api/security/recovery/generate')
async def generate_recovery_codes(request: Request):
    """Generate 6 single-use emergency recovery codes (hashed with Argon2id/SHA256) for account/USB/biometric recovery (I.7, B.6)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    with SessionLocal.begin() as db:
        u = recent_session(db, request, password=p.get('password'))
        plain_codes = [f'CHRYA-{secrets.token_hex(3).upper()}-{secrets.token_hex(3).upper()}' for _ in range(6)]
        hashed_codes = [digest(c) for c in plain_codes]
        u.recovery_code_hashes = json.dumps(hashed_codes)
        ledger_append(db, u.id, 'RECOVERY_CODES_GENERATED', f'user:{u.id}')
    return {
        'ok': True,
        'codes': plain_codes,
        'message': 'Simpan kode pemulihan darurat ini di tempat aman. Setiap kode hanya berlaku satu kali.',
    }


@app.post('/api/auth/recover')
async def recover_account(request: Request):
    """Recover account using username + recovery code when password, face, or personal USB key is lost/damaged (I.7, B.6)."""
    p = await request.json()
    identity = str(p.get('identity', '')).strip().lower()
    code = str(p.get('recovery_code', '')).strip().upper()
    new_password = p.get('new_password')
    reset_face = bool(p.get('reset_face', False))
    revoke_personal_usb = bool(p.get('revoke_usb', False))
    if not identity or not code:
        raise Failure('Masukkan username/email dan kode pemulihan.')
    with SessionLocal.begin() as db:
        u = db.scalar(select(User).where(or_(User.username == identity, User.email == identity)))
        if not u:
            raise Failure('Identitas atau kode pemulihan tidak valid.', 401)
        stored_hashes = json.loads(u.recovery_code_hashes or '[]')
        code_hash = digest(code)
        if code_hash not in stored_hashes:
            record_login_event(db, request, user_id=u.id, username=u.username, method='recovery_code', status='failed', reason='Kode pemulihan salah')
            raise Failure('Identitas atau kode pemulihan tidak valid.', 401)
        stored_hashes.remove(code_hash)
        u.recovery_code_hashes = json.dumps(stored_hashes)
        u.failure_count = 0
        u.locked_until = 0
        u.face_failure_count = 0
        u.face_locked_until = 0
        if new_password:
            if not isinstance(new_password, str) or len(new_password) < 12:
                raise Failure('Password baru minimal 12 karakter.')
            u.password_hash = PASSWORD_HASHER.hash(new_password)
        if reset_face:
            db.query(FaceTemplate).filter(FaceTemplate.user_id == u.id).delete()
        if revoke_personal_usb:
            for uk in db.scalars(select(UserUSBKey).where(UserUSBKey.user_id == u.id, UserUSBKey.status == 'active')).all():
                uk.status = 'lost'
                uk.revoked_at = now()
        db.query(UserSession).filter(UserSession.user_id == u.id).delete()
        token = secrets.token_urlsafe(32)
        has_face = bool(valid_face_template(db, u.id))
        db.add(Flow(token_hash=digest(token), user_id=u.id, kind='register' if not has_face else 'login', expires=int(time.time()) + 600))
        record_login_event(db, request, user_id=u.id, username=u.username, method='recovery_code', status='success', reason='Pemulihan akun darurat')
        ledger_append(db, u.id, 'ACCOUNT_RECOVERED', f'user:{u.id}')
    return {
        'ok': True,
        'flow': token,
        'stage': 'usb',
        'setup': not has_face,
        'message': 'Pemulihan akun berhasil diverifikasi. Lanjutkan verifikasi USB dan wajah.',
    }


# --- C.8, C.9 & K.4: MASTER KEY BACKUP, KEY ROTATION & DATABASE BACKUP ---
@app.post('/api/security/keys/rotate')
async def rotate_encryption_key(request: Request):
    """Rotate active encryption key version in KeyRing and optionally re-encrypt user notes/messages (C.9)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    with SessionLocal.begin() as db:
        u = recent_session(db, request, password=p.get('password'))
        new_kid = KEYRING.rotate()
        # Re-encrypt user's vault notes seamlessly to the new key version
        notes_rows = db.scalars(select(VaultNote).where(VaultNote.owner_id == u.id)).all()
        for n in notes_rows:
            t_plain = decrypt_domain_text(n.title_ciphertext, 'NOTE_TITLE')
            b_plain = decrypt_domain_text(n.body_ciphertext, 'NOTE_BODY')
            n.title_ciphertext = encrypt_domain_text(t_plain, 'NOTE_TITLE')
            n.body_ciphertext = encrypt_domain_text(b_plain, 'NOTE_BODY')
        ledger_append(db, u.id, 'KEY_ROTATED', f'kid:{new_kid}')
    return {
        'ok': True,
        'current_kid': new_kid,
        'message': f'Rotasi kunci enkripsi berhasil (aktif: v{new_kid}). Data lama tetap dapat didekripsi dan catatan Anda telah diperbarui ke kunci baru.',
    }


@app.post('/api/security/keys/backup')
async def backup_master_key(request: Request):
    """Export passphrase-encrypted backup of master.key and keyring (C.8)."""
    p = await request.json()
    passphrase = str(p.get('passphrase', ''))
    with SessionLocal.begin() as db:
        u = recent_session(db, request, password=p.get('password'))
        keyring_doc = json.loads(KEYRING.keyring_path.read_text(encoding='utf-8')) if KEYRING.keyring_path.is_file() else {}
        try:
            blob = export_master_key_backup(MASTER, passphrase, keyring_doc)
        except ValueError as exc:
            raise Failure(str(exc), 400) from exc
        backup_file = BACKUPS_DIR / f'master_key_backup_{int(time.time())}.enc.json'
        backup_file.write_bytes(blob)
        ledger_append(db, u.id, 'MASTER_KEY_BACKUP', f'file:{backup_file.name}')
    return Response(blob, media_type='application/json', headers={
        'Content-Disposition': 'attachment; filename="chrya_master_key_backup.enc.json"',
        'Cache-Control': 'no-store',
    })


@app.post('/api/security/database/backup')
async def create_database_backup(request: Request):
    """Create a consistent hot backup of the SQLite database / schema dump in instance/backups (K.4)."""
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    with SessionLocal.begin() as db:
        u = recent_session(db, request, password=p.get('password'))
        ts_label = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        if DB_URL.startswith('sqlite:///'):
            import sqlite3
            db_path = Path(DB_URL.replace('sqlite:///', '', 1))
            dest = BACKUPS_DIR / f'chrya_db_backup_{ts_label}.sqlite3'
            if db_path.is_file():
                src_conn = sqlite3.connect(str(db_path))
                dst_conn = sqlite3.connect(str(dest))
                with dst_conn:
                    src_conn.backup(dst_conn)
                dst_conn.close()
                src_conn.close()
            else:
                dest.write_bytes(b'')
        else:
            dest = BACKUPS_DIR / f'chrya_db_snapshot_{ts_label}.json'
            users_count = db.scalar(select(func.count()).select_from(User))
            dest.write_text(json.dumps({'timestamp': ts_label, 'users': users_count}), encoding='utf-8')
        ledger_append(db, u.id, 'DATABASE_BACKUP', f'backup:{dest.name}')
    return {
        'ok': True,
        'backup_file': dest.name,
        'size_bytes': dest.stat().st_size if dest.is_file() else 0,
        'message': f'Backup database berhasil disimpan di instance/backups/{dest.name}.',
    }


if __name__ == '__main__':
    import uvicorn
    ssl_cert = os.getenv('CHRYA_SSL_CERTFILE', '').strip()
    ssl_key = os.getenv('CHRYA_SSL_KEYFILE', '').strip()
    print('CHRYA BOX |', ORIGIN, '| dongle:', GUARD.status()['reason'])
    print('Biometrik di HP perlu HTTPS. Flashdisk USB standar bukan kunci FIDO2.')
    uvicorn_kwargs: dict[str, Any] = {
        'host': os.getenv('CHRYA_HOST', '127.0.0.1'),
        'port': int(os.getenv('CHRYA_PORT', '8765')),
    }
    if ssl_cert and ssl_key and Path(ssl_cert).is_file() and Path(ssl_key).is_file():
        uvicorn_kwargs['ssl_certfile'] = ssl_cert
        uvicorn_kwargs['ssl_keyfile'] = ssl_key
        print('HTTPS TLS aktif menggunakan sertifikat:', ssl_cert)
    uvicorn.run(app, **uvicorn_kwargs)
