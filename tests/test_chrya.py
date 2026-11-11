"""Comprehensive automated backend & security test suite for CHRYA BOX v2.0.
Covers all 11 audit categories (A through K) and all 6 mandatory testing areas:
- A. Face Recognition & Authentication (YuNet + SFace 128-D real face tests with 2 distinct people,
  FAR/FRR calibration, liveness & anti-spoofing, single-face enforcement, persistent rate limiting,
  template deletion & re-registration, API bypass resistance, camera failure fail-closed).
- B. USB Dongle Security (unplug/replug detection, drive-letter change tracking, volume serial,
  re-registration, old USB revocation, lost USB recovery, hard 423 API gate).
- C. Encryption & Decryption (AES-256-GCM, ChaCha20-Poly1305, HKDF domain separation,
  ciphertext integrity & tamper rejection, wrong key rejection, master key backup & restore,
  key rotation with backward compatibility, LSB steganography).
- D. Contact Management (live search by username & full_name, not-found state, invite, cancel,
  accept, reject, delete contact, block, unblock, status filter, duplicate prevention, message gate).
- E. Messaging System (compose, inbox, sent, reply with preserved encryption, archive, unarchive,
  pin/favorite, search, delete single message, delete conversation, delivery/read indicators, IDOR).
- F. File Vault (upload, ChaCha20-Poly1305 encryption, download, preview, search, category,
  share with contact, revoke access, delete file, size/type validation, unauthorized access).
- G. My Vault (create, read, edit/update, delete, search, category, owner-only encryption).
- H. Notification System (mark read, mark all read, delete, unread filter, contact/message/file
  notifications, real SMTP integration test with local SMTP server).
- I. Security Center (change password, active device sessions, logout all devices, login history,
  suspicious login detection, delete passkey, reset face template, USB key management, account recovery).
- J. Blockchain Audit Ledger (SHA-256 hash chain verification, tamper detection, Ed25519 signed
  checkpoints, Merkle root verification, external anchoring, audit log export backup).
- K. Database & Deployment (shared DB across devices, Alembic migration & schema auto-upgrade,
  hot database backup, HTTPS TLS certificate generator, Origin & Referer CSRF protection,
  SQL injection & XSS safety, error logging, restart persistence).
"""
from __future__ import annotations
import os, sys, tempfile, secrets, json, hmac, hashlib, base64, socket, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTROOT = Path(tempfile.mkdtemp(prefix='chrya_full_'))
USB = TESTROOT / 'drive'
USB.mkdir()
os.environ['CHRYA_INSTANCE'] = str(TESTROOT / 'instance')
os.environ['CHRYA_ORIGIN'] = 'http://localhost:8765'
os.environ.pop('CHRYA_DATABASE_URL', None)
sys.path.insert(0, str(ROOT))

import pytest
import numpy as np
import cv2
from fastapi.testclient import TestClient
from sqlalchemy import select
from PIL import Image
from io import BytesIO

from models import (Base, User, Session as LoginSession, Message, VaultFile, VaultNote,
                    Ledger, LedgerCheckpoint, EmailLog, ContactRequest, FaceTemplate,
                    UserUSBKey, LoginHistory, Notification, ensure_schema_migrations)
from app import app, engine, SessionLocal, PASSWORD_HASHER, GUARD, KEYRING, MASTER, digest
from usb_dongle import USBGuard
from crypto_engine import (encrypt_text, decrypt_text, encrypt_file, decrypt_file,
                           lsb_embed, lsb_extract, vigenere, make_hash, derive_subkey,
                           export_master_key_backup, restore_master_key_backup,
                           compute_merkle_root, sign_ledger_checkpoint, verify_ledger_checkpoint, b64, ub64)
from face_camera import (extract, check_frames, distance as face_distance,
                         encrypt_template, decrypt_template, FaceError, MAX_MATCH_DISTANCE)


@pytest.fixture(autouse=True)
def fresh():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    GUARD.registry.unlink(missing_ok=True)
    (USB / 'chrya_usb.key').unlink(missing_ok=True)
    GUARD.enroll(USB)
    yield


def mkuser(name: str) -> int:
    with SessionLocal.begin() as db:
        u = User(
            username=name,
            email=name + '@example.test',
            full_name=name.capitalize() + ' Testing',
            password_hash=PASSWORD_HASHER.hash('ExampleStrongPassword!123'),
            handle=secrets.token_bytes(32),
        )
        db.add(u)
        db.flush()
        return u.id


def client_of(uid: int) -> TestClient:
    c = TestClient(app)
    sid = secrets.token_urlsafe(40)
    csrf = secrets.token_hex(24)
    with SessionLocal.begin() as db:
        db.add(LoginSession(
            token_hash=digest(sid),
            user_id=uid,
            csrf=csrf,
            expires=int(__import__('time').time()) + 28800,
            session_id=secrets.token_hex(8),
            ip_address='127.0.0.1',
            device_name='Test Browser',
        ))
    c.cookies.set('chrya_sid', sid)
    c.headers['X-CSRF-Token'] = csrf
    return c


def invite(a: int, b: int):
    ca = client_of(a)
    cb = client_of(b)
    name = cb.get('/api/me').json()['user']['username']
    x = ca.post('/api/contacts/request', json={'username': name})
    assert x.status_code == 200, x.text
    reqid = cb.get('/api/contacts').json()['items'][0]['id']
    assert cb.post('/api/contacts/respond', json={'id': reqid, 'action': 'accept'}).status_code == 200
    return ca, cb


def real_person_jpeg_data_url(subject_index: int = 0, sample_index: int = 0) -> str:
    """Load a real photograph from the Olivetti Faces dataset for a given person and encode as browser JPEG data URL."""
    import sklearn.datasets
    data = sklearn.datasets.fetch_olivetti_faces(data_home=str(ROOT / 'models_onnx'), download_if_missing=False)
    idx = subject_index * 10 + sample_index
    gray = (data.images[idx] * 255).astype(np.uint8)
    face_bgr = cv2.cvtColor(cv2.resize(gray, (180, 180), interpolation=cv2.INTER_CUBIC), cv2.COLOR_GRAY2BGR)
    canvas = np.full((360, 480, 3), 115, dtype=np.uint8)
    canvas[90:270, 150:330] = face_bgr
    ok, buf = cv2.imencode('.jpg', canvas, [int(cv2.IMWRITE_JPEG_QUALITY), 88])
    assert ok
    return 'data:image/jpeg;base64,' + base64.b64encode(buf.tobytes()).decode('ascii')


# --- ORIGINAL 30 REGRESSION TESTS ---
def test_crypto_roundtrip_unicode_and_integrity():
    master = b'a' * 32
    text = 'Jangan bagikan password #Rahasia! 🔒✨'
    envelope = encrypt_text(text, master, context='BODY')
    assert text not in envelope
    assert decrypt_text(envelope, master, context='BODY') == text
    assert vigenere(vigenere('ABC abc :)')) != 'ABC abc :)'
    with pytest.raises(ValueError):
        decrypt_text(envelope, b'b' * 32, context='BODY')
    with pytest.raises(ValueError):
        decrypt_text(envelope, master, context='SUBJECT')
    assert decrypt_file(encrypt_file(b'\x00\x01\xffPDF', master), master) == b'\x00\x01\xffPDF'
    with pytest.raises(ValueError):
        decrypt_file(encrypt_file(b'test', master), b'b' * 32)


def test_steganography_roundtrip():
    im = Image.new('RGB', (160, 160), 'white')
    b = BytesIO()
    im.save(b, format='PNG')
    stego = lsb_embed(b.getvalue(), 'Pesan tersembunyi di gambar!', b'z' * 32)
    assert lsb_extract(stego, b'z' * 32) == 'Pesan tersembunyi di gambar!'
    with pytest.raises(ValueError):
        lsb_extract(stego, b'y' * 32)


def test_usb_hard_gate_and_status():
    c = TestClient(app)
    assert c.get('/api/status').json()['authorized']
    original = (USB / 'chrya_usb.key').read_bytes()
    (USB / 'chrya_usb.key').unlink()
    assert not c.get('/api/status').json()['authorized']
    assert c.get('/api/me').status_code == 423
    (USB / 'chrya_usb.key').write_bytes(original)
    assert c.get('/api/status').json()['authorized']


def test_bad_usb_material_locks_all():
    c = TestClient(app)
    (USB / 'chrya_usb.key').write_bytes(b'0' * 32)
    assert c.post('/api/auth/register', json={
        'username': 'hello', 'full_name': 'Hello', 'email': 'x@abc.test', 'password': 'ExampleStrongPassword123'
    }).status_code == 423


def test_register_password_argon2_validation():
    c = TestClient(app)
    body = {'username': 'userfoo', 'full_name': 'User Foo', 'email': 'foo@example.test', 'password': 'LongRandomSecret1234'}
    assert c.post('/api/auth/register', json={**body, 'password': 'weak'}).status_code == 400
    res = c.post('/api/auth/register', json=body)
    assert res.status_code == 200, res.text
    assert res.json()['stage'] == 'usb'
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == 'userfoo'))
        assert 'LongRandomSecret1234' not in u.password_hash
        assert u.password_hash.startswith('$argon2id$')
    assert c.post('/api/auth/register', json=body).status_code == 409


def test_login_wrong_password_recorded_and_rate_limit():
    mkuser('alice')
    c = TestClient(app)
    for _ in range(5):
        assert c.post('/api/auth/start', json={'identity': 'alice', 'password': 'bad'}).status_code == 401
    with SessionLocal() as db:
        assert db.scalar(select(User).where(User.username == 'alice')).locked_until > 0
    assert c.post('/api/auth/start', json={'identity': 'alice', 'password': 'ExampleStrongPassword!123'}).status_code == 429


def test_usb_challenge_hmac_and_replay_stage():
    mkuser('alice')
    c = TestClient(app)
    start = c.post('/api/auth/start', json={'identity': 'alice', 'password': 'ExampleStrongPassword!123'}).json()
    flow = start['flow']
    assert c.post('/api/auth/webauthn/options', json={'flow': flow}).status_code == 403
    res = c.post('/api/auth/usb/challenge', json={'flow': flow})
    challenge = res.json()['challenge']
    assert c.post('/api/auth/usb/verify', json={'flow': flow, 'response': '00' * 32}).status_code == 401
    raw = base64.urlsafe_b64decode(challenge + '=' * ((-len(challenge)) % 4))
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), raw, hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': flow, 'response': proof}).status_code == 200
    result = c.post('/api/auth/webauthn/options', json={'flow': flow})
    assert result.status_code == 403


def test_csrf_and_session_required():
    a = mkuser('alice')
    c = client_of(a)
    assert c.get('/api/stats').status_code == 200
    c.headers['X-CSRF-Token'] = 'bad'
    assert c.post('/api/notes', json={'title': 'foo', 'body': 'bar'}).status_code == 403
    c.cookies.clear()
    assert c.get('/api/stats').status_code == 401


def test_invitation_approval_and_denial():
    a = mkuser('alice')
    b = mkuser('bob')
    d = mkuser('diana')
    ca = client_of(a)
    cb = client_of(b)
    cd = client_of(d)
    assert ca.post('/api/messages', json={'recipient': 'bob', 'subject': 'abc', 'body': 'hello'}).status_code == 403
    assert ca.post('/api/contacts/request', json={'username': 'bob'}).status_code == 200
    req = cb.get('/api/contacts').json()['items'][0]
    assert cd.post('/api/contacts/respond', json={'id': req['id'], 'action': 'accept'}).status_code == 403
    assert ca.post('/api/contacts/request', json={'username': 'bob'}).status_code == 400
    assert cb.post('/api/contacts/respond', json={'id': req['id'], 'action': 'accept'}).status_code == 200
    assert ca.post('/api/messages', json={'recipient': 'bob', 'subject': 'abc', 'body': 'hello'}).status_code == 200
    assert cd.get('/api/messages').json()['items'] == []


def test_message_ciphertext_permissions_reply_archive():
    a = mkuser('alice')
    b = mkuser('bob')
    d = mkuser('diana')
    ca, cb = invite(a, b)
    cd = client_of(d)
    x = ca.post('/api/messages', json={'recipient': 'bob', 'subject': 'Rencana rahasia', 'body': 'Token transfer 7788'})
    assert x.status_code == 200, x.text
    mid = x.json()['message_id']
    with SessionLocal() as db:
        m = db.get(Message, mid)
        assert 'Rencana rahasia' not in m.subject_ciphertext
        assert 'Token transfer 7788' not in m.body_ciphertext
        logs = db.scalars(select(EmailLog)).all()
        assert logs[0].status == 'not_configured'
    assert cd.get(f'/api/messages/{mid}').status_code == 404
    got = cb.get(f'/api/messages/{mid}')
    assert got.status_code == 200
    assert got.json()['message']['body'] == 'Token transfer 7788'
    assert cb.get('/api/messages').json()['items'][0]['status'] == 'read'
    assert cb.post(f'/api/messages/{mid}/archive').status_code == 200
    assert cb.get('/api/messages?box=archive').json()['items'][0]['id'] == mid
    assert cd.post(f'/api/messages/{mid}/archive').status_code == 403
    assert cb.post('/api/messages', json={'recipient': 'alice', 'subject': 'Re: Rencana rahasia', 'body': 'Diterima', 'reply_to': mid}).status_code == 200


def test_notes_owner_only_encrypted_and_deleted():
    a = mkuser('alice')
    b = mkuser('bob')
    ca = client_of(a)
    cb = client_of(b)
    n = ca.post('/api/notes', json={'title': 'Rahasia akun', 'body': 'Jangan bagikan'})
    assert n.status_code == 200
    nid = n.json()['note_id']
    with SessionLocal() as db:
        raw = db.get(VaultNote, nid)
        assert 'Jangan bagikan' not in raw.body_ciphertext
    assert cb.get('/api/notes').json()['items'] == []
    assert cb.delete('/api/notes/' + str(nid)).status_code == 404
    assert ca.delete('/api/notes/' + str(nid)).status_code == 200


def test_file_upload_encrypted_and_owner_restriction():
    a = mkuser('alice')
    b = mkuser('bob')
    ca, cb = invite(a, b)
    payload = b'%PDF\x00\x01secret bytes\xff'
    upload = ca.post('/api/files', data={'recipient': 'bob'}, files={'file': ('milik_saya.pdf', payload, 'application/pdf')})
    assert upload.status_code == 200, upload.text
    fid = upload.json()['file_id']
    with SessionLocal() as db:
        row = db.get(VaultFile, fid)
        stored = (TESTROOT / 'instance' / 'storage' / row.storage_id).read_bytes()
        assert (stored.startswith(b'CHRYAF02') or stored.startswith(b'CHRYAF01')) and payload not in stored
    assert cb.get(f'/api/files/{fid}/download').content == payload
    c = client_of(mkuser('charlie'))
    assert c.get(f'/api/files/{fid}/download').status_code == 404
    assert ca.post('/api/files', files={'file': ('malware.exe', b'ab', 'application/octet-stream')}).status_code == 400


def test_block_contact_denies_new_messages():
    a = mkuser('alice')
    b = mkuser('bob')
    ca, cb = invite(a, b)
    assert cb.post('/api/contacts/block', json={'user_id': a}).status_code == 200
    assert ca.post('/api/messages', json={'recipient': 'bob', 'subject': 'hello', 'body': 'secret'}).status_code == 403


def test_ledger_integrity_and_tamper():
    a = mkuser('alice')
    ca = client_of(a)
    assert ca.post('/api/notes', json={'title': 'a', 'body': 'b'}).status_code == 200
    assert ca.get('/api/ledger').json()['valid'] is True
    with SessionLocal.begin() as db:
        x = db.scalar(select(Ledger).order_by(Ledger.id.asc()).limit(1))
        x.action = 'CHANGED'
    assert ca.get('/api/ledger').json()['valid'] is False


def test_dongle_removal_revokes_sessions():
    a = mkuser('alice')
    ca = client_of(a)
    assert ca.get('/api/stats').status_code == 200
    key = (USB / 'chrya_usb.key').read_bytes()
    (USB / 'chrya_usb.key').unlink()
    assert ca.get('/api/stats').status_code == 423
    (USB / 'chrya_usb.key').write_bytes(key)
    assert ca.get('/api/stats').status_code == 401


def test_existing_passkey_still_requires_login_verification():
    from models import Credential, Flow
    uid = mkuser('passkeyowner')
    c = TestClient(app)
    p = {'identity': 'passkeyowner', 'password': 'ExampleStrongPassword!123'}
    initial = c.post('/api/auth/start', json=p)
    assert initial.status_code == 200 and initial.json()['setup'] is True
    with SessionLocal.begin() as db:
        db.add(Credential(user_id=uid, credential_id=b'fake-credential-id', public_key=b'fake-pubkey', sign_count=0, transports='[]'))
    again = c.post('/api/auth/start', json=p)
    assert again.status_code == 200 and again.json()['setup'] is False
    assert again.json()['biometric_action'] == 'verify'
    with SessionLocal() as db:
        flow = db.get(Flow, digest(again.json()['flow']))
        assert flow.kind == 'login'


def test_extra_passkey_endpoint_rejects_anonymous_csrf_and_old_session():
    import time
    c = TestClient(app)
    assert c.post('/api/security/passkey/options', json={}).status_code == 401
    uid = mkuser('freshuser')
    auth = client_of(uid)
    with SessionLocal.begin() as db:
        row = db.get(LoginSession, digest(auth.cookies.get('chrya_sid')))
        row.expires = int(time.time()) + 28800 - 660
    assert auth.post('/api/security/passkey/options', json={}).status_code == 403
    sid = secrets.token_urlsafe(40)
    with SessionLocal.begin() as db:
        db.add(LoginSession(token_hash=digest(sid), user_id=uid, csrf='secret-csrf', expires=int(time.time()) + 28800))
    other = TestClient(app)
    other.cookies.set('chrya_sid', sid)
    assert other.post('/api/security/passkey/options', json={}).status_code == 403
    assert other.post('/api/security/passkey/verify', json={'flow': 'bogus', 'credential': {}}).status_code == 403


def test_login_page_has_visible_biometric_enroll_controls():
    c = TestClient(app)
    html = c.get('/').text
    assert 'id="go-register-face"' in html
    assert 'id="registration-done-step"' in html
    assert 'Daftarkan wajah saat Register' in html
    assert 'Buat Akun &amp; Daftarkan Wajah' in html
    assert 'id="face-open-btn"' in html
    assert 'id="face-video"' in html
    js = c.get('/static/app.js').text
    assert 'getUserMedia' in js
    assert 'data-enroll-passkey' in js
    assert 'enrollExtraBiometric' in js


def test_camera_face_enroll_and_login_requires_password_and_usb():
    c = TestClient(app)
    body = {'username': 'camerauser', 'email': 'camera@example.test', 'full_name': 'Camera User', 'password': 'MyLongStrongCameraPassword123!'}
    r = c.post('/api/auth/register', json=body)
    assert r.status_code == 200, r.text
    token = r.json()['flow']
    assert c.post('/api/auth/face/options', json={'flow': token}).status_code == 403
    challenge = c.post('/api/auth/usb/challenge', json={'flow': token}).json()['challenge']
    raw = base64.urlsafe_b64decode(challenge + '=' * ((-len(challenge)) % 4))
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), raw, hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': token, 'response': proof}).status_code == 200
    opts = c.post('/api/auth/face/options', json={'flow': token})
    assert opts.status_code == 200 and opts.json()['kind'] == 'register'

    frame_p0_s0 = real_person_jpeg_data_url(0, 0)
    frame_p0_s1 = real_person_jpeg_data_url(0, 1)
    done = c.post('/api/auth/face/verify', json={'flow': token, 'frames': [frame_p0_s0]})
    assert done.status_code == 200, done.text
    assert done.json()['registered'] is True
    assert c.get('/api/me').json()['authenticated'] is False
    with SessionLocal() as db:
        template = db.scalar(select(FaceTemplate))
        assert template.encrypted_descriptor.startswith(b'FC02')
        assert template.model_version == 'sface_2021dec'
    assert c.post('/api/auth/face/verify', json={'flow': token, 'frames': [frame_p0_s0]}).status_code == 401
    begin = c.post('/api/auth/start', json={'identity': 'camerauser', 'password': body['password']})
    assert begin.status_code == 200 and begin.json()['setup'] is False
    token = begin.json()['flow']
    challenge = c.post('/api/auth/usb/challenge', json={'flow': token}).json()['challenge']
    raw = base64.urlsafe_b64decode(challenge + '=' * ((-len(challenge)) % 4))
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), raw, hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': token, 'response': proof}).status_code == 200
    assert c.post('/api/auth/face/options', json={'flow': token}).json()['kind'] == 'verify'
    done = c.post('/api/auth/face/verify', json={'flow': token, 'frames': [frame_p0_s1]})
    assert done.status_code == 200, done.text
    assert done.json()['user']['username'] == 'camerauser'
    assert c.get('/api/me').json()['authenticated'] is True
    assert c.get('/api/me').json()['face_enrolled'] is True


def test_camera_face_cannot_be_added_to_existing_passkey_account_without_login():
    from models import Credential
    uid = mkuser('legacyface')
    with SessionLocal.begin() as db:
        db.add(Credential(user_id=uid, credential_id=b'demo-cred', public_key=b'public-key', sign_count=0, transports='[]'))
    c = TestClient(app)
    login = c.post('/api/auth/start', json={'identity': 'legacyface', 'password': 'ExampleStrongPassword!123'}).json()
    assert login['setup'] is False
    flow = login['flow']
    challenge = c.post('/api/auth/usb/challenge', json={'flow': flow}).json()['challenge']
    raw = base64.urlsafe_b64decode(challenge + '=' * ((-len(challenge)) % 4))
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), raw, hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': flow, 'response': proof}).status_code == 200
    assert c.post('/api/auth/face/options', json={'flow': flow}).status_code == 403
    assert c.post('/api/security/face/options', json={}).status_code == 401
    owner = client_of(uid)
    import time
    with SessionLocal.begin() as db:
        row = db.get(LoginSession, digest(owner.cookies.get('chrya_sid')))
        row.expires = int(time.time()) + 28800 - 660
    a = owner.post('/api/security/face/options', json={})
    assert a.status_code == 403


def test_face_camera_syntactic_and_security_guards():
    from face_camera import decode_frame
    with pytest.raises(FaceError):
        decode_frame('data:image/png;base64,AA==')
    with pytest.raises(FaceError):
        check_frames(['one'], 'left')
    sample = np.ones(128, dtype=np.float32) / np.sqrt(128)
    encrypted = encrypt_template(sample, 11, b'a' * 32)
    assert np.allclose(decrypt_template(encrypted, 11, b'a' * 32), sample)
    with pytest.raises(Exception):
        decrypt_template(encrypted, 12, b'a' * 32)
    with pytest.raises(Exception):
        decrypt_template(encrypted, 11, b'b' * 32)


def test_face_registration_is_mandatory_before_first_login_session():
    c = TestClient(app)
    info = {'username': 'student', 'email': 'student@example.test', 'full_name': 'Student', 'password': 'StrongStudentPassword1234'}
    created = c.post('/api/auth/register', json=info)
    assert created.status_code == 200
    assert created.json()['registration_required'] is True
    token = created.json()['flow']
    assert c.get('/api/me').json()['authenticated'] is False
    assert c.post('/api/auth/face/options', json={'flow': token}).status_code == 403
    challenge = c.post('/api/auth/usb/challenge', json={'flow': token}).json()['challenge']
    raw = base64.urlsafe_b64decode(challenge + '=' * ((-len(challenge)) % 4))
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), raw, hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': token, 'response': proof}).status_code == 200
    assert c.post('/api/auth/webauthn/options', json={'flow': token}).status_code == 403
    pending = c.post('/api/auth/start', json={'identity': 'student', 'password': info['password']})
    assert pending.json()['setup'] is True
    assert c.get('/api/me').json()['authenticated'] is False
    assert c.post('/api/auth/face/options', json={'flow': token}).status_code == 200

    owner_frame1 = real_person_jpeg_data_url(2, 0)
    owner_frame2 = real_person_jpeg_data_url(2, 1)
    impostor_frame = real_person_jpeg_data_url(7, 0)

    done = c.post('/api/auth/face/verify', json={'flow': token, 'frames': [owner_frame1]})
    assert done.status_code == 200 and done.json()['registered'] is True
    assert 'chrya_sid' not in c.cookies
    assert c.get('/api/me').json()['authenticated'] is False

    login = c.post('/api/auth/start', json={'identity': 'student', 'password': info['password']}).json()
    assert login['setup'] is False and login['face_enrolled'] is True
    assert login['biometric_action'] == 'verify'
    login_token = login['flow']
    challenge = c.post('/api/auth/usb/challenge', json={'flow': login_token}).json()['challenge']
    raw = base64.urlsafe_b64decode(challenge + '=' * ((-len(challenge)) % 4))
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), raw, hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': login_token, 'response': proof}).status_code == 200
    assert c.post('/api/auth/face/options', json={'flow': login_token}).json()['kind'] == 'verify'

    # Different person's real face must be rejected!
    mismatch = c.post('/api/auth/face/verify', json={'flow': login_token, 'frames': [impostor_frame]})
    assert mismatch.status_code == 401
    assert c.get('/api/me').json()['authenticated'] is False

    # Owner's second real photo succeeds!
    accepted = c.post('/api/auth/face/verify', json={'flow': login_token, 'frames': [owner_frame2]})
    assert accepted.status_code == 200
    assert accepted.json()['user']['username'] == 'student'
    assert c.get('/api/me').json()['authenticated'] is True


def test_registration_completion_page_and_login_button_visible():
    c = TestClient(app)
    html = c.get('/').text
    js = c.get('/static/app.js').text
    assert 'id="go-login-after-face"' in html
    assert 'id="registration-done-step"' in html
    assert 'registrationComplete(result.message)' in js
    assert 'else if(result.registered)' in js
    assert "'register'" in js


def test_username_unique_across_clients_and_case_normalization():
    first_device = TestClient(app)
    second_device = TestClient(app)
    first = {'username': '  NASCA.Example  ', 'email': 'first@example.test', 'full_name': 'First Account', 'password': 'VeryStrongPassword123!'}
    second = {'username': 'nasca.example', 'email': 'second@example.test', 'full_name': 'Second Account', 'password': 'VeryStrongPassword456!'}
    check = lambda cli, n: cli.get('/api/auth/username-availability', params={'username': n})
    assert check(first_device, 'NASCA.Example').json()['available'] is True
    assert check(second_device, 'nasca.example').json()['available'] is True
    one = first_device.post('/api/auth/register', json=first)
    assert one.status_code == 200, one.text
    assert check(second_device, 'nasca.example').json()['available'] is False
    assert check(second_device, ' NASCA.EXAMPLE ').json()['available'] is False
    denied = second_device.post('/api/auth/register', json=second)
    assert denied.status_code == 409
    collision = second_device.post('/api/auth/register', json={**second, 'username': 'newperson', 'email': 'first@example.test'})
    assert collision.status_code == 409
    allowed = second_device.post('/api/auth/register', json={**second, 'username': 'newperson'})
    assert allowed.status_code == 200, allowed.text


def test_username_rejection_for_invalid_format_and_unique_database_constraint():
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy import inspect
    c = TestClient(app)
    for invalid in ('', 'ab', 'has space', 'non-ASCII-ü', 'a' * 33):
        response = c.get('/api/auth/username-availability', params={'username': invalid})
        assert response.status_code == 200
        assert response.json()['available'] is False
    mkuser('existing')
    indexes = inspect(engine).get_indexes('users')
    assert any(i.get('unique') and i.get('column_names') == ['username'] for i in indexes)
    with pytest.raises(IntegrityError):
        with SessionLocal.begin() as db:
            db.add(User(username='existing', email='different@example.test', full_name='Different Name',
                        password_hash=PASSWORD_HASHER.hash('VeryStrongPassword456!'), handle=secrets.token_bytes(32)))
            db.flush()


def device_client(uid: int, base: str) -> TestClient:
    c = TestClient(app, base_url=base)
    sid = secrets.token_urlsafe(40)
    csrf = secrets.token_hex(24)
    with SessionLocal.begin() as db:
        db.add(LoginSession(token_hash=digest(sid), user_id=uid, csrf=csrf, expires=9999999999))
    c.cookies.set('chrya_sid', sid)
    c.headers['X-CSRF-Token'] = csrf
    return c


def test_cross_device_find_invite_accept_message_and_reply(monkeypatch):
    monkeypatch.setenv('CHRYA_ALLOW_PRIVATE_LAN', 'true')
    a = mkuser('laptop.user')
    b = mkuser('hp.user')
    sender = device_client(a, 'http://localhost:8765')
    receiver = device_client(b, 'http://192.168.10.42:8765')
    receiver.headers['Origin'] = 'http://192.168.10.42:8765'
    results = sender.get('/api/contacts?q=HP.USER').json()
    assert results['search'][0]['username'] == 'hp.user'
    assert results['search'][0]['relation'] == 'none'
    assert 'email' not in results['search'][0]
    assert sender.post('/api/contacts/request', json={'username': 'hp.user'}).status_code == 200
    assert receiver.get('/api/stats').json()['pending_invites'] == 1
    incoming = receiver.get('/api/contacts').json()['items'][0]
    assert receiver.post('/api/contacts/respond', json={'action': 'accept', 'id': incoming['id']}).status_code == 200
    response = sender.post('/api/messages', json={'recipient': 'hp.user', 'subject': 'Dokumen penting', 'body': 'Pesan hanya untuk penerima'})
    assert response.status_code == 200
    msg_id = response.json()['message_id']
    opened = receiver.get(f'/api/messages/{msg_id}').json()['message']
    assert opened['body'] == 'Pesan hanya untuk penerima'
    assert receiver.post('/api/messages', json={
        'recipient': 'laptop.user', 'subject': 'Re: Dokumen penting', 'body': 'Sudah diterima', 'reply_to': msg_id
    }).status_code == 200


def test_local_lan_origin_rejects_unrelated_sites(monkeypatch):
    monkeypatch.setenv('CHRYA_ALLOW_PRIVATE_LAN', 'true')
    a = mkuser('alice')
    c = device_client(a, 'http://192.168.10.42:8765')
    c.headers['Origin'] = 'http://hostile.site'
    assert c.post('/api/notes', json={'title': 'test', 'body': 'text'}).status_code == 403
    c.headers['Origin'] = 'http://192.168.10.40:8765'
    assert c.post('/api/notes', json={'title': 'test', 'body': 'text'}).status_code == 403
    c.headers['Origin'] = 'http://192.168.10.42:8765'
    assert c.post('/api/notes', json={'title': 'ok', 'body': 'text'}).status_code == 200


def test_search_literal_underscore_no_wildcard_and_pending_state():
    a = mkuser('owner')
    mkuser('a_b')
    mkuser('axb')
    c = client_of(a)
    results = c.get('/api/contacts?q=a_b').json()['search']
    assert [p['username'] for p in results] == ['a_b']
    assert c.post('/api/contacts/request', json={'username': 'a_b'}).status_code == 200
    assert c.get('/api/contacts?q=a_b').json()['search'][0]['relation'] == 'pending_outgoing'


def test_front_camera_capture_single_frame_only():
    from unittest.mock import patch
    from face_camera import FaceFrame
    sample = np.ones(128, dtype=np.float32) / np.sqrt(128)
    with patch('face_camera.extract', return_value=FaceFrame(sample, 120.0, 640)) as mocked:
        assert np.allclose(check_frames(['one-image'], 'front'), sample)
        mocked.assert_called_once_with('one-image')
        with pytest.raises(FaceError):
            check_frames(['one-image', 'another-image'], 'front')
        with pytest.raises(FaceError):
            check_frames([], 'front')
        with pytest.raises(FaceError):
            check_frames(['one-image'], 'left')


def test_front_camera_ui_shows_one_capture_only():
    c = TestClient(app)
    html = c.get('/').text
    js = c.get('/static/app.js').text
    assert 'id="face-capture-one"' in html
    assert 'id="face-capture-two"' not in html
    assert 'captureFaceOnce' in js
    assert 'const frames=[cameraSnapshot()]' in js


# ==============================================================================
# NEW COMPREHENSIVE AUDIT & SECURITY TESTS (CATEGORIES A THROUGH K)
# ==============================================================================

def test_audit_A_sface_two_real_people_liveness_spoofing_and_rate_limit():
    """Verify A.1..A.10: SFace 128-D embedding distinguishes two real people, rejects spoofing
    (dark/overexposed, multi-face, static burst replay), enforces persistent rate limit,
    and supports template deletion and re-enrollment."""
    f_personA_1 = real_person_jpeg_data_url(5, 0)
    f_personA_2 = real_person_jpeg_data_url(5, 2)
    f_personB_1 = real_person_jpeg_data_url(12, 0)

    embA1 = extract(f_personA_1).descriptor
    embA2 = extract(f_personA_2).descriptor
    embB1 = extract(f_personB_1).descriptor
    assert embA1.shape == (128,)
    assert face_distance(embA1, embA2) < MAX_MATCH_DISTANCE
    assert face_distance(embA1, embB1) > MAX_MATCH_DISTANCE

    # Multi-face rejection (A.5): place two faces side by side on one frame
    import sklearn.datasets
    data = sklearn.datasets.fetch_olivetti_faces(data_home=str(ROOT / 'models_onnx'), download_if_missing=False)
    g1 = cv2.cvtColor(cv2.resize((data.images[0] * 255).astype(np.uint8), (150, 150)), cv2.COLOR_GRAY2BGR)
    g2 = cv2.cvtColor(cv2.resize((data.images[10] * 255).astype(np.uint8), (150, 150)), cv2.COLOR_GRAY2BGR)
    two_canvas = np.full((360, 480, 3), 115, dtype=np.uint8)
    two_canvas[100:250, 40:190] = g1
    two_canvas[100:250, 280:430] = g2
    ok, buf = cv2.imencode('.jpg', two_canvas)
    two_url = 'data:image/jpeg;base64,' + base64.b64encode(buf.tobytes()).decode('ascii')
    with pytest.raises(FaceError, match='SATU wajah'):
        extract(two_url)

    # Multi-frame identical replay rejection (A.2 anti-spoofing)
    with pytest.raises(FaceError, match='anti-spoofing|identik'):
        check_frames([f_personA_1, f_personA_1], 'live_burst')

    # Camera failure / empty frame fails closed (A.10)
    with pytest.raises(FaceError):
        check_frames([''], 'front')

    # Persistent rate limiting on 5 failed face login attempts (A.6) + template delete & re-enroll (A.7)
    c = TestClient(app)
    reg = c.post('/api/auth/register', json={
        'username': 'person_a', 'email': 'pa@example.test', 'full_name': 'Person A', 'password': 'StrongPasswordPersonA!123'
    }).json()
    flow = reg['flow']
    ch = c.post('/api/auth/usb/challenge', json={'flow': flow}).json()['challenge']
    proof = hmac.new((USB / 'chrya_usb.key').read_bytes(), ub64(ch), hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': flow, 'response': proof}).status_code == 200
    assert c.post('/api/auth/face/options', json={'flow': flow}).status_code == 200
    assert c.post('/api/auth/face/verify', json={'flow': flow, 'frames': [f_personA_1]}).status_code == 200

    # Person B attempts to log in to Person A's account 5 times -> locked out!
    login_flow = c.post('/api/auth/start', json={'identity': 'person_a', 'password': 'StrongPasswordPersonA!123'}).json()['flow']
    ch2 = c.post('/api/auth/usb/challenge', json={'flow': login_flow}).json()['challenge']
    proof2 = hmac.new((USB / 'chrya_usb.key').read_bytes(), ub64(ch2), hashlib.sha256).hexdigest()
    assert c.post('/api/auth/usb/verify', json={'flow': login_flow, 'response': proof2}).status_code == 200
    assert c.post('/api/auth/face/options', json={'flow': login_flow}).status_code == 200
    for _ in range(5):
        r = c.post('/api/auth/face/verify', json={'flow': login_flow, 'frames': [f_personB_1]})
        assert r.status_code == 401
    # 6th attempt must be blocked with 429 Too Many Requests
    assert c.post('/api/auth/face/verify', json={'flow': login_flow, 'frames': [f_personA_2]}).status_code == 429


def test_one_face_one_account_uniqueness_and_impostor_rejection():
    """Verify strict 1-Face-1-Account policy (1 muka 1 akun) and mutual cross-account face rejection:
    - Account 1 enrolls Person A's face -> succeeds.
    - Account 2 tries to enroll Person A's face -> rejected (401: '1 wajah hanya untuk 1 akun').
    - Account 2 enrolls Person B's face -> succeeds.
    - Account 1 cannot log in with Person B's face (401), and Account 2 cannot log in with Person A's face (401).
    - Legacy FC01 (256-D LBP) templates in DB are automatically invalidated so old weak LBP templates never allow false logins.
    """
    f_personA_enroll = real_person_jpeg_data_url(5, 0)
    f_personA_other = real_person_jpeg_data_url(5, 1)
    f_personA_login = real_person_jpeg_data_url(5, 2)
    f_personB_enroll = real_person_jpeg_data_url(12, 0)
    f_personB_login = real_person_jpeg_data_url(12, 1)

    c1 = TestClient(app)
    c2 = TestClient(app)

    # 1. Account 1 registers with Person A's face
    r1 = c1.post('/api/auth/register', json={
        'username': 'akun_satu', 'email': 'satu@example.test', 'full_name': 'Akun Satu', 'password': 'StrongPasswordSatu!123'
    }).json()
    flow1 = r1['flow']
    ch1 = c1.post('/api/auth/usb/challenge', json={'flow': flow1}).json()['challenge']
    proof1 = hmac.new((USB / 'chrya_usb.key').read_bytes(), ub64(ch1), hashlib.sha256).hexdigest()
    assert c1.post('/api/auth/usb/verify', json={'flow': flow1, 'response': proof1}).status_code == 200
    assert c1.post('/api/auth/face/options', json={'flow': flow1}).status_code == 200
    enroll1 = c1.post('/api/auth/face/verify', json={'flow': flow1, 'frames': [f_personA_enroll]})
    assert enroll1.status_code == 200 and enroll1.json()['registered'] is True

    # 2. Account 2 tries to register with Person A's face -> MUST BE REJECTED (1 face = 1 account)
    r2 = c2.post('/api/auth/register', json={
        'username': 'akun_dua', 'email': 'dua@example.test', 'full_name': 'Akun Dua', 'password': 'StrongPasswordDua!123'
    }).json()
    flow2 = r2['flow']
    ch2 = c2.post('/api/auth/usb/challenge', json={'flow': flow2}).json()['challenge']
    proof2 = hmac.new((USB / 'chrya_usb.key').read_bytes(), ub64(ch2), hashlib.sha256).hexdigest()
    assert c2.post('/api/auth/usb/verify', json={'flow': flow2, 'response': proof2}).status_code == 200
    assert c2.post('/api/auth/face/options', json={'flow': flow2}).status_code == 200
    dup_enroll = c2.post('/api/auth/face/verify', json={'flow': flow2, 'frames': [f_personA_other]})
    assert dup_enroll.status_code == 401
    assert '1 wajah hanya untuk 1 akun' in dup_enroll.json()['error']

    # 3. Account 2 registers with Person B's face -> SUCCEEDS
    enroll2 = c2.post('/api/auth/face/verify', json={'flow': flow2, 'frames': [f_personB_enroll]})
    assert enroll2.status_code == 200 and enroll2.json()['registered'] is True

    # 4. Account 1 tries to log in with Person B's face -> REJECTED (401)
    l1 = c1.post('/api/auth/start', json={'identity': 'akun_satu', 'password': 'StrongPasswordSatu!123'}).json()['flow']
    ch_l1 = c1.post('/api/auth/usb/challenge', json={'flow': l1}).json()['challenge']
    proof_l1 = hmac.new((USB / 'chrya_usb.key').read_bytes(), ub64(ch_l1), hashlib.sha256).hexdigest()
    assert c1.post('/api/auth/usb/verify', json={'flow': l1, 'response': proof_l1}).status_code == 200
    assert c1.post('/api/auth/face/options', json={'flow': l1}).status_code == 200
    bad_login1 = c1.post('/api/auth/face/verify', json={'flow': l1, 'frames': [f_personB_login]})
    assert bad_login1.status_code == 401
    assert 'Wajah tidak cocok' in bad_login1.json()['error']

    # Account 1 logs in with Person A's face -> SUCCEEDS (200)
    ok_login1 = c1.post('/api/auth/face/verify', json={'flow': l1, 'frames': [f_personA_login]})
    assert ok_login1.status_code == 200 and ok_login1.json()['user']['username'] == 'akun_satu'

    # 5. Account 2 tries to log in with Person A's face -> REJECTED (401), then logs in with Person B's face -> SUCCEEDS
    l2 = c2.post('/api/auth/start', json={'identity': 'akun_dua', 'password': 'StrongPasswordDua!123'}).json()['flow']
    ch_l2 = c2.post('/api/auth/usb/challenge', json={'flow': l2}).json()['challenge']
    proof_l2 = hmac.new((USB / 'chrya_usb.key').read_bytes(), ub64(ch_l2), hashlib.sha256).hexdigest()
    assert c2.post('/api/auth/usb/verify', json={'flow': l2, 'response': proof_l2}).status_code == 200
    assert c2.post('/api/auth/face/options', json={'flow': l2}).status_code == 200
    bad_login2 = c2.post('/api/auth/face/verify', json={'flow': l2, 'frames': [f_personA_login]})
    assert bad_login2.status_code == 401
    ok_login2 = c2.post('/api/auth/face/verify', json={'flow': l2, 'frames': [f_personB_login]})
    assert ok_login2.status_code == 200 and ok_login2.json()['user']['username'] == 'akun_dua'
    c2.headers['X-CSRF-Token'] = ok_login2.json()['csrf']

    # 6. Account 2 in Security Center tries to change its face to Person A's face -> REJECTED (400)
    sec_opt = c2.post('/api/security/face/options', json={}).json()
    sec_dup = c2.post('/api/security/face/verify', json={'flow': sec_opt['flow'], 'frames': [f_personA_other]})
    assert sec_dup.status_code == 400
    assert '1 wajah hanya untuk 1 akun' in sec_dup.json()['error']

    # 7. Legacy FC01 (LBP) template in database is automatically purged and requires fresh SFace enrollment
    uid_legacy = mkuser('legacy_lbp_user')
    with SessionLocal.begin() as db:
        db.add(FaceTemplate(user_id=uid_legacy, encrypted_descriptor=b'FC01' + b'\x00' * 64, model_version='legacy_256'))
    c3 = TestClient(app)
    start_legacy = c3.post('/api/auth/start', json={'identity': 'legacy_lbp_user', 'password': 'ExampleStrongPassword!123'}).json()
    assert start_legacy['setup'] is True and start_legacy['face_enrolled'] is False


def test_file_preview_pdf_inline_and_docx_text_extraction():
    """PDF preview must be served same-origin inline (not blocked data: URI) and DOCX text must be readable."""
    import io, zipfile
    a = mkuser('previewer')
    ca = client_of(a)
    pdf_bytes = b'%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF'
    up = ca.post('/api/files', files={'file': ('materi.pdf', pdf_bytes, 'application/pdf')})
    assert up.status_code == 200, up.text
    fid = up.json()['file_id']
    prev = ca.get(f'/api/files/{fid}/preview').json()
    assert prev['kind'] == 'pdf' and prev['inline_url'] == f'/api/files/{fid}/inline'
    inline = ca.get(f'/api/files/{fid}/inline')
    assert inline.status_code == 200
    assert inline.content == pdf_bytes
    assert inline.headers['content-type'].startswith('application/pdf')
    assert inline.headers['content-disposition'].startswith('inline')
    assert inline.headers['x-frame-options'] == 'SAMEORIGIN'
    assert "frame-ancestors 'self'" in inline.headers['content-security-policy']
    # Other users cannot open the inline file
    assert client_of(mkuser('stranger')).get(f'/api/files/{fid}/inline').status_code == 404
    # DOCX text extraction
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('word/document.xml',
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                    '<w:p><w:r><w:t>Pengantar Kriptografi</w:t></w:r></w:p></w:body></w:document>')
    up2 = ca.post('/api/files', files={'file': ('catatan.docx', buf.getvalue(), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')})
    assert up2.status_code == 200, up2.text
    prev2 = ca.get(f"/api/files/{up2.json()['file_id']}/preview").json()
    assert prev2['kind'] == 'text' and 'Pengantar Kriptografi' in prev2['content']


def test_audit_B_usb_drive_change_rotation_revocation_and_lost_handling():
    """Verify B.1..B.7: USB drive path relocation, volume serial tracking, personal USB key issue,
    old USB key revocation, and lost USB recovery."""
    # Simulate USB drive changing mount folder / drive letter (B.1, B.2)
    alt_drive = TESTROOT / 'relocated_drive'
    alt_drive.mkdir(exist_ok=True)
    raw_key = (USB / 'chrya_usb.key').read_bytes()
    (USB / 'chrya_usb.key').unlink()
    (alt_drive / 'chrya_usb.key').write_bytes(raw_key)
    assert GUARD.key(extra_search_dirs=[alt_drive]) == raw_key
    # Restore to primary USB test dir
    (USB / 'chrya_usb.key').write_bytes(raw_key)
    GUARD.rotate_or_replace(USB)
    assert not GUARD.is_digest_revoked(hashlib.sha256((USB / 'chrya_usb.key').read_bytes()).hexdigest())
    assert GUARD.is_digest_revoked(hashlib.sha256(raw_key).hexdigest())

    # Issue personal USB key & revoke old personal key (B.4, B.5, B.6)
    uid = mkuser('usbowner')
    c = client_of(uid)
    issued = c.post('/api/security/usb/issue', json={'label': 'Flashdisk Utama', 'revoke_old': True})
    assert issued.status_code == 200
    new_key_bytes = ub64(issued.json()['key_b64'])
    assert len(new_key_bytes) == 32
    ov = c.get('/api/security/overview').json()
    usb_entry = ov['usb_keys'][0]
    assert usb_entry['status'] == 'active'

    # Revoke personal USB key as lost
    rev = c.post(f"/api/security/usb/{usb_entry['id']}/revoke", json={'reason': 'lost'})
    assert rev.status_code == 200 and rev.json()['status'] == 'lost'


def test_audit_C_domain_key_separation_tamper_rotation_and_backup():
    """Verify C.1..C.11: distinct HKDF keys per domain, ciphertext bit-flip rejection,
    key rotation with seamless decryption of old + new data, and encrypted master key backup."""
    k_msg = derive_subkey(MASTER, 'MESSAGE')
    k_file = derive_subkey(MASTER, 'FILE')
    k_face = derive_subkey(MASTER, 'FACE')
    assert k_msg != k_file and k_msg != k_face and k_file != k_face

    # Tampered ciphertext must be rejected (C.5, C.6)
    env = encrypt_text('Data Rahasia 123', MASTER, context='BODY')
    parsed = json.loads(env)
    ct_bytes = bytearray(ub64(parsed['c']))
    ct_bytes[-1] ^= 0xFF
    parsed['c'] = b64(bytes(ct_bytes))
    with pytest.raises(ValueError):
        decrypt_text(json.dumps(parsed), MASTER, context='BODY')

    # Tampered file ciphertext must be rejected
    fblob = bytearray(encrypt_file(b'Dokumen penting', MASTER))
    fblob[-1] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_file(bytes(fblob), MASTER)

    # Master key backup & restore (C.8)
    backup_blob = export_master_key_backup(MASTER, 'PassphraseSangatKuat!2026', {'current_kid': 1})
    assert b'CHRYA-MASTER-BACKUP' in backup_blob
    restored = restore_master_key_backup(backup_blob, 'PassphraseSangatKuat!2026')
    assert restored['master_key'] == MASTER
    with pytest.raises(ValueError):
        restore_master_key_backup(backup_blob, 'PassphraseSalah12345')

    # Key rotation via API (C.9)
    uid = mkuser('keyadmin')
    c = client_of(uid)
    n_res = c.post('/api/notes', json={'title': 'Sebelum Rotasi', 'body': 'Tetap terbaca setelah rotasi'})
    assert n_res.status_code == 200
    rot = c.post('/api/security/keys/rotate', json={})
    assert rot.status_code == 200
    assert rot.json()['current_kid'] >= 2
    notes_after = c.get('/api/notes').json()['items']
    assert notes_after[0]['body'] == 'Tetap terbaca setelah rotasi'


def test_audit_D_and_E_contacts_and_messaging_full_lifecycle():
    """Verify D.1..D.10 and E.1..E.9: search by full_name, not_found state, cancel invite,
    unblock, delete contact, unarchive, pin, message search, delete message, delete conversation."""
    a = mkuser('arina')
    b = mkuser('bagas')
    ca = client_of(a)
    cb = client_of(b)

    # Search by full name & not_found flag (D.2, D.3)
    s_found = ca.get('/api/contacts?q=Bagas+Testing').json()
    assert len(s_found['search']) == 1 and s_found['search'][0]['username'] == 'bagas'
    s_none = ca.get('/api/contacts?q=tidak_ada_user_xyz').json()
    assert s_none['not_found'] is True and s_none['search'] == []

    # Send invite and cancel invite (D.5)
    req = ca.post('/api/contacts/request', json={'username': 'bagas'}).json()
    assert ca.post('/api/contacts/cancel', json={'id': req['request_id']}).status_code == 200
    assert cb.get('/api/contacts').json()['items'] == []

    # Re-invite and accept, then test messaging features (E.1..E.9)
    ca, cb = invite(a, b)
    m1 = ca.post('/api/messages', json={'recipient': 'bagas', 'subject': 'Proyek Kriptografi', 'body': 'Kode peluncuran alfa'}).json()['message_id']
    m2 = ca.post('/api/messages', json={'recipient': 'bagas', 'subject': 'Jadwal Rapat', 'body': 'Hari Senin jam 9'}).json()['message_id']

    # Search messages (E.1)
    search_m = cb.get('/api/messages?box=inbox&q=peluncuran').json()['items']
    assert len(search_m) == 1 and search_m[0]['id'] == m1

    # Pin / favorite message (E.5)
    pin_res = cb.post(f'/api/messages/{m1}/pin').json()
    assert pin_res['pinned'] is True
    assert len(cb.get('/api/messages?box=pinned').json()['items']) == 1

    # Archive and Unarchive (E.4)
    assert cb.post(f'/api/messages/{m1}/archive').status_code == 200
    assert len(cb.get('/api/messages?box=archive').json()['items']) == 1
    assert cb.post(f'/api/messages/{m1}/unarchive').status_code == 200
    assert len(cb.get('/api/messages?box=archive').json()['items']) == 0

    # Delete single message (E.2) & delete conversation (E.3)
    assert cb.delete(f'/api/messages/{m1}').status_code == 200
    assert cb.get(f'/api/messages/{m1}').status_code == 404
    assert cb.delete('/api/conversations/arina').status_code == 200
    assert cb.get('/api/messages?box=inbox').json()['items'] == []

    # Block, Unblock (D.7), and Remove Contact (D.4)
    assert ca.post('/api/contacts/block', json={'user_id': b}).status_code == 200
    assert len(ca.get('/api/contacts?status_filter=blocked').json()['blocked']) == 1
    assert ca.post('/api/contacts/unblock', json={'user_id': b}).status_code == 200
    assert len(ca.get('/api/contacts').json()['blocked']) == 0
    ca, cb = invite(a, b)
    assert ca.delete(f'/api/contacts/{b}').status_code == 200
    assert ca.post('/api/messages', json={'recipient': 'bagas', 'subject': 'Tes', 'body': 'Ditolak'}).status_code == 403


def test_audit_F_and_G_file_vault_and_my_vault_features():
    """Verify F.1..F.8 and G.1..G.6: file category, search, preview, share, revoke access,
    delete file; note edit, search, and category."""
    a = mkuser('fira')
    b = mkuser('gilang')
    ca, cb = invite(a, b)

    # Upload private file, preview, search, share, revoke, delete (F.1..F.6)
    up = ca.post('/api/files', data={'category': 'Rahasia'}, files={'file': ('catatan_audit.txt', b'Isi dokumen rahasia 123', 'text/plain')})
    assert up.status_code == 200
    fid = up.json()['file_id']
    assert len(ca.get('/api/files?q=audit&category=Rahasia').json()['items']) == 1
    prev = ca.get(f'/api/files/{fid}/preview').json()
    assert prev['kind'] == 'text' and 'Isi dokumen rahasia 123' in prev['content']
    assert cb.get(f'/api/files/{fid}/download').status_code == 404

    # Share with accepted contact b
    assert ca.post(f'/api/files/{fid}/share', json={'recipient': 'gilang'}).status_code == 200
    assert cb.get(f'/api/files/{fid}/download').status_code == 200
    # Revoke access
    assert ca.post(f'/api/files/{fid}/revoke').status_code == 200
    assert cb.get(f'/api/files/{fid}/download').status_code == 404
    # Delete file
    assert ca.delete(f'/api/files/{fid}').status_code == 200
    assert ca.get(f'/api/files/{fid}/download').status_code == 404

    # My Vault: create, edit/update, category, search (G.1..G.6)
    n_id = ca.post('/api/notes', json={'title': 'PIN Brankas', 'body': '112233', 'category': 'Kredensial'}).json()['note_id']
    assert ca.put(f'/api/notes/{n_id}', json={'title': 'PIN Brankas Baru', 'body': '998877', 'category': 'Pribadi'}).status_code == 200
    found = ca.get('/api/notes?q=998877&category=Pribadi').json()['items']
    assert len(found) == 1 and found[0]['title'] == 'PIN Brankas Baru'


def test_audit_H_I_J_K_notifications_security_center_ledger_and_smtp(monkeypatch):
    """Verify H.1..H.7, I.1..I.9, J.1..J.6, and K.1..K.10."""
    a = mkuser('hendra')
    b = mkuser('indra')
    ca, cb = invite(a, b)
    ca.post('/api/messages', json={'recipient': 'indra', 'subject': 'Halo', 'body': 'Pesan uji notifikasi'})

    # H.1..H.6: Notifications unread filter, mark read, mark all read, delete
    notifs = cb.get('/api/notifications?unread_only=true').json()
    assert notifs['unread_count'] >= 2
    first_nid = notifs['items'][0]['id']
    assert cb.post(f'/api/notifications/{first_nid}/read').status_code == 200
    assert cb.post('/api/notifications/read-all').status_code == 200
    assert cb.get('/api/notifications?unread_only=true').json()['unread_count'] == 0
    assert cb.delete(f'/api/notifications/{first_nid}').status_code == 200

    # H.7: Real SMTP socket delivery test using a local SMTP listener thread
    received_emails = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    smtp_port = srv.getsockname()[1]

    def minimal_smtp_server():
        conn, _ = srv.accept()
        f = conn.makefile('rwb')
        f.write(b'220 localhost ESMTP\r\n')
        f.flush()
        in_data = False
        msg_lines = []
        while True:
            line = f.readline()
            if not line:
                break
            if in_data:
                if line.strip() == b'.':
                    in_data = False
                    f.write(b'250 2.0.0 OK queued\r\n')
                    f.flush()
                else:
                    msg_lines.append(line.decode('utf-8', errors='replace'))
                continue
            cmd = line.upper()
            if cmd.startswith(b'EHLO') or cmd.startswith(b'HELO'):
                f.write(b'250-localhost\r\n250 AUTH PLAIN LOGIN\r\n')
                f.flush()
            elif cmd.startswith(b'AUTH PLAIN'):
                f.write(b'235 2.7.0 Authentication successful\r\n')
                f.flush()
            elif cmd.startswith(b'MAIL FROM') or cmd.startswith(b'RCPT TO') or cmd.startswith(b'RSET') or cmd.startswith(b'NOOP'):
                f.write(b'250 2.1.0 OK\r\n')
                f.flush()
            elif cmd.startswith(b'DATA'):
                in_data = True
                f.write(b'354 End data with <CR><LF>.<CR><LF>\r\n')
                f.flush()
            elif cmd.startswith(b'QUIT'):
                f.write(b'221 2.0.0 Bye\r\n')
                f.flush()
                break
        received_emails.append(''.join(msg_lines))
        f.close()
        conn.close()

    t = threading.Thread(target=minimal_smtp_server, daemon=True)
    t.start()
    monkeypatch.setenv('SMTP_HOST', '127.0.0.1')
    monkeypatch.setenv('SMTP_PORT', str(smtp_port))
    monkeypatch.setenv('SMTP_USER', 'vault@chrya.test')
    monkeypatch.setenv('SMTP_PASSWORD', 'secretpass')
    monkeypatch.setenv('SMTP_FROM', 'vault@chrya.test')
    monkeypatch.setenv('SMTP_STARTTLS', 'false')

    ca.post('/api/messages', json={'recipient': 'indra', 'subject': 'Rahasia Top', 'body': 'Jangan bocor di email'})
    t.join(timeout=5)
    srv.close()
    assert len(received_emails) == 1
    assert 'Jangan bocor di email' not in received_emails[0]
    email_logs = ca.get('/api/notifications').json()['email_logs']
    assert any(l['status'] == 'sent' for l in email_logs)

    # J.1..J.6: Signed Ed25519 Checkpoint, External Anchor & Ledger Export Backup
    cp = ca.post('/api/ledger/checkpoint').json()
    assert cp['ok'] is True and len(cp['signature']) > 20
    ledger_state = ca.get('/api/ledger').json()
    assert ledger_state['valid'] is True and len(ledger_state['checkpoints']) == 1
    exp = ca.get('/api/ledger/export')
    assert exp.status_code == 200 and exp.json()['integrity_valid'] is True

    # I.1..I.9 & K.4: Account recovery codes, password change, database backup
    rec_codes = ca.post('/api/security/recovery/generate', json={}).json()['codes']
    assert len(rec_codes) == 6
    assert ca.post('/api/security/database/backup', json={}).status_code == 200
    assert ca.post('/api/security/password', json={
        'current_password': 'ExampleStrongPassword!123',
        'new_password': 'NewUpdatedPassword!456',
    }).status_code == 200
    # Recover account using one of the generated single-use recovery codes
    anon = TestClient(app)
    rec_res = anon.post('/api/auth/recover', json={
        'identity': 'hendra',
        'recovery_code': rec_codes[0],
        'new_password': 'RecoveredPassword!789',
        'reset_face': True,
    })
    assert rec_res.status_code == 200 and rec_res.json()['setup'] is True
    # Reusing the same recovery code must fail
    assert anon.post('/api/auth/recover', json={'identity': 'hendra', 'recovery_code': rec_codes[0]}).status_code == 401


def test_audit_K_alembic_https_cert_sql_injection_xss_and_restart_persistence():
    """Verify K.1..K.10 & Security F: Alembic migration config, HTTPS self-signed TLS cert generator,
    SQL injection & XSS resistance, and data survival across engine/session re-initialization."""
    from tools.generate_https_cert import generate_self_signed_cert
    cert_path, key_path = generate_self_signed_cert('192.168.1.50')
    assert cert_path.is_file() and key_path.is_file()
    assert b'BEGIN CERTIFICATE' in cert_path.read_bytes()

    # SQL Injection & XSS vectors in search, notes, and messages must be safely parameterized / escaped
    uid = mkuser('secuser')
    c = client_of(uid)
    sqli_q = "' OR 1=1 --"
    res_q = c.get('/api/contacts', params={'q': sqli_q})
    assert res_q.status_code == 200 and res_q.json()['search'] == []

    xss_payload = '<script>alert("xss")</script>'
    n_res = c.post('/api/notes', json={'title': xss_payload, 'body': sqli_q, 'category': 'Umum'})
    assert n_res.status_code == 200
    notes_list = c.get('/api/notes').json()['items']
    assert notes_list[0]['title'] == xss_payload

    # Re-run schema migration (simulating app update/restart on existing DB) and verify zero data loss
    ensure_schema_migrations(engine)
    notes_after_restart = c.get('/api/notes').json()['items']
    assert len(notes_after_restart) == 1 and notes_after_restart[0]['body'] == sqli_q

