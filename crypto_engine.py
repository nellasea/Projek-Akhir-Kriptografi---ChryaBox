"""Cryptography engine for CHRYA BOX.
Educational Vigenere + authenticated modern AEAD (AES-256-GCM & ChaCha20-Poly1305)
with HKDF-SHA256 domain key separation, key versioning/rotation, passphrase-encrypted
master key backup, and Ed25519 checkpoint signing for the SHA-256 audit hash chain.

Architecture note:
CHRYA BOX uses Server-Side Encryption (SSE) at rest with domain-separated keys derived from
the master keyring. Because the server holds the master keyring to perform server-side
encryption/decryption, this is NOT End-to-End Encryption (E2EE); see docs/SSE_VS_E2EE.md
for the complete architectural comparison and optional client-side WebCrypto E2EE helper.
"""
from __future__ import annotations
import os, json, base64, secrets, hashlib, hmac
from pathlib import Path
from typing import Dict, Tuple, Sequence
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidTag, InvalidSignature


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii')


def ub64(s: str) -> bytes:
    if not isinstance(s, str) or not s:
        raise ValueError('Base64 kosong atau tidak valid')
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# Domain separation mapping so messages, files, notes, biometrics, stego, and USB keys
# never share the same encryption key even when derived from the same root master key.
KEY_DOMAINS = {
    'MESSAGE': b'CHRYA-DOMAIN:MESSAGE:v1',
    'SUBJECT': b'CHRYA-DOMAIN:MESSAGE-SUBJECT:v1',
    'BODY': b'CHRYA-DOMAIN:MESSAGE-BODY:v1',
    'NOTE_TITLE': b'CHRYA-DOMAIN:NOTE-TITLE:v1',
    'NOTE_BODY': b'CHRYA-DOMAIN:NOTE-BODY:v1',
    'FILENAME': b'CHRYA-DOMAIN:FILE-NAME:v1',
    'FILE': b'CHRYA-DOMAIN:FILE-WRAP:v1',
    'FACE': b'CHRYA-DOMAIN:BIOMETRIC-FACE:v1',
    'STEGO': b'CHRYA-DOMAIN:STEGANOGRAPHY:v1',
    'USB_SECRET': b'CHRYA-DOMAIN:USB-TOKEN:v1',
}


def derive_subkey(master_key: bytes, context: str, *, key_id: int = 1) -> bytes:
    """Derive a distinct 256-bit key per domain context using HKDF-SHA256."""
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
        raise ValueError('Master key harus tepat 32 byte')
    domain_info = KEY_DOMAINS.get(context, f'CHRYA-DOMAIN:{context}:v1'.encode('utf-8'))
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=f'CHRYA-SALT:kid={key_id}'.encode('utf-8'),
        info=domain_info,
    )
    return hkdf.derive(bytes(master_key))


class KeyRing:
    """Manages the root master key and rotated key versions without losing old data."""
    def __init__(self, instance_dir: Path, root_master_key: bytes):
        self.instance = Path(instance_dir)
        self.keyring_path = self.instance / 'keyring.json'
        self.root_master_key = bytes(root_master_key)
        self.keys: Dict[int, bytes] = {1: self.root_master_key}
        self.current_kid: int = 1
        self._load()

    def _wrap_version_key(self, kid: int, raw_key: bytes) -> str:
        nonce = secrets.token_bytes(12)
        wrap_key = derive_subkey(self.root_master_key, f'KEYRING_WRAP_{kid}', key_id=1)
        ct = AESGCM(wrap_key).encrypt(nonce, raw_key, f'CHRYA:KEYRING:{kid}'.encode())
        return json.dumps({'n': b64(nonce), 'c': b64(ct)})

    def _unwrap_version_key(self, kid: int, envelope: str) -> bytes:
        obj = json.loads(envelope)
        wrap_key = derive_subkey(self.root_master_key, f'KEYRING_WRAP_{kid}', key_id=1)
        return AESGCM(wrap_key).decrypt(ub64(obj['n']), ub64(obj['c']), f'CHRYA:KEYRING:{kid}'.encode())

    def _load(self):
        if not self.keyring_path.is_file():
            return
        try:
            data = json.loads(self.keyring_path.read_text(encoding='utf-8'))
            self.current_kid = int(data.get('current_kid', 1))
            for k_str, wrapped in data.get('wrapped_keys', {}).items():
                kid = int(k_str)
                if kid != 1:
                    self.keys[kid] = self._unwrap_version_key(kid, wrapped)
            if self.current_kid not in self.keys:
                self.current_kid = max(self.keys.keys())
        except Exception:
            self.current_kid = 1

    def _save(self):
        self.instance.mkdir(parents=True, exist_ok=True)
        wrapped = {}
        for kid, raw in self.keys.items():
            if kid != 1:
                wrapped[str(kid)] = self._wrap_version_key(kid, raw)
        payload = {'current_kid': self.current_kid, 'wrapped_keys': wrapped}
        self.keyring_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        if os.name != 'nt':
            os.chmod(self.keyring_path, 0o600)

    def active_key(self) -> Tuple[int, bytes]:
        return self.current_kid, self.keys[self.current_kid]

    def get_key(self, kid: int) -> bytes:
        if kid not in self.keys:
            raise ValueError(f'Versi kunci (kid={kid}) tidak ditemukan')
        return self.keys[kid]

    def rotate(self) -> int:
        """Generate a new 256-bit key version and make it active while keeping all previous keys."""
        new_kid = max(self.keys.keys()) + 1
        self.keys[new_kid] = secrets.token_bytes(32)
        self.current_kid = new_kid
        self._save()
        return new_kid


def export_master_key_backup(master_key: bytes, passphrase: str, keyring_data: dict | None = None) -> bytes:
    """Create an authenticated encrypted backup of the master key using Scrypt + AES-256-GCM."""
    if not isinstance(passphrase, str) or len(passphrase) < 10:
        raise ValueError('Passphrase backup master key minimal 10 karakter.')
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    kek = kdf.derive(passphrase.encode('utf-8'))
    plain = json.dumps({
        'master_key': b64(master_key),
        'keyring': keyring_data or {},
    }, separators=(',', ':')).encode('utf-8')
    ct = AESGCM(kek).encrypt(nonce, plain, b'CHRYA:MASTER_BACKUP:v1')
    doc = {
        'format': 'CHRYA-MASTER-BACKUP',
        'version': 1,
        'kdf': 'scrypt(n=16384,r=8,p=1)',
        'cipher': 'AES-256-GCM',
        'salt': b64(salt),
        'nonce': b64(nonce),
        'ciphertext': b64(ct),
        'key_fingerprint': hashlib.sha256(master_key).hexdigest()[:16],
    }
    return json.dumps(doc, indent=2).encode('utf-8')


def restore_master_key_backup(backup_bytes: bytes, passphrase: str) -> dict:
    """Verify and decrypt an encrypted master key backup."""
    try:
        doc = json.loads(backup_bytes.decode('utf-8'))
        if doc.get('format') != 'CHRYA-MASTER-BACKUP' or doc.get('version') != 1:
            raise ValueError('Format file backup master key tidak dikenal.')
        salt = ub64(doc['salt'])
        nonce = ub64(doc['nonce'])
        ct = ub64(doc['ciphertext'])
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        kek = kdf.derive(passphrase.encode('utf-8'))
        plain = AESGCM(kek).decrypt(nonce, ct, b'CHRYA:MASTER_BACKUP:v1')
        parsed = json.loads(plain.decode('utf-8'))
        raw_master = ub64(parsed['master_key'])
        if len(raw_master) != 32:
            raise ValueError('Panjang master key tidak valid.')
        return {'master_key': raw_master, 'keyring': parsed.get('keyring', {})}
    except (InvalidTag, KeyError, ValueError, json.JSONDecodeError) as e:
        raise ValueError('Gagal memulihkan backup master key: passphrase salah atau file rusak.') from e


def vigenere(text: str, keyword: str = 'CHRYABOX', decrypt: bool = False) -> str:
    """Preserves punctuation/non-ASCII, shifts Latin A-Z letters only."""
    shifts = [ord(c) - 65 for c in keyword.upper() if 'A' <= c <= 'Z']
    if not shifts:
        raise ValueError('Kunci Vigenere kosong')
    out = []
    i = 0
    for c in text:
        if 'A' <= c <= 'Z' or 'a' <= c <= 'z':
            offset = ord('A') if c.isupper() else ord('a')
            shift = shifts[i % len(shifts)] * (-1 if decrypt else 1)
            out.append(chr((ord(c) - offset + shift) % 26 + offset))
            i += 1
        else:
            out.append(c)
    return ''.join(out)


def encrypt_text(text: str, master_key: bytes, *, context: str = 'MESSAGE', key_id: int = 1) -> str:
    """Super-encryption: Vigenere classical layer + AES-256-GCM with domain-separated HKDF key."""
    if not isinstance(text, str):
        raise ValueError('Input teks salah')
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
        raise ValueError('Kunci master harus 32 byte')
    nonce = secrets.token_bytes(12)
    payload = vigenere(text).encode('utf-8')
    subkey = derive_subkey(master_key, context, key_id=key_id)
    aad = f'CHRYA:{context}:v2:kid={key_id}'.encode('utf-8')
    cipher = AESGCM(subkey).encrypt(nonce, payload, aad)
    return json.dumps({
        'v': 2,
        'kid': key_id,
        'ctx': context,
        'alg': 'Vigenere+AES-256-GCM-HKDF',
        'n': b64(nonce),
        'c': b64(cipher),
    }, separators=(',', ':'))


def decrypt_text(envelope: str, master_key: bytes, *, context: str = 'MESSAGE', keyring: KeyRing | None = None) -> str:
    """Verify integrity and decrypt v2 (domain-separated HKDF) or legacy v1 ciphertext."""
    if not isinstance(envelope, str) or not envelope:
        raise ValueError('Dekripsi gagal: amplop ciphertext kosong')
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
        raise ValueError('Dekripsi gagal: kunci tidak valid')
    try:
        data = json.loads(envelope)
        version = data.get('v')
        nonce = ub64(data['n'])
        cipher = ub64(data['c'])
        if len(nonce) != 12 or len(cipher) < 16:
            raise ValueError('Nonce atau tag autentikasi tidak valid')
        if version == 2:
            if data.get('ctx') and data['ctx'] != context:
                raise ValueError('Konteks domain ciphertext tidak sesuai')
            kid = int(data.get('kid', 1))
            base_key = keyring.get_key(kid) if keyring is not None else master_key
            subkey = derive_subkey(base_key, context, key_id=kid)
            aad = f'CHRYA:{context}:v2:kid={kid}'.encode('utf-8')
            raw = AESGCM(subkey).decrypt(nonce, cipher, aad)
        elif version == 1:
            raw = AESGCM(master_key).decrypt(nonce, cipher, f'CHRYA:{context}:v1'.encode('utf-8'))
        else:
            raise ValueError('Versi data tidak didukung')
        return vigenere(raw.decode('utf-8'), decrypt=True)
    except (InvalidTag, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as e:
        raise ValueError('Dekripsi gagal: data rusak atau kunci tidak sesuai') from e


def encrypt_file(data: bytes, master_key: bytes, *, key_id: int = 1) -> bytes:
    """ChaCha20-Poly1305 with a unique random 256-bit file key; that key is wrapped with
    a domain-separated FILE subkey (or root master key in legacy v1).
    Format v2: 8 magic (CHRYAF02) | 2 byte kid | 12 wrap nonce | 48 wrapped key | 12 file nonce | ciphertext+tag.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError('Data file harus berupa bytes')
    if len(data) > 6 * 1024 * 1024:
        raise ValueError('Maksimal file 6 MB')
    filekey = secrets.token_bytes(32)
    knonce = secrets.token_bytes(12)
    nonce = secrets.token_bytes(12)
    wrap_subkey = derive_subkey(master_key, 'FILE', key_id=key_id)
    wrap_aad = f'CHRYA:FILEKEY:v2:kid={key_id}'.encode('utf-8')
    wrap = AESGCM(wrap_subkey).encrypt(knonce, filekey, wrap_aad)
    encrypted = ChaCha20Poly1305(filekey).encrypt(nonce, bytes(data), b'CHRYA:FILE:v2')
    return b'CHRYAF02' + int(key_id).to_bytes(2, 'big') + knonce + wrap + nonce + encrypted


def decrypt_file(blob: bytes, master_key: bytes, *, keyring: KeyRing | None = None) -> bytes:
    """Verify Poly1305 & GCM tags and decrypt file blob (supports CHRYAF02 and legacy CHRYAF01)."""
    if not isinstance(blob, (bytes, bytearray)):
        raise ValueError('Bukan berkas CHRYA BOX')
    if blob.startswith(b'CHRYAF02'):
        if len(blob) < 8 + 2 + 12 + 48 + 12 + 16:
            raise ValueError('Bukan berkas CHRYA BOX atau header rusak')
        try:
            kid = int.from_bytes(blob[8:10], 'big')
            knonce, wrap, nonce, ct = blob[10:22], blob[22:70], blob[70:82], blob[82:]
            base_key = keyring.get_key(kid) if keyring is not None else master_key
            wrap_subkey = derive_subkey(base_key, 'FILE', key_id=kid)
            wrap_aad = f'CHRYA:FILEKEY:v2:kid={kid}'.encode('utf-8')
            filekey = AESGCM(wrap_subkey).decrypt(knonce, wrap, wrap_aad)
            return ChaCha20Poly1305(filekey).decrypt(nonce, ct, b'CHRYA:FILE:v2')
        except (InvalidTag, ValueError) as e:
            raise ValueError('File gagal diverifikasi/dekripsi') from e
    elif blob.startswith(b'CHRYAF01'):
        if len(blob) < 8 + 12 + 48 + 12 + 16:
            raise ValueError('Bukan berkas CHRYA BOX')
        try:
            knonce, wrap, nonce, ct = blob[8:20], blob[20:68], blob[68:80], blob[80:]
            filekey = AESGCM(master_key).decrypt(knonce, wrap, b'CHRYA:FILEKEY:v1')
            return ChaCha20Poly1305(filekey).decrypt(nonce, ct, b'CHRYA:FILE:v1')
        except InvalidTag as e:
            raise ValueError('File gagal diverifikasi/dekripsi') from e
    else:
        raise ValueError('Bukan berkas CHRYA BOX')


def lsb_embed(image_data: bytes, secret: str, master_key: bytes) -> bytes:
    from PIL import Image, UnidentifiedImageError
    from io import BytesIO
    try:
        image = Image.open(BytesIO(image_data))
        if image.width * image.height > 4_000_000:
            raise ValueError('Gambar maksimum 4 megapiksel')
        image = image.convert('RGB')
    except (UnidentifiedImageError, OSError) as e:
        raise ValueError('File gambar tidak valid') from e
    payload = encrypt_text(secret, master_key, context='STEGO').encode('utf-8')
    blob = b'CHBX' + len(payload).to_bytes(4, 'big') + payload
    pixels = bytearray(image.tobytes())
    if len(blob) * 8 > len(pixels):
        raise ValueError('Gambar terlalu kecil untuk pesan')
    for i in range(len(blob) * 8):
        pixels[i] = (pixels[i] & 254) | ((blob[i // 8] >> (7 - i % 8)) & 1)
    output = BytesIO()
    Image.frombytes('RGB', image.size, bytes(pixels)).save(output, format='PNG')
    return output.getvalue()


def lsb_extract(data: bytes, master_key: bytes, *, keyring: KeyRing | None = None) -> str:
    from PIL import Image, UnidentifiedImageError
    from io import BytesIO
    try:
        im = Image.open(BytesIO(data))
        im.load()
        pixels = im.convert('RGB').tobytes()
    except (UnidentifiedImageError, OSError) as e:
        raise ValueError('Gambar tidak valid') from e

    def read_bytes(start: int, n: int):
        out = bytearray(n)
        for i in range(n * 8):
            out[i // 8] |= (pixels[start + i] & 1) << (7 - i % 8)
        return bytes(out)

    if len(pixels) < 64 or read_bytes(0, 4) != b'CHBX':
        raise ValueError('Tidak ada pesan rahasia CHRYA BOX')
    n = int.from_bytes(read_bytes(32, 4), 'big')
    if n < 30 or n > 1_000_000 or (n + 8) * 8 > len(pixels):
        raise ValueError('Payload steganografi rusak')
    try:
        return decrypt_text(read_bytes(64, n).decode('utf-8'), master_key, context='STEGO', keyring=keyring)
    except UnicodeDecodeError as e:
        raise ValueError('Payload tidak valid') from e


def make_hash(index, ts, actor_id, action, resource, previous):
    obj = {'index': index, 'ts': ts, 'actor': actor_id, 'action': action, 'resource': resource, 'prev': previous}
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def compute_merkle_root(hashes_list: Sequence[str]) -> str:
    """Compute a SHA-256 Merkle root over all block hashes up to a checkpoint."""
    if not hashes_list:
        return '0' * 64
    layer = [bytes.fromhex(h) for h in hashes_list]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(hashlib.sha256(b'\x01' + layer[i] + layer[i + 1]).digest())
        layer = next_layer
    return layer[0].hex()


def ledger_signing_keypair(master_key: bytes) -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Derive a deterministic Ed25519 signing key for ledger checkpoints from the master key."""
    seed = derive_subkey(master_key, 'LEDGER_ED25519_SIGNING', key_id=1)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv, priv.public_key()


def sign_ledger_checkpoint(up_to_index: int, block_hash: str, merkle_root: str, master_key: bytes) -> dict:
    priv, pub = ledger_signing_keypair(master_key)
    msg = f'CHRYA-CHECKPOINT:v1:{up_to_index}:{block_hash}:{merkle_root}'.encode('utf-8')
    sig = priv.sign(msg)
    pub_raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        'up_to_index': up_to_index,
        'block_hash': block_hash,
        'merkle_root': merkle_root,
        'signature': b64(sig),
        'public_key': b64(pub_raw),
    }


def verify_ledger_checkpoint(up_to_index: int, block_hash: str, merkle_root: str, signature_b64: str, public_key_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(ub64(public_key_b64))
        msg = f'CHRYA-CHECKPOINT:v1:{up_to_index}:{block_hash}:{merkle_root}'.encode('utf-8')
        pub.verify(ub64(signature_b64), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
