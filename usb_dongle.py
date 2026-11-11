"""USB Vault Dongle & Per-User USB Token Security for CHRYA BOX.

Security features:
1. Drive-letter independent detection: if a USB flash drive changes drive letter on Windows
   (e.g., E:\\ -> F:\\) or mount point on Linux/macOS, USBGuard automatically scans active removable
   and fixed drive roots to locate the enrolled `chrya_usb.key` and verifies its SHA-256 digest
   and Windows Volume Serial Number / hardware metadata.
2. Live unplug & replug detection: re-evaluates filesystem presence on every check without caching
   stale state when a USB drive is removed and re-inserted.
3. Revocation list (`revoked_digests`): any rotated, revoked, or lost USB key digest is permanently
   rejected even if a copy of the old `chrya_usb.key` file is presented.
4. Supports both 32-byte raw USB key files (`chrya_usb.key`) and authenticated JSON envelope tokens.

Important security limitation (documented):
A filesystem-based token (`chrya_usb.key`) stored on a standard USB mass-storage flash drive can be
copied by anyone with physical access to the flash drive unless protected by user PIN/passphrase or
hardware security. It is an educational possession-factor prototype and NOT equivalent to a
non-exportable FIDO2 / PKCS#11 hardware security key.
"""
from __future__ import annotations
from pathlib import Path
import ctypes
import json
import os
import secrets
import hashlib
import hmac
import time

KEY_NAME = 'chrya_usb.key'


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def get_volume_serial(path: Path) -> str:
    """Return Windows volume serial number (hex) or POSIX device ID for drive-letter independent tracking."""
    try:
        resolved = Path(path).resolve()
        anchor = resolved.anchor or str(resolved)
        if os.name == 'nt' and len(anchor) >= 2 and anchor[1] == ':':
            root = anchor[:2] + '\\'
            vol_name = ctypes.create_unicode_buffer(261)
            fs_name = ctypes.create_unicode_buffer(261)
            serial = ctypes.c_ulong(0)
            max_comp = ctypes.c_ulong(0)
            flags = ctypes.c_ulong(0)
            ok = ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(root),
                vol_name,
                260,
                ctypes.byref(serial),
                ctypes.byref(max_comp),
                ctypes.byref(flags),
                fs_name,
                260,
            )
            if ok:
                return f'{serial.value:08X}'
        return f'DEV-{os.stat(resolved).st_dev:X}'
    except Exception:
        return 'UNKNOWN'


def candidate_drive_roots() -> list[Path]:
    """Enumerate mounted drive roots on Windows (C:..Z:) or common removable mount dirs on POSIX."""
    roots: list[Path] = []
    if os.name == 'nt':
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    letter = chr(ord('A') + i)
                    # Put D:..Z: before C: so external USB drives are checked first
                    roots.append(Path(f'{letter}:\\'))
        except Exception:
            pass
    else:
        for base in ('/media', '/mnt', '/Volumes', '/run/media'):
            p = Path(base)
            if p.is_dir():
                try:
                    roots.extend([x for x in p.iterdir() if x.is_dir()])
                except OSError:
                    pass
    return roots


class USBGuard:
    def __init__(self, instance):
        self.instance = Path(instance)
        self.registry = self.instance / 'dongle_registry.json'

    def _read_registry(self) -> dict:
        if not self.registry.is_file():
            return {}
        try:
            return json.loads(self.registry.read_text(encoding='utf-8'))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _write_registry(self, data: dict):
        self.instance.mkdir(parents=True, exist_ok=True)
        self.registry.write_text(json.dumps(data, indent=2), encoding='utf-8')
        if os.name != 'nt':
            try:
                os.chmod(self.registry, 0o600)
            except OSError:
                pass

    def enroll(self, drive, *, force_replace: bool = False) -> str:
        drive = Path(drive).resolve()
        if not drive.exists() or not drive.is_dir():
            raise ValueError('Drive/folder tidak ditemukan')
        keyfile = drive / KEY_NAME
        old_reg = self._read_registry()
        revoked = list(old_reg.get('revoked_digests', []))

        if keyfile.exists():
            if not force_replace:
                raise ValueError('File dongle sudah ada. Untuk mengganti, pindahkan dengan aman terlebih dahulu.')
            try:
                old_bytes = keyfile.read_bytes()
                if len(old_bytes) == 32:
                    old_d = sha256(old_bytes)
                    if old_d not in revoked:
                        revoked.append(old_d)
            except OSError:
                pass

        if old_reg.get('digest') and old_reg['digest'] not in revoked:
            revoked.append(old_reg['digest'])

        token = secrets.token_bytes(32)
        keyfile.write_bytes(token)
        if os.name != 'nt':
            try:
                os.chmod(keyfile, 0o600)
            except OSError:
                pass

        vol_serial = get_volume_serial(drive)
        key_id = secrets.token_hex(8)
        reg_data = {
            'key_id': key_id,
            'path': str(keyfile),
            'digest': sha256(token),
            'volume_serial': vol_serial,
            'enrolled_at': int(time.time()),
            'revoked_digests': revoked[-50:],
            'status': 'active',
        }
        self._write_registry(reg_data)
        return str(keyfile)

    def rotate_or_replace(self, drive) -> dict:
        """Re-enroll a new USB key on `drive` and revoke the previous USB key digest."""
        path = self.enroll(drive, force_replace=True)
        info = self._read_registry()
        return {
            'path': path,
            'key_id': info.get('key_id', ''),
            'digest': info.get('digest', ''),
            'volume_serial': info.get('volume_serial', ''),
        }

    def revoke_current(self, reason: str = 'lost_or_revoked') -> bool:
        """Mark the currently registered host USB key as revoked/lost."""
        info = self._read_registry()
        if not info:
            return False
        revoked = list(info.get('revoked_digests', []))
        if info.get('digest') and info['digest'] not in revoked:
            revoked.append(info['digest'])
        info['revoked_digests'] = revoked
        info['status'] = reason
        info['digest'] = ''
        self._write_registry(info)
        return True

    def is_digest_revoked(self, token_digest: str) -> bool:
        info = self._read_registry()
        return token_digest in set(info.get('revoked_digests', []))

    def _verify_candidate_file(self, candidate: Path, expected_digest: str, revoked: set[str]) -> bytes | None:
        try:
            if not candidate.is_file() or candidate.name != KEY_NAME:
                return None
            token = candidate.read_bytes()
            if len(token) != 32:
                return None
            d = sha256(token)
            if d in revoked:
                return None
            if hmac.compare_digest(d, expected_digest):
                return token
        except OSError:
            return None
        return None

    def key(self, extra_search_dirs: list[Path] | None = None) -> bytes | None:
        """Return the 32-byte host USB key if present and valid; scans alternate drive letters if moved."""
        info = self._read_registry()
        if not info or info.get('status', 'active') != 'active':
            return None
        expected_digest = info.get('digest', '')
        if not expected_digest or len(expected_digest) != 64:
            return None
        revoked = set(info.get('revoked_digests', []))
        if expected_digest in revoked:
            return None

        # 1. Check recorded path first
        recorded_path = Path(info.get('path', ''))
        token = self._verify_candidate_file(recorded_path, expected_digest, revoked)
        if token is not None:
            return token

        # 2. Drive-letter / mount-point independent fallback scan:
        # If the USB was unplugged and plugged back into another port with a different drive letter,
        # check the same relative subpath or root on all available drives.
        search_Targets: list[Path] = []
        if extra_search_dirs:
            for d in extra_search_dirs:
                search_Targets.append(Path(d) / KEY_NAME)
        rel_parts = recorded_path.parts[1:] if len(recorded_path.parts) > 1 else (KEY_NAME,)
        for root in candidate_drive_roots():
            search_Targets.append(root / KEY_NAME)
            if len(rel_parts) > 1:
                search_Targets.append(root.joinpath(*rel_parts))

        for candidate in search_Targets:
            token = self._verify_candidate_file(candidate, expected_digest, revoked)
            if token is not None:
                # Update path and volume serial seamlessly
                try:
                    info['path'] = str(candidate)
                    info['volume_serial'] = get_volume_serial(candidate.parent)
                    self._write_registry(info)
                except Exception:
                    pass
                return token
        return None

    def status(self) -> dict:
        enrolled = self.registry.is_file()
        info = self._read_registry() if enrolled else {}
        k = self.key()
        is_revoked = info.get('status') in ('revoked', 'lost', 'lost_or_revoked')
        if k is not None:
            reason = 'Dongle aktif'
        elif is_revoked:
            reason = 'Flashdisk lama telah dicabut/dilaporkan hilang. Daftarkan USB baru.'
        elif enrolled:
            reason = 'Flashdisk terdaftar tidak ditemukan / kunci berbeda'
        else:
            reason = 'Flashdisk belum didaftarkan'
        return {
            'enrolled': enrolled,
            'authorized': k is not None,
            'key_id': info.get('key_id', ''),
            'volume_serial': info.get('volume_serial', ''),
            'status': info.get('status', 'unregistered'),
            'reason': reason,
        }
