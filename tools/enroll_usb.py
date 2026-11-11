"""Usage:
  python tools/enroll_usb.py E:\\            # Enroll new USB flashdrive
  python tools/enroll_usb.py --rotate E:\\   # Replace/rotate USB key and revoke old token
  python tools/enroll_usb.py --revoke        # Revoke lost/damaged USB dongle
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usb_dongle import USBGuard

if __name__ == '__main__':
    instance = Path(__file__).resolve().parents[1] / 'instance'
    guard = USBGuard(instance)
    if len(sys.argv) == 2 and sys.argv[1] == '--revoke':
        if guard.revoke_current('lost_or_revoked'):
            print('Dongle lama berhasil dicabut (revoked).')
            sys.exit(0)
        else:
            print('ERROR: Belum ada dongle terdaftar.')
            sys.exit(1)
    elif len(sys.argv) == 3 and sys.argv[1] == '--rotate':
        try:
            info = guard.rotate_or_replace(sys.argv[2])
            print(f"Dongle dirotasi di: {info['path']} (key_id={info['key_id']}, serial={info['volume_serial']})")
            sys.exit(0)
        except ValueError as exc:
            print('ERROR:', exc)
            sys.exit(1)
    elif len(sys.argv) == 2:
        try:
            print('Dongle didaftarkan di:', guard.enroll(sys.argv[1]))
        except ValueError as exc:
            print('ERROR:', exc)
            sys.exit(1)
    else:
        print('Gunakan: python tools/enroll_usb.py E:\\  atau  --rotate E:\\  atau  --revoke')
        sys.exit(2)
