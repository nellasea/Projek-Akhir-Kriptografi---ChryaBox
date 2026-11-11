"""Generate a local self-signed X.509 TLS certificate + SAN for HTTPS on localhost & private LAN IP.
Usage:
  python tools/generate_https_cert.py [192.168.1.10]
Outputs:
  instance/certs/chrya_cert.pem
  instance/certs/chrya_key.pem
"""
from __future__ import annotations
import datetime
import ipaddress
import socket
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
CERT_DIR = ROOT / 'instance' / 'certs'


def generate_self_signed_cert(extra_ip: str | None = None) -> tuple[Path, Path]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'ID'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'CHRYA BOX Private Vault'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])
    san_entries: list[x509.GeneralName] = [
        x509.DNSName('localhost'),
        x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
    ]
    for candidate in filter(None, [extra_ip]):
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(candidate)))
        except ValueError:
            san_entries.append(x509.DNSName(candidate))
    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
        san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname_ip)))
    except Exception:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = CERT_DIR / 'chrya_cert.pem'
    key_path = CERT_DIR / 'chrya_key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return cert_path, key_path


if __name__ == '__main__':
    extra = sys.argv[1] if len(sys.argv) > 1 else None
    c_path, k_path = generate_self_signed_cert(extra)
    print('Sertifikat HTTPS berhasil dibuat:')
    print('  CHRYA_SSL_CERTFILE=' + str(c_path))
    print('  CHRYA_SSL_KEYFILE=' + str(k_path))
