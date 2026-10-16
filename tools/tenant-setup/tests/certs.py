"""Test certificates, made at test time (no key is committed)."""

import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def make(*, bits: int = 2048, days: int = 730, ec_key: bool = False, starts_days_ago: int = 1):
    key = ec.generate_private_key(ec.SECP256R1()) if ec_key else rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RestoreProof Worker")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=starts_days_ago))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")


def thumbprint(cert) -> str:
    return hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
