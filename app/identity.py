"""Signing identity on disk: private key (never leaves the box), CSR, Apple cert, provisioning profile, p12."""
import datetime as dt
import plistlib
import secrets
import subprocess
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from .config import APPLE_NAME, CSR_EMAIL, DATA, ZSIGN
from .store import atomic_write

ID = DATA / "identity"
KEY = ID / "key.pem"
CSR = ID / "csr.pem"
CERT = ID / "cert.pem"
CHAIN = ID / "chain.pem"          # optional extra CA certs (only needed for non-Apple test identities)
PROFILE = ID / "profile.mobileprovision"
P12 = ID / "sign.p12"             # internal p12 handed to zsign
P12PASS = ID / "sign.p12.pass"

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def load_key():
    if not KEY.exists():
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        atomic_write(KEY, k.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        CSR.unlink(missing_ok=True)
    return serialization.load_pem_private_key(KEY.read_bytes(), None)


def csr_pem() -> str:
    k = load_key()
    if CSR.exists():
        return CSR.read_text()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.EMAIL_ADDRESS, CSR_EMAIL),
               x509.NameAttribute(NameOID.COMMON_NAME, APPLE_NAME),
           ])).sign(k, hashes.SHA256()))
    pem = csr.public_bytes(PEM).decode()
    atomic_write(CSR, pem.encode(), 0o644)
    return pem


def parse_cert(data: bytes) -> x509.Certificate:
    data = data.strip()
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def load_cert():
    return parse_cert(CERT.read_bytes()) if CERT.exists() else None


def cert_matches_key(cert) -> bool:
    if not KEY.exists() or cert is None:
        return False
    return load_key().public_key().public_bytes(DER, SPKI) == cert.public_key().public_bytes(DER, SPKI)


def _attr(name, oid):
    v = name.get_attributes_for_oid(oid)
    return v[0].value if v else ""


def cert_info(cert) -> dict:
    exp = cert.not_valid_after_utc
    return {
        "cn": _attr(cert.subject, NameOID.COMMON_NAME),
        "team": _attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "org": _attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer": _attr(cert.issuer, NameOID.COMMON_NAME),
        "serial": format(cert.serial_number, "X"),
        "expires_ts": int(exp.timestamp()),
        "matches_key": cert_matches_key(cert),
    }


def _chain():
    if not CHAIN.exists():
        return []
    return x509.load_pem_x509_certificates(CHAIN.read_bytes())


def _legacy_enc(password: bytes):
    # 3DES/SHA1 p12: readable by iOS, Feather/ESign, old OpenSSL builds
    return (serialization.PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(password))


def rebuild_p12() -> None:
    cert = load_cert()
    if not cert or not cert_matches_key(cert):
        P12.unlink(missing_ok=True)
        return
    pw = secrets.token_urlsafe(18)
    data = pkcs12.serialize_key_and_certificates(b"sign", load_key(), cert, _chain() or None, _legacy_enc(pw.encode()))
    atomic_write(P12PASS, pw.encode())
    atomic_write(P12, data)


def p12_password() -> str:
    return P12PASS.read_text().strip()


def export_p12(password: str) -> bytes:
    cert = load_cert()
    if not cert or not cert_matches_key(cert):
        raise ValueError("No usable certificate yet")
    return pkcs12.serialize_key_and_certificates(APPLE_NAME.encode(), load_key(), cert, _chain() or None,
                                                 _legacy_enc(password.encode()))


def install_cert(cert, chain: bytes | None = None) -> dict:
    if not cert_matches_key(cert):
        raise ValueError("That certificate was not made from this server's CSR (public key doesn't match). "
                         "Download the CSR from this page, create the certificate from it, then upload the .cer.")
    atomic_write(CERT, cert.public_bytes(PEM), 0o644)
    if chain is not None:
        if chain.strip():
            atomic_write(CHAIN, chain, 0o644)
        else:
            CHAIN.unlink(missing_ok=True)
    rebuild_p12()
    return cert_info(cert)


def import_p12(data: bytes, password: str) -> dict:
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, password.encode() if password else None)
    except Exception as e:
        raise ValueError(f"Couldn't open the .p12 (wrong password?): {e}")
    if key is None or cert is None:
        raise ValueError("The .p12 must contain both the private key and the certificate")
    atomic_write(KEY, key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    CSR.unlink(missing_ok=True)
    chain = b"".join(c.public_bytes(PEM) for c in (extra or []))
    return install_cert(cert, chain)


# ---- provisioning profiles ----

def parse_profile(data: bytes) -> dict:
    s, e = data.find(b"<?xml"), data.find(b"</plist>")
    if s < 0 or e < 0:
        raise ValueError("That file is not a provisioning profile (.mobileprovision)")
    return plistlib.loads(data[s:e + 8])


def _ts(d) -> int:
    if isinstance(d, dt.datetime):
        return int(d.replace(tzinfo=dt.timezone.utc).timestamp() if d.tzinfo is None else d.timestamp())
    return 0


def profile_info(p: dict) -> dict:
    ents = p.get("Entitlements", {})
    appid = ents.get("application-identifier", "")
    pattern = appid.split(".", 1)[1] if "." in appid else appid
    if pattern == "*":
        prefix = ""
    elif pattern.endswith(".*"):
        prefix = pattern[:-1]
    else:
        prefix = None                       # explicit App ID: only that one bundle id
    if p.get("ProvisionsAllDevices"):
        kind = "enterprise"
    elif ents.get("get-task-allow"):
        kind = "development"
    elif p.get("ProvisionedDevices"):
        kind = "ad hoc"
    else:
        kind = "app store"
    return {
        "name": p.get("Name", ""), "uuid": p.get("UUID", ""),
        "team": (p.get("TeamIdentifier") or [""])[0], "team_name": p.get("TeamName", ""),
        "app_id": appid, "bundle_pattern": pattern, "wildcard_prefix": prefix, "kind": kind,
        "devices": [d.lower() for d in p.get("ProvisionedDevices", [])],
        "expires_ts": _ts(p.get("ExpirationDate")), "created_ts": _ts(p.get("CreationDate")),
    }


def profile_has_cert(p: dict, cert) -> bool:
    der = cert.public_bytes(DER)
    return any(bytes(c) == der for c in p.get("DeveloperCertificates", []))


def install_profile(data: bytes) -> dict:
    p = parse_profile(data)
    cert = load_cert()
    if cert is None:
        raise ValueError("Add the certificate first, then the profile")
    if not profile_has_cert(p, cert):
        raise ValueError("This profile doesn't include the server's certificate. When creating the ad hoc "
                         "profile, tick the certificate that was made from this server's CSR.")
    atomic_write(PROFILE, data, 0o644)
    return profile_info(p)


def current_profile():
    if not PROFILE.exists():
        return None
    p = parse_profile(PROFILE.read_bytes())
    info = profile_info(p)
    cert = load_cert()
    info["cert_ok"] = bool(cert and profile_has_cert(p, cert))
    return info


_ocsp = {"t": 0, "serial": None, "v": "unknown"}


def ocsp_status() -> str:
    """Ask Apple (via zsign -C) whether the certificate is revoked. Cached 6 h."""
    cert = load_cert()
    if not cert:
        return "no certificate"
    serial = cert.serial_number
    if _ocsp["serial"] == serial and time.time() - _ocsp["t"] < 6 * 3600:
        return _ocsp["v"]
    try:
        out = subprocess.run([ZSIGN, "-C", str(CERT)], capture_output=True, text=True, timeout=20)
        line = next((l for l in (out.stdout + out.stderr).splitlines() if "OCSP:" in l), "")
        v = line.split("OCSP:", 1)[1].strip() if line else "unknown"
    except Exception as e:
        v = f"check failed ({e.__class__.__name__})"
    _ocsp.update(t=time.time(), serial=serial, v=v)
    return v
