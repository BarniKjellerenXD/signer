import os
import re
from pathlib import Path

DATA = Path(os.environ.get("DATA_DIR", "/data"))

# Absolute https:// address of this site as the iPhones see it, e.g. https://signer.tail1234.ts.net
# (OTA installs need absolute HTTPS URLs with a valid certificate).
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
if not PUBLIC_URL.startswith("https://"):
    raise SystemExit("PUBLIC_URL must be set to the https:// address of this site, "
                     "e.g. PUBLIC_URL=https://signer.tail1234.ts.net")

SITE_NAME = os.environ.get("SITE_NAME", "Signer").strip() or "Signer"
# Name usable in Apple resource names and file names (letters, digits, spaces)
APPLE_NAME = re.sub(r"[^A-Za-z0-9 ]", "", SITE_NAME).strip() or "Signer"
FILE_NAME = APPLE_NAME.replace(" ", "") or "Signer"

# Who may open /setup: logins found in OWNER_HEADER. With `tailscale serve` in front, that header is
# Tailscale-User-Login (e.g. you@github or you@gmail.com). Behind another auth proxy use its header.
OWNER_HEADER = os.environ.get("OWNER_HEADER", "Tailscale-User-Login").strip().lower()
OWNERS = {x.strip().lower() for x in os.environ.get("OWNER_LOGINS", "").split(",") if x.strip()}

# Reverse-DNS prefix for the enrollment profile id and the fallback wildcard App ID (<prefix>.*)
ID_PREFIX = os.environ.get("ID_PREFIX", "local.signer").strip().strip(".") or "local.signer"
CSR_EMAIL = os.environ.get("CSR_EMAIL", "signer@example.com").strip()

ZSIGN = os.environ.get("ZSIGN_BIN", "zsign")
ZIP_LEVEL = os.environ.get("ZIP_LEVEL", "3")
MAX_DOWNLOAD = int(os.environ.get("MAX_DOWNLOAD_MB", "4096")) * 1024 * 1024

for _d in ("identity", "secrets", "apps", "tmp"):
    (DATA / _d).mkdir(parents=True, exist_ok=True)
