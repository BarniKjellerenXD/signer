# Signer

Self-hosted iOS app signing for people with a paid Apple Developer account. Upload an `.ipa` from your
phone, the server signs it with [zsign](https://github.com/zhlynn/zsign), and you tap **Install** in Safari.
No Mac, no computer, no AltStore refreshes. The site is reachable only through your
[Tailscale](https://tailscale.com) network.

- Upload an `.ipa` (file or direct link), sign it, and install it over the air (`itms-services`)
- Register an iPhone with one tap: a temporary profile reads its UDID, nothing stays installed
- With an App Store Connect API key, the Apple side runs itself: it creates the certificate from the
  server's own CSR, the wildcard App ID and the Ad Hoc profile, registers new iPhones, and re-signs all apps
- Options: new bundle ID or name, remove extensions or the Watch app, remove device restrictions, show the
  app's files in the Files app, inject `.dylib` tweaks
- Warns about App Store-encrypted IPAs, which would crash on launch
- Exports `.p12` + `.mobileprovision` for on-device signers like Feather
- Mobile-first UI. Data lives in JSON files, no database

Apps are signed as **Ad Hoc** (Apple Distribution certificate + profile listing your iPhones). They need
no Developer Mode, no "Trust" step and no weekly refresh. They keep working until the profile expires
(1 year) or Apple revokes the certificate.

## What you need

- A Linux server with Docker and Docker Compose (x86_64; arm64 builds but is untested)
- A Tailscale account (free plan is fine), with the Tailscale app on every iPhone that installs apps
- A paid Apple Developer Program membership ($99/year). You can share one with friends; Apple allows 100
  iPhones per membership year

## Setup

### 1. Tailscale

1. On https://login.tailscale.com/admin/dns, make sure **MagicDNS** is on and enable **HTTPS Certificates**.
   Note your tailnet name (like `tail1234.ts.net`).
2. On https://login.tailscale.com/admin/settings/keys, click **Generate auth key**. The defaults are fine;
   it's used once.

### 2. Server

```bash
git clone https://github.com/BarniKjellerenXD/signer.git
cd signer
cp .env.example .env
nano .env        # set PUBLIC_URL, TS_AUTHKEY, and OWNER_LOGINS if you know it
docker compose up -d --build
```

- `PUBLIC_URL` = `https://<TS_HOSTNAME>.<your tailnet>.ts.net`, e.g. `https://signer.tail1234.ts.net`
- `OWNER_LOGINS` = your Tailscale login, e.g. `yourname@github` or `you@gmail.com`. Only these logins
  can open **Setup**. If you're unsure, leave it empty and open the site: the bottom of the page says
  *Signed in as …*. Put that into `.env` and run `docker compose up -d` again.

After the first start you can delete `TS_AUTHKEY` from `.env`. In the Tailscale admin console under
**Machines**, open the new `signer` machine and choose **Disable key expiry**, otherwise it drops off
after 180 days.

The first page load can take a few seconds while Tailscale issues the HTTPS certificate.

### 3. Apple (on the site → Setup)

Recommended: let the server do everything with an App Store Connect API key.

1. Go to https://appstoreconnect.apple.com/access/integrations/api. The first time, click **Request Access**.
2. **Team Keys → Generate API Key**, Access **Admin**.
3. Download the `AuthKey_XXXXXXXXXX.p8` file (Apple only lets you download it once) and note the
   **Issuer ID** and **Key ID**.
4. On the site, open **Setup**, enter all three and save. The server tests the key, creates an Apple
   Distribution certificate from its own CSR, and creates (or reuses) the wildcard App ID `*`.

You need an Admin key on the account. If you share a membership, the account holder can create a
separate key for you. Each Signer server makes its own certificate, so two servers on one account is fine.
Apple only allows a few Distribution certificates per account, though.

No API key? **Setup → Manual setup** walks you through it: download the server's CSR, create an Apple
Distribution certificate, a wildcard App ID and an Ad Hoc profile on developer.apple.com, and upload the
`.cer` and `.mobileprovision`. You can also import an existing `.p12`.

### 4. Each iPhone

With Tailscale on, open `https://signer.<tailnet>.ts.net/enroll` in **Safari**:

1. Enter a name and tap the button. Safari asks to download a profile: tap **Allow**.
2. Go to **Settings → Profile Downloaded → Install** and enter your passcode. iOS shows the profile as
   "Unverified"; that's normal.
3. Safari reopens with the UDID. With an API key, the server registers the phone with Apple, rebuilds the
   profile and re-signs all apps, which takes about a minute.

### 5. Install apps

On the main page, upload an `.ipa` or paste a direct link, wait for **Install**, and tap it. The app
appears on the home screen. Tailscale has to be on while installing, not while using the app.

## Sharing with friends

- Use the same server: in the Tailscale admin console, open the machine → **Share…**. Your friend
  accepts with his own Tailscale account and sees only this machine. He registers his iPhone at `/enroll`.
- Or host your own copy with this README.

## Good to know

- **The IPA must be decrypted.** App Store copies are FairPlay-encrypted; Signer warns you, and they
  crash on launch.
- **Same app as an App Store version already installed?** Set a new bundle ID in Options so both can
  live side by side.
- The wildcard App ID can't carry capabilities, so apps that need push notifications, iCloud or App Groups
  may lose those features.
- **New iPhone added?** Apps get re-signed automatically. Phones that already have an app keep working;
  the new phone installs the fresh copy.
- **After about a year**, press **Rebuild certificate & profile now** on Setup and reinstall the apps.
- If Apple revokes the certificate, apps won't open. Setup shows the certificate's live Apple (OCSP)
  status; rebuild to get a new one.

## Troubleshooting

| Problem | Fix |
|---|---|
| Site doesn't load | Tailscale on? HTTPS Certificates enabled in the tailnet DNS settings? `docker compose logs tailscale` |
| "Unable to install" | The phone isn't in the profile. Devices page: it must say *in profile*. Then re-sign or reinstall |
| Install button does nothing | Use Safari, not an in-app browser |
| App crashes on launch | Encrypted IPA, or profile expired / certificate revoked (see Setup) |
| Setup says "Only the owner…" | Put the login from the page footer into `OWNER_LOGINS`, then `docker compose up -d` |
| Registering a device never returns | Retry from `/enroll` in Safari with Tailscale on |

## Operations

```bash
docker compose logs -f app          # app log
git pull && docker compose up -d --build   # update
```

Everything (private key, certificate, profile, apps) is in the `signer-data` Docker volume. Back it up if
you care about it; the certificate can always be recreated with the API key.

### Security

- The site is only reachable inside your tailnet (no Funnel, no published ports). The private key is made
  on the server and never leaves it unless you export a `.p12`.
- Anyone who can reach the site can upload, install and register devices. Only `OWNER_LOGINS` can see
  Setup, manage the API key or export signing files.
- The App Store Connect key has Admin rights on your developer account. Remove it on Setup (and revoke
  it in App Store Connect) if you stop using Signer.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | (required) | `https://` address of the site as phones reach it |
| `OWNER_LOGINS` | empty | Comma-separated logins allowed into Setup |
| `OWNER_HEADER` | `Tailscale-User-Login` | Header carrying the login (change only if you use another auth proxy) |
| `SITE_NAME` | `Signer` | Name shown in the UI and used for Apple resources |
| `ID_PREFIX` | `local.signer` | Reverse-DNS prefix for the enrollment profile and the fallback wildcard App ID |
| `ZIP_LEVEL` | `3` | Compression of signed IPAs (0–9) |
| `MAX_DOWNLOAD_MB` | `4096` | Size limit for "paste a link" downloads |

Without Tailscale: any reverse proxy with a **valid** HTTPS certificate works (OTA install needs one).
Set `PUBLIC_URL` and point the proxy at `app:8080`. For Setup to work, your proxy must authenticate users
and pass the login in a header (`OWNER_HEADER`).

## Development

`tests/smoke.sh` runs the whole flow against a throwaway instance with a fake (non-Apple) identity:

```bash
docker build -t signer:test .
docker run -d --name signer-test -p 127.0.0.1:18080:8080 -e PUBLIC_URL=https://signer.example.ts.net \
  -e OWNER_LOGINS=owner@example signer:test
OWNER_LOGIN=owner@example tests/smoke.sh http://127.0.0.1:18080 some.ipa
docker rm -f signer-test
```

It needs `openssl`, `curl`, `python3` and `unzip` on the host (plus `zsign` for one optional check).

## Credits

- [zsign](https://github.com/zhlynn/zsign) by zhlynn (MIT), the signing engine; release binaries are
  vendored with pinned checksums in `vendor/`
- Built with FastAPI, Jinja2 and cryptography

MIT licensed, see `LICENSE`.
