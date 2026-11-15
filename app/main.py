import plistlib
import re
from contextlib import asynccontextmanager
import secrets
import shutil
import struct
import time
import urllib.parse
import uuid
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import identity, provision, signer, store
from .asc import ASC, ASCError
from .config import FILE_NAME, ID_PREFIX, OWNER_HEADER, OWNERS, PUBLIC_URL, SITE_NAME

BASE = Path(__file__).parent


@asynccontextmanager
async def lifespan(_app):
    identity.load_key()
    signer.startup()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
tpl = Jinja2Templates(directory=BASE / "templates")

AID_RE = re.compile(r"^[a-f0-9]{12}$")
UDID_RE = re.compile(r"^([0-9a-fA-F]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})$")
BID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,150}$")


# ---------- helpers ----------

def who(request: Request) -> str:
    return request.headers.get(OWNER_HEADER, "")


def is_owner(request: Request) -> bool:
    return who(request).lower() in OWNERS if who(request) else False


def require_owner(request: Request) -> None:
    if not is_owner(request):
        raise HTTPException(403, "Only the owner can do this")


def go(path: str, msg: str = "", err: str = "") -> RedirectResponse:
    q = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse(path + ("?" + urllib.parse.urlencode(q) if q else ""), status_code=303)


def png(w: int, h: int, rgb=(40, 44, 58)) -> bytes:
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))

    def chunk(t, data):
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


DEFAULT_ICON = png(120, 120)
TOUCH_ICON = png(180, 180, (201, 162, 39))


def itms(m: dict) -> str:
    url = f"{PUBLIC_URL}/m/{m['id']}/{m.get('rev', 0)}.plist"
    return "itms-services://?action=download-manifest&url=" + urllib.parse.quote(url, safe="")


def _ago(ts):
    if not ts:
        return ""
    s = int(time.time() - ts)
    for n, u in ((86400, "d"), (3600, "h"), (60, "min")):
        if s >= n:
            return f"{s // n} {u} ago"
    return "just now"


def _days(ts):
    return int((ts - time.time()) // 86400) if ts else 0


def _size(n):
    n = n or 0
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


tpl.env.filters.update(ago=_ago, days=_days, size=_size,
                       date=lambda ts: time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "",
                       itms=itms)


def page(request: Request, name: str, status_code: int = 200, **kw):
    st = store.load()
    ctx = {"site": SITE_NAME, "login": who(request), "owner": is_owner(request),
           "ident": provision.status(st), "task": st.get("task"), "public_url": PUBLIC_URL,
           "msg": request.query_params.get("msg", ""), "err": request.query_params.get("err", "")}
    ctx.update(kw)
    return tpl.TemplateResponse(request, name, ctx, status_code=status_code, headers={"Cache-Control": "no-store"})


def get_app(aid: str) -> dict:
    if not AID_RE.match(aid):
        raise HTTPException(404)
    m = store.app_load(aid)
    if not m:
        raise HTTPException(404)
    return m


def parse_opts(form) -> dict:
    o = {}
    bid = (form.get("bundle_id") or "").strip()
    if bid:
        if not BID_RE.match(bid):
            raise ValueError("Bundle ID may only contain letters, digits, dots and dashes")
        o["bundle_id"] = bid
    name = (form.get("name") or "").strip()[:60]
    if name:
        o["name"] = name
    mo = (form.get("min_os") or "").strip()
    if mo:
        if not re.fullmatch(r"\d{1,2}(\.\d{1,2}){0,2}", mo):
            raise ValueError("Minimum iOS must look like 15.0")
        o["min_os"] = mo
    for k in ("rm_extensions", "rm_watch", "rm_uisd", "enable_docs", "inject_ext"):
        if form.get(k):
            o[k] = True
    return o


async def save_upload(f: UploadFile, dest: Path) -> int:
    def cp():
        with open(dest, "wb") as out:
            shutil.copyfileobj(f.file, out, 1 << 20)
        return dest.stat().st_size
    n = await run_in_threadpool(cp)
    await f.close()
    return n


async def read_small(f, limit=2 << 20) -> bytes:
    if not isinstance(f, UploadFile) or not f.filename:
        return b""
    data = await f.read(limit + 1)
    await f.close()
    if len(data) > limit:
        raise ValueError("File too large")
    return data


# ---------- middleware ----------

@app.middleware("http")
async def guard(request: Request, call_next):
    if request.method == "POST" and not request.url.path.startswith("/enroll/cb/"):
        origin = request.headers.get("origin")
        if (origin and origin.rstrip("/") != PUBLIC_URL) or request.headers.get("sec-fetch-site") == "cross-site":
            return PlainTextResponse("Cross-site request blocked", status_code=403)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    msg = {403: "Only the owner can open this page.", 404: "Not found."}.get(exc.status_code, str(exc.detail))
    return page(request, "error.html", code=exc.status_code, text=msg, status_code=exc.status_code)


# ---------- apps ----------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    apps = store.app_list()
    busy = any(a.get("status") in ("queued", "signing", "downloading", "uploading") for a in apps)
    return page(request, "index.html", apps=apps, busy=busy)


@app.post("/upload")
async def upload(request: Request):
    form = await request.form(max_files=20, max_fields=50)
    try:
        opts = parse_opts(form)
    except ValueError as e:
        return go("/", err=str(e))
    f = form.get("ipa")
    url = (form.get("url") or "").strip()
    has_file = isinstance(f, UploadFile) and bool(f.filename)
    if not has_file and not url:
        return go("/", err="Pick an .ipa file or paste a link to one")
    if not has_file and not re.match(r"^https?://", url):
        return go("/", err="The link must start with https://")
    aid = secrets.token_hex(6)
    adir = store.app_dir(aid)
    adir.mkdir(parents=True)
    m = {"id": aid, "status": "uploading" if has_file else "downloading", "uploaded": int(time.time()),
         "by": who(request), "options": opts, "name": (f.filename if has_file else url.rsplit("/", 1)[-1])[:80],
         "source": f.filename if has_file else url}
    store.app_save(m)
    dylibs = [x for x in form.getlist("dylib") if isinstance(x, UploadFile) and x.filename]
    if dylibs:
        (adir / "inject").mkdir()
        for x in dylibs:
            nm = re.sub(r"[^A-Za-z0-9._-]", "_", Path(x.filename).name)
            if not nm.endswith(".dylib"):
                shutil.rmtree(adir)
                return go("/", err="Tweaks must be .dylib files")
            await save_upload(x, adir / "inject" / nm)
    if has_file:
        await save_upload(f, adir / "original.ipa")
        await run_in_threadpool(signer.ingest, aid)
    else:
        signer.enqueue_fetch(aid, url)
    return go(f"/app/{aid}")


@app.get("/app/{aid}", response_class=HTMLResponse)
def app_page(request: Request, aid: str):
    m = get_app(aid)
    busy = m.get("status") in ("queued", "signing", "downloading", "uploading")
    return page(request, "app.html", m=m, busy=busy)


@app.post("/app/{aid}/resign")
async def app_resign(request: Request, aid: str):
    m = get_app(aid)
    if m.get("fatal"):
        return go(f"/app/{aid}", err="This upload is broken; delete it and upload again")
    form = await request.form()
    try:
        store.app_update(aid, options=parse_opts(form))
    except ValueError as e:
        return go(f"/app/{aid}", err=str(e))
    signer.enqueue_sign(aid)
    return go(f"/app/{aid}", msg="Re-signing…")


@app.post("/app/{aid}/delete")
def app_delete(request: Request, aid: str):
    m = get_app(aid)
    shutil.rmtree(store.app_dir(m["id"]), ignore_errors=True)
    return go("/", msg=f"Deleted {m.get('name') or 'app'}")


@app.post("/resign-all")
def resign_all(request: Request):
    n = signer.resign_all()
    return go("/", msg=f"Re-signing {n} app(s)")


@app.get("/m/{aid}/{rev}.plist")
def manifest(aid: str, rev: str):
    m = get_app(aid)
    if m.get("status") != "signed":
        raise HTTPException(404)
    f = m["final"]
    ipa = f"{PUBLIC_URL}/d/{aid}/{m['rev']}.ipa"
    icon = f"{PUBLIC_URL}/i/{aid}.png"
    body = plistlib.dumps({"items": [{
        "assets": [{"kind": "software-package", "url": ipa},
                   {"kind": "display-image", "url": icon},
                   {"kind": "full-size-image", "url": icon}],
        "metadata": {"bundle-identifier": f["bundle_id"], "bundle-version": f.get("version") or "1.0",
                     "kind": "software", "title": f.get("name") or "App"}}]})
    return Response(body, media_type="text/xml", headers={"Cache-Control": "no-store"})


@app.get("/d/{aid}/{rev}.ipa")
def download(aid: str, rev: str):
    m = get_app(aid)
    p = store.app_dir(aid) / "signed.ipa"
    if not p.exists():
        raise HTTPException(404)
    nm = re.sub(r"[^A-Za-z0-9._ -]", "", (m.get("final") or {}).get("name") or "app").strip() or "app"
    return FileResponse(p, media_type="application/octet-stream", filename=f"{nm}.ipa")


@app.get("/i/{aid}.png")
def icon(aid: str):
    if AID_RE.match(aid) and (store.app_dir(aid) / "icon.png").exists():
        return FileResponse(store.app_dir(aid) / "icon.png", media_type="image/png")
    return Response(DEFAULT_ICON, media_type="image/png")


@app.get("/apple-touch-icon.png")
@app.get("/favicon.ico")
def touch_icon():
    return Response(TOUCH_ICON, media_type="image/png")


@app.get("/api/status")
def api_status():
    st = store.load()
    return JSONResponse({"task": st.get("task"),
                         "apps": {a["id"]: a.get("status") for a in store.app_list()}})


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


# ---------- devices + UDID enrollment ----------

@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request):
    st = store.load()
    prof = identity.current_profile()
    in_profile = set(prof["devices"]) if prof else set()
    devs = sorted(st["devices"], key=lambda d: (bool(d.get("disabled")), -d.get("added", 0)))
    return page(request, "devices.html", devices=devs, in_profile=in_profile)


@app.post("/devices/add")
async def devices_add(request: Request):
    require_owner(request)
    form = await request.form()
    udid = (form.get("udid") or "").strip()
    name = provision.clean_name(form.get("name") or "")
    if not UDID_RE.match(udid):
        return go("/devices", err="That doesn't look like a UDID (40 hex chars, or 8-16 with a dash)")
    add_device(udid, name, who(request), "manual")
    return go("/devices", msg=after_device_added())


@app.post("/devices/{udid}/disable")
def devices_disable(request: Request, udid: str):
    require_owner(request)
    if not UDID_RE.match(udid):
        raise HTTPException(404)
    signer.run_task("Remove device", provision.disable_device, udid)
    return go("/devices", msg="Removing device and rebuilding the profile…")


def add_device(udid: str, name: str, by: str, source: str, product: str = "", version: str = "") -> None:
    with store.tx() as d:
        for x in d["devices"]:
            if x["udid"].lower() == udid.lower():
                x.update(name=name or x["name"], disabled=False, product=product or x.get("product"),
                         version=version or x.get("version"))
                break
        else:
            d["devices"].append({"udid": udid, "name": name, "product": product, "version": version,
                                 "added": int(time.time()), "by": by, "source": source})
    store.log(f"Device enrolled: {name} {product} ({udid}) by {by or 'unknown'}")


def after_device_added() -> str:
    if provision.client():
        signer.run_task("Add device to profile", provision.full_setup)
        return "Saved. Registering it with Apple and rebuilding the profile…"
    return "Saved. Add this UDID on developer.apple.com and update the profile (no API key configured)."


@app.get("/enroll", response_class=HTMLResponse)
def enroll(request: Request):
    return page(request, "enroll.html")


@app.get("/enroll/profile")
def enroll_profile(request: Request, name: str = ""):
    token = secrets.token_urlsafe(16)
    with store.tx() as d:
        now = int(time.time())
        d["enroll"] = {k: v for k, v in d["enroll"].items() if now - v["t"] < 7200}
        d["enroll"][token] = {"t": now, "name": provision.clean_name(name) if name.strip() else "",
                              "by": who(request), "udid": None}
    payload = {
        "PayloadContent": {"URL": f"{PUBLIC_URL}/enroll/cb/{token}",
                           "DeviceAttributes": ["UDID", "IMEI", "ICCID", "VERSION", "PRODUCT"]},
        "PayloadOrganization": SITE_NAME,
        "PayloadDisplayName": f"{SITE_NAME}: register this device",
        "PayloadVersion": 1,
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadIdentifier": f"{ID_PREFIX}.enroll",
        "PayloadDescription": "Sends this device's UDID to your signing server so apps can be signed for it. "
                              "Nothing stays installed.",
        "PayloadType": "Profile Service",
    }
    return Response(plistlib.dumps(payload), media_type="application/x-apple-aspen-config",
                    headers={"Content-Disposition": 'attachment; filename="register-device.mobileconfig"',
                             "Cache-Control": "no-store"})


@app.post("/enroll/cb/{token}")
async def enroll_cb(request: Request, token: str):
    body = await request.body()
    if len(body) > 256 * 1024:
        return PlainTextResponse("too large", status_code=413)
    s, e = body.find(b"<?xml"), body.find(b"</plist>")
    if s < 0 or e < 0:
        return PlainTextResponse("bad request", status_code=400)
    try:
        info = plistlib.loads(body[s:e + 8])
    except Exception:
        return PlainTextResponse("bad plist", status_code=400)
    udid = str(info.get("UDID", "")).strip()
    st = store.load()
    tok = st["enroll"].get(token)
    if not tok or not UDID_RE.match(udid):
        return PlainTextResponse("unknown or expired enrollment link - start again", status_code=400)
    product, version = str(info.get("PRODUCT", "")), str(info.get("VERSION", ""))
    name = tok["name"] or provision.clean_name(f"{(tok['by'] or 'iPhone').split('@')[0]} {product}")
    add_device(udid, name, tok["by"], "enroll", product, version)
    with store.tx() as d:
        if token in d["enroll"]:
            d["enroll"][token].update(udid=udid, product=product, version=version, name=name)
    after_device_added()
    # 301 makes iOS leave Settings and open the done page in Safari
    return RedirectResponse(f"{PUBLIC_URL}/enroll/done/{token}", status_code=301)


@app.get("/enroll/done/{token}", response_class=HTMLResponse)
def enroll_done(request: Request, token: str):
    tok = store.load()["enroll"].get(token)
    if not tok or not tok.get("udid"):
        return go("/enroll", err="That enrollment link expired or wasn't completed - try again")
    return page(request, "enroll_done.html", tok=tok)


# ---------- setup (owner only) ----------

@app.get("/setup", response_class=HTMLResponse)
async def setup(request: Request):
    require_owner(request)
    st = store.load()
    ocsp = await run_in_threadpool(identity.ocsp_status) if identity.CERT.exists() else ""
    return page(request, "setup.html", st=st, ocsp=ocsp, has_key=identity.KEY.exists(),
                log=list(reversed(st["log"][-40:])))


@app.post("/setup/asc")
async def setup_asc(request: Request):
    require_owner(request)
    form = await request.form()
    issuer = (form.get("issuer_id") or "").strip()
    key_id = (form.get("key_id") or "").strip().upper()
    try:
        p8 = (await read_small(form.get("p8"), 64 * 1024)).decode("utf-8", "replace")
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", issuer):
            raise ValueError("Issuer ID looks wrong (it's a UUID like 57246542-96fe-1a63-e053-0824d011072a)")
        if not re.fullmatch(r"[A-Z0-9]{10}", key_id):
            raise ValueError("Key ID looks wrong (10 characters, e.g. 2X9R4HXF34)")
        if not p8:
            raise ValueError("Choose the AuthKey_XXXX.p8 file")
        k = serialization.load_pem_private_key(p8.encode(), None)
        if not isinstance(k, ec.EllipticCurvePrivateKey):
            raise ValueError("That .p8 isn't an App Store Connect key")
    except ValueError as e:
        return go("/setup", err=str(e))
    except Exception:
        return go("/setup", err="Couldn't read the .p8 file")
    c = ASC(issuer, key_id, p8)
    try:
        await run_in_threadpool(c.call, "GET", "/v1/certificates", {"limit": 1})
    except ASCError as e:
        hint = {401: " Apple rejected the key: check Issuer ID / Key ID, or the key was revoked.",
                403: " The key has no access to certificates: create it with the Admin role."}.get(e.status, "")
        return go("/setup", err=f"{e}.{hint}")
    store.atomic_write(provision.P8, p8.encode())
    with store.tx() as d:
        d["asc"] = {"issuer_id": issuer, "key_id": key_id, "saved": int(time.time())}
    store.log(f"App Store Connect key {key_id} saved")
    signer.run_task("Apple setup", provision.full_setup)
    return go("/setup", msg="Key works. Setting up certificate, App ID, devices and profile…")


@app.post("/setup/run")
def setup_run(request: Request):
    require_owner(request)
    if not provision.client():
        return go("/setup", err="Save an App Store Connect API key first")
    signer.run_task("Apple setup", provision.full_setup, True)
    return go("/setup", msg="Rebuilding certificate/profile…")


@app.post("/setup/asc/remove")
def setup_asc_remove(request: Request):
    require_owner(request)
    provision.P8.unlink(missing_ok=True)
    with store.tx() as d:
        d["asc"] = None
    store.log("App Store Connect key removed")
    return go("/setup", msg="API key deleted from the server (also revoke it in App Store Connect if you want)")


@app.get("/setup/csr")
def setup_csr(request: Request):
    require_owner(request)
    return Response(identity.csr_pem(), media_type="application/pkcs10",
                    headers={"Content-Disposition": f'attachment; filename="{FILE_NAME}.certSigningRequest"'})


@app.post("/setup/cert")
async def setup_cert(request: Request):
    require_owner(request)
    form = await request.form()
    try:
        data = await read_small(form.get("cer"))
        if not data:
            raise ValueError("Choose the .cer file")
        info = identity.install_cert(identity.parse_cert(data))
    except ValueError as e:
        return go("/setup", err=str(e))
    except Exception as e:
        return go("/setup", err=f"Couldn't read that certificate: {e}")
    store.log(f"Certificate uploaded: {info['cn']}")
    return go("/setup", msg=f"Certificate saved: {info['cn']}")


@app.post("/setup/profile")
async def setup_profile(request: Request):
    require_owner(request)
    form = await request.form()
    try:
        data = await read_small(form.get("profile"))
        if not data:
            raise ValueError("Choose the .mobileprovision file")
        info = identity.install_profile(data)
    except ValueError as e:
        return go("/setup", err=str(e))
    n = signer.resign_all()
    store.log(f"Profile uploaded: {info['name']} ({info['kind']}, {len(info['devices'])} devices)")
    return go("/setup", msg=f"Profile saved ({info['kind']}, {len(info['devices'])} devices). Re-signing {n} app(s).")


@app.post("/setup/p12")
async def setup_p12(request: Request):
    require_owner(request)
    form = await request.form()
    try:
        data = await read_small(form.get("p12"))
        if not data:
            raise ValueError("Choose the .p12 file")
        info = identity.import_p12(data, form.get("password") or "")
        prof = await read_small(form.get("profile"))
        pinfo = identity.install_profile(prof) if prof else None
    except ValueError as e:
        return go("/setup", err=str(e))
    store.log(f"Imported p12: {info['cn']}")
    n = signer.resign_all() if pinfo else 0
    return go("/setup", msg=f"Imported {info['cn']}" + (f"; profile saved, re-signing {n} app(s)" if pinfo else ""))


@app.post("/setup/export-p12")
async def setup_export_p12(request: Request):
    require_owner(request)
    form = await request.form()
    pw = form.get("password") or ""
    if len(pw) < 4:
        return go("/setup", err="Pick a password of at least 4 characters for the .p12")
    try:
        data = identity.export_p12(pw)
    except ValueError as e:
        return go("/setup", err=str(e))
    return Response(data, media_type="application/x-pkcs12",
                    headers={"Content-Disposition": f'attachment; filename="{FILE_NAME}.p12"', "Cache-Control": "no-store"})


@app.get("/setup/profile.mobileprovision")
def setup_profile_download(request: Request):
    require_owner(request)
    if not identity.PROFILE.exists():
        raise HTTPException(404)
    return FileResponse(identity.PROFILE, media_type="application/octet-stream",
                        filename=f"{FILE_NAME}.mobileprovision")
