"""zsign wrapper, IPA inspection and the single background work queue."""
import json
import re
import shutil
import struct
import subprocess
import time
import traceback
import uuid
import plistlib
import zipfile
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import identity, store
from .config import DATA, MAX_DOWNLOAD, ZIP_LEVEL, ZSIGN

WORK = ThreadPoolExecutor(max_workers=1, thread_name_prefix="work")    # signing + Apple tasks, strictly serial
FETCH = ThreadPoolExecutor(max_workers=2, thread_name_prefix="fetch")  # URL downloads
TMP = DATA / "tmp"

# ---------- IPA inspection ----------

LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2C


def _thin_encrypted(buf: bytes, off: int):
    if off + 32 > len(buf):
        return None
    magic = struct.unpack_from("<I", buf, off)[0]
    if magic == 0xFEEDFACF:
        hdr = 32
    elif magic == 0xFEEDFACE:
        hdr = 28
    else:
        return None
    ncmds = struct.unpack_from("<I", buf, off + 16)[0]
    p = off + hdr
    for _ in range(ncmds):
        if p + 20 > len(buf):
            return None
        cmd, size = struct.unpack_from("<II", buf, p)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            return struct.unpack_from("<I", buf, p + 16)[0] != 0
        if size < 8:
            return None
        p += size
    return False


def macho_encrypted(z: zipfile.ZipFile, name: str):
    """True if the main binary still has FairPlay encryption (App Store copy) -> it will crash on launch."""
    with z.open(name) as f:
        head = f.read(4096)
        if len(head) < 8:
            return None
        magic = struct.unpack_from(">I", head, 0)[0]
        if magic in (0xCAFEBABE, 0xCAFEBABF):
            n = struct.unpack_from(">I", head, 4)[0]
            offs = []
            for i in range(min(n, 8)):
                if magic == 0xCAFEBABE:
                    offs.append(struct.unpack_from(">iiIII", head, 8 + 20 * i)[2])
                else:
                    offs.append(struct.unpack_from(">iiQQII", head, 8 + 32 * i)[2])
            buf = head + f.read(max(offs) + 262144 - len(head))
            res = [_thin_encrypted(buf, o) for o in offs]
        else:
            res = [_thin_encrypted(head + f.read(262144), 0)]
    if any(r is True for r in res):
        return True
    return False if any(r is False for r in res) else None


def read_ipa_info(path) -> dict:
    if not zipfile.is_zipfile(path):
        raise ValueError("That file isn't an .ipa (not a zip archive)")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        info_name = next((n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)), None)
        if not info_name:
            raise ValueError("Not an iOS app: Payload/<App>.app/Info.plist is missing")
        root = info_name.rsplit("/", 1)[0]
        info = plistlib.loads(z.read(info_name))
        exe = info.get("CFBundleExecutable")
        encrypted = None
        if exe and f"{root}/{exe}" in names:
            try:
                encrypted = macho_encrypted(z, f"{root}/{exe}")
            except Exception:
                encrypted = None
        exts = {n.split("/")[3] for n in names if n.startswith(root + "/PlugIns/") and n.count("/") >= 4}
        exts |= {n.split("/")[3] for n in names if n.startswith(root + "/Extensions/") and n.count("/") >= 4}
        return {
            "bundle_id": info.get("CFBundleIdentifier", ""),
            "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or exe or "App",
            "version": str(info.get("CFBundleShortVersionString", "")),
            "build": str(info.get("CFBundleVersion", "")),
            "min_os": str(info.get("MinimumOSVersion", "")),
            "encrypted": encrypted,
            "extensions": len(exts),
            "watch": any(n.startswith(root + "/Watch/") for n in names),
            "has_profile": f"{root}/embedded.mobileprovision" in names,
        }


# ---------- background tasks ----------

def _safe(fn, *a):
    try:
        fn(*a)
    except Exception:
        traceback.print_exc()


def run_task(name: str, fn, *a) -> None:
    """Apple/provisioning job, serialized with signing. Status shown in the UI banner."""
    with store.tx() as d:
        d["task"] = {"name": name, "status": "queued", "t": int(time.time()), "msg": ""}

    def work():
        with store.tx() as d:
            d["task"]["status"] = "running"
        try:
            msg = fn(*a) or "Done"
            store.log(f"{name}: {msg}")
            st, out = "ok", msg
        except Exception as e:
            traceback.print_exc()
            store.log(f"{name} failed: {e}", "error")
            st, out = "error", str(e)
        with store.tx() as d:
            d["task"] = {"name": name, "status": st, "t": int(time.time()), "msg": out}

    WORK.submit(work)


def enqueue_sign(aid: str) -> None:
    store.app_update(aid, status="queued", error=None)
    WORK.submit(_safe, sign, aid)


def resign_all() -> int:
    n = 0
    for m in store.app_list():
        if m.get("fatal") or not (store.app_dir(m["id"]) / "original.ipa").exists():
            continue
        if m.get("status") in ("uploading", "downloading"):
            continue
        enqueue_sign(m["id"])
        n += 1
    return n


def ingest(aid: str) -> None:
    """original.ipa is in place: read it, then queue signing."""
    orig = store.app_dir(aid) / "original.ipa"
    try:
        info = read_ipa_info(orig)
    except Exception as e:
        store.app_update(aid, status="error", fatal=True, error=str(e))
        orig.unlink(missing_ok=True)
        return
    store.app_update(aid, orig=info, name=info["name"], size_orig=orig.stat().st_size)
    enqueue_sign(aid)


def fetch(aid: str, url: str) -> None:
    adir = store.app_dir(aid)
    part = adir / "original.ipa.part"
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=httpx.Timeout(60, read=300),
                          headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"}) as r:
            if r.status_code >= 400:
                raise ValueError(f"Download failed: HTTP {r.status_code}")
            total = 0
            with open(part, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise ValueError("Download is bigger than the size limit")
                    f.write(chunk)
        part.replace(adir / "original.ipa")
    except Exception as e:
        part.unlink(missing_ok=True)
        store.app_update(aid, status="error", fatal=True, error=f"{e}")
        return
    ingest(aid)


def enqueue_fetch(aid: str, url: str) -> None:
    FETCH.submit(_safe, fetch, aid, url)


# ---------- signing ----------

def ready_problem():
    cert = identity.load_cert()
    prof = identity.current_profile()
    if not cert or not identity.cert_matches_key(cert) or not identity.P12.exists():
        return "No signing certificate yet (owner: open Setup)"
    if not prof:
        return "No provisioning profile yet (owner: open Setup)"
    if not prof.get("cert_ok"):
        return "Profile doesn't contain the current certificate"
    if prof["expires_ts"] < time.time():
        return "Provisioning profile expired"
    if prof["kind"] == "app store":
        return "Profile is an App Store profile; it can't install on phones"
    return None


def target_bundle_id(orig_bid: str, opts: dict, prof: dict) -> str:
    want = (opts.get("bundle_id") or orig_bid).strip()
    prefix = prof["wildcard_prefix"]
    if prefix is None:                      # explicit App ID profile
        return prof["bundle_pattern"]
    if prefix and not want.startswith(prefix):
        want = prefix + want
    return want


def sign(aid: str) -> None:
    m = store.app_load(aid)
    if not m:
        return
    adir = store.app_dir(aid)
    orig = adir / "original.ipa"
    if not orig.exists():
        store.app_update(aid, status="error", fatal=True, error="Original IPA missing")
        return
    problem = ready_problem()
    if problem:
        store.app_update(aid, status="waiting", error=problem)
        return
    prof = identity.current_profile()
    opts = m.get("options", {})
    store.app_update(aid, status="signing", error=None)
    work = TMP / f"sign-{aid}-{uuid.uuid4().hex[:8]}"
    meta = work / "meta"
    meta.mkdir(parents=True)
    out_ipa = work / "signed.ipa"
    bid = target_bundle_id(m["orig"]["bundle_id"], opts, prof)
    cmd = [ZSIGN, "-k", str(identity.P12), "-p", identity.p12_password(), "-m", str(identity.PROFILE),
           "-o", str(out_ipa), "-z", ZIP_LEVEL, "-x", str(meta), "-t", str(work)]
    if bid != m["orig"]["bundle_id"]:
        cmd += ["-b", bid]
    if opts.get("name"):
        cmd += ["-n", opts["name"]]
    if opts.get("rm_extensions"):
        cmd.append("-E")
    if opts.get("rm_watch"):
        cmd.append("-W")
    if opts.get("rm_uisd"):
        cmd.append("-U")
    if opts.get("enable_docs"):
        cmd.append("-S")
    if opts.get("min_os"):
        cmd += ["-M", opts["min_os"]]
    dylibs = sorted((adir / "inject").glob("*.dylib")) if (adir / "inject").exists() else []
    for dl in dylibs:
        cmd += ["-l", str(dl)]
    if dylibs and opts.get("inject_ext"):
        cmd.append("-P")
    cmd.append(str(orig))
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        out = (r.stdout + r.stderr).replace(identity.p12_password(), "***")
        ok = r.returncode == 0 and out_ipa.exists() and "Signed OK" in out
        if not ok:
            lines = [l for l in out.splitlines() if l.strip()]
            reason = next((l for l in reversed(lines) if "fail" in l.lower() or "error" in l.lower()), lines[-1] if lines else "zsign failed")
            store.app_update(aid, status="error", error=reason.replace(">>>", "").strip(), zsign_log=out[-6000:])
            return
        final = read_ipa_info(out_ipa)
        out_ipa.replace(adir / "signed.ipa")
        try:
            md = json.loads((meta / "metadata.json").read_text())
            icon = meta / md.get("IconName", "")
            if md.get("IconName") and icon.exists():
                shutil.copyfile(icon, adir / "icon.png")
        except Exception:
            pass
        rev = int(time.time())
        store.app_update(aid, status="signed", error=None, rev=rev, signed_at=rev,
                         seconds=round(time.time() - t0, 1), final=final, name=final["name"],
                         profile_uuid=prof["uuid"], profile_expires=prof["expires_ts"],
                         size=(adir / "signed.ipa").stat().st_size, zsign_log=out[-6000:])
        store.log(f"Signed {final['name']} ({final['bundle_id']}) in {time.time() - t0:.1f}s")
    except subprocess.TimeoutExpired:
        store.app_update(aid, status="error", error="zsign timed out")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def startup() -> None:
    for p in TMP.iterdir():
        shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
    with store.tx() as d:
        if d.get("task") and d["task"].get("status") in ("queued", "running"):
            d["task"]["status"] = "error"
            d["task"]["msg"] = "Interrupted by a restart - run it again"
    for m in store.app_list():
        if m.get("status") in ("queued", "signing"):
            enqueue_sign(m["id"])
        elif m.get("status") in ("uploading", "downloading"):
            store.app_update(m["id"], status="error", fatal=True, error="Interrupted by a restart - upload again")
