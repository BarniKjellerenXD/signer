"""Automatic Apple-side setup through the App Store Connect API:
Apple Distribution cert from our CSR -> wildcard App ID -> register devices -> ad hoc profile -> re-sign apps."""
import base64
import re
import time

from . import identity, signer, store
from .asc import ASC, ASCError
from .config import APPLE_NAME, DATA, ID_PREFIX

P8 = DATA / "secrets" / "asc.p8"
IOS_CLASSES = {"IPHONE", "IPAD", "IPOD"}


def client():
    a = store.load().get("asc")
    if not a or not P8.exists():
        return None
    return ASC(a["issuer_id"], a["key_id"], P8.read_text())


def status(st=None) -> dict:
    st = st or store.load()
    now = time.time()
    cert = identity.load_cert()
    cinfo = identity.cert_info(cert) if cert else None
    prof = identity.current_profile()
    problems = []
    if not cert:
        problems.append("no certificate")
    elif not cinfo["matches_key"]:
        problems.append("certificate doesn't match the server key")
    elif cinfo["expires_ts"] < now:
        problems.append("certificate expired")
    if not prof:
        problems.append("no provisioning profile")
    else:
        if prof["expires_ts"] < now:
            problems.append("profile expired")
        if cert and not prof["cert_ok"]:
            problems.append("profile doesn't include the certificate")
        if prof["kind"] == "app store":
            problems.append("App Store profile can't install on phones")
    enrolled = {d["udid"].lower() for d in st["devices"] if not d.get("disabled")}
    missing = sorted(enrolled - set(prof["devices"])) if prof else sorted(enrolled)
    return {"ready": not problems, "problems": problems, "cert": cinfo, "profile": prof,
            "asc": st.get("asc"), "bundle": st.get("bundle"), "devices": len(enrolled),
            "missing_devices": missing}


def clean_name(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9 ._'()-]", "", s or "").strip()
    return (s or "iPhone")[:50]


def ensure_certificate(c: ASC):
    """Returns (asc_cert_id, created_new)."""
    remote = c.certificates()
    cert = identity.load_cert()
    if cert and identity.cert_matches_key(cert) and identity.cert_info(cert)["expires_ts"] > time.time() + 86400:
        serial = format(cert.serial_number, "X").lstrip("0")
        for r in remote:
            if (r["attributes"].get("serialNumber") or "").upper().lstrip("0") == serial:
                return r["id"], False
        store.log("Local certificate is not (or no longer) on the Apple account - creating a new one", "warn")
    try:
        r = c.create_certificate(identity.csr_pem())
    except ASCError as e:
        raise ASCError(f"Couldn't create an Apple Distribution certificate: {e}. If the account is at its "
                       "certificate limit, revoke an unused Distribution certificate on developer.apple.com "
                       "(Certificates) or import its .p12 on the Setup page instead.")
    der = base64.b64decode(r["data"]["attributes"]["certificateContent"])
    identity.install_cert(identity.parse_cert(der), b"")
    store.log("Created a new Apple Distribution certificate from the server CSR")
    return r["data"]["id"], True


def ensure_bundle(c: ASC) -> dict:
    ids = c.bundle_ids()
    ios = [b for b in ids if b["attributes"].get("platform") in ("IOS", "UNIVERSAL", None)]
    for b in ios:
        if b["attributes"]["identifier"] == "*":
            return {"id": b["id"], "identifier": "*"}
    try:
        r = c.create_bundle_id("*", f"{APPLE_NAME} Wildcard")
        store.log("Created wildcard App ID '*'")
        return {"id": r["data"]["id"], "identifier": "*"}
    except ASCError as e1:
        partial = [b for b in ios if b["attributes"]["identifier"].endswith(".*")]
        if partial:
            b = partial[0]
            return {"id": b["id"], "identifier": b["attributes"]["identifier"]}
        try:
            ident = f"{ID_PREFIX}.*"
            r = c.create_bundle_id(ident, f"{APPLE_NAME} Wildcard")
            store.log(f"Apple refused '*', created wildcard App ID '{ident}' (bundle IDs get that prefix)", "warn")
            return {"id": r["data"]["id"], "identifier": ident}
        except ASCError as e2:
            raise ASCError(f"Couldn't create a wildcard App ID ({e1}; {e2})")


def sync_devices(c: ASC) -> list:
    """Register enrolled devices that Apple doesn't know yet; import Apple's list. Returns eligible Apple devices."""
    remote = {r["attributes"]["udid"].lower(): r for r in c.devices()}
    local = store.load()["devices"]
    errors = {}
    for dev in local:
        u = dev["udid"].lower()
        if u in remote or dev.get("disabled"):
            continue
        try:
            r = c.register_device(clean_name(dev["name"]), dev["udid"])["data"]
            remote[u] = r
            store.log(f"Registered {dev['name']} ({dev['udid']}) with Apple")
        except ASCError as e:
            errors[u] = str(e)
            store.log(f"Registering {dev['udid']} failed: {e}", "error")
    with store.tx() as d:
        known = set()
        for dev in d["devices"]:
            u = dev["udid"].lower()
            known.add(u)
            r = remote.get(u)
            if r:
                a = r["attributes"]
                dev.update(asc_id=r["id"], apple_status=a.get("status"), model=a.get("model") or dev.get("model"),
                           device_class=a.get("deviceClass"), registered=True)
                dev.pop("error", None)
            elif u in errors:
                dev["error"] = errors[u]
        for u, r in remote.items():
            if u not in known:
                a = r["attributes"]
                d["devices"].append({"udid": a["udid"], "name": a.get("name", ""), "model": a.get("model"),
                                     "device_class": a.get("deviceClass"), "apple_status": a.get("status"),
                                     "asc_id": r["id"], "registered": True, "source": "apple",
                                     "added": int(time.time()), "disabled": a.get("status") != "ENABLED"})
    return [r for r in remote.values()
            if r["attributes"].get("status") == "ENABLED"
            and r["attributes"].get("platform") in ("IOS", "UNIVERSAL")
            and r["attributes"].get("deviceClass", "IPHONE") in IOS_CLASSES]


def full_setup(force_profile: bool = False) -> str:
    c = client()
    if not c:
        raise RuntimeError("No App Store Connect API key saved")
    cert_id, created = ensure_certificate(c)
    bundle = ensure_bundle(c)
    eligible = sync_devices(c)
    with store.tx() as d:
        d["bundle"] = bundle
        d["cert_asc_id"] = cert_id
    if not eligible:
        return "Certificate is ready. No iPhones on the account yet - register one on the Devices page."
    want = {r["attributes"]["udid"].lower() for r in eligible}
    cur = identity.current_profile()
    fresh = (cur and cur.get("cert_ok") and not created and not force_profile
             and want <= set(cur["devices"]) and cur["bundle_pattern"] == bundle["identifier"]
             and cur["expires_ts"] - time.time() > 14 * 86400)
    if fresh:
        return f"Everything up to date ({len(want)} device(s) in the profile)"
    name = f"{APPLE_NAME} AdHoc {time.strftime('%Y-%m-%d %H%M%S')}"
    r = c.create_profile(name, bundle["id"], cert_id, [x["id"] for x in eligible])
    info = identity.install_profile(base64.b64decode(r["data"]["attributes"]["profileContent"]))
    with store.tx() as d:
        d["profile_asc_id"] = r["data"]["id"]
    n = signer.resign_all()
    return f"New ad hoc profile with {len(info['devices'])} device(s); re-signing {n} app(s)"


def disable_device(udid: str) -> str:
    c = client()
    st = store.load()
    dev = next((x for x in st["devices"] if x["udid"].lower() == udid.lower()), None)
    if not dev:
        return "Unknown device"
    if c and dev.get("asc_id"):
        c.set_device_status(dev["asc_id"], "DISABLED")
    with store.tx() as d:
        for x in d["devices"]:
            if x["udid"].lower() == udid.lower():
                x["disabled"] = True
                x["apple_status"] = "DISABLED" if c else x.get("apple_status")
    if c:
        return full_setup(force_profile=True)
    return "Device removed locally (remove it from the profile on developer.apple.com yourself)"
