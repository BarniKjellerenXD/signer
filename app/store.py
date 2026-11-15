"""Tiny JSON-file state (no database). One process, one lock."""
import json
import os
import threading
import time
from pathlib import Path

from .config import DATA

LOCK = threading.RLock()
STATE = DATA / "state.json"
APPS = DATA / "apps"
DEFAULT = {"asc": None, "bundle": None, "cert_asc_id": None, "profile_asc_id": None,
           "devices": [], "enroll": {}, "log": [], "task": None}


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load() -> dict:
    with LOCK:
        d = json.loads(STATE.read_text()) if STATE.exists() else {}
        for k, v in DEFAULT.items():
            d.setdefault(k, json.loads(json.dumps(v)))
        return d


def save(d: dict) -> None:
    with LOCK:
        atomic_write(STATE, json.dumps(d, indent=1).encode())


class tx:
    """with store.tx() as d: ...  -> read-modify-write under the lock"""

    def __enter__(self):
        LOCK.acquire()
        self.d = load()
        return self.d

    def __exit__(self, et, e, tb):
        try:
            if et is None:
                save(self.d)
        finally:
            LOCK.release()


def log(msg: str, level: str = "info") -> None:
    print(f"[{level}] {msg}", flush=True)
    with tx() as d:
        d["log"].append({"t": int(time.time()), "level": level, "msg": msg})
        d["log"] = d["log"][-200:]


# ---- apps: one directory per app with meta.json ----

def app_dir(aid: str) -> Path:
    return APPS / aid


def app_load(aid: str):
    p = app_dir(aid) / "meta.json"
    with LOCK:
        return json.loads(p.read_text()) if p.exists() else None


def app_save(m: dict) -> None:
    with LOCK:
        app_dir(m["id"]).mkdir(parents=True, exist_ok=True)
        atomic_write(app_dir(m["id"]) / "meta.json", json.dumps(m, indent=1).encode(), 0o644)


def app_update(aid: str, **kw):
    with LOCK:
        m = app_load(aid)
        if m is None:
            return None
        m.update(kw)
        app_save(m)
        return m


def app_list() -> list:
    out = []
    with LOCK:
        for p in APPS.glob("*/meta.json"):
            try:
                out.append(json.loads(p.read_text()))
            except Exception:
                pass
    return sorted(out, key=lambda m: m.get("uploaded", 0), reverse=True)
