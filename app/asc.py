"""Minimal App Store Connect API client (certificates, bundle IDs, devices, profiles)."""
import time

import httpx
import jwt

BASE = "https://api.appstoreconnect.apple.com"


class ASCError(Exception):
    def __init__(self, msg, status=None, code=None):
        super().__init__(msg)
        self.status = status
        self.code = code


class ASC:
    def __init__(self, issuer_id: str, key_id: str, p8_pem: str):
        self.issuer_id = issuer_id.strip()
        self.key_id = key_id.strip()
        self.p8 = p8_pem
        self._tok = None
        self._exp = 0

    def token(self) -> str:
        now = int(time.time())
        if self._tok and now < self._exp - 60:
            return self._tok
        self._exp = now + 1100                     # Apple allows max 20 min
        self._tok = jwt.encode({"iss": self.issuer_id, "iat": now, "exp": self._exp, "aud": "appstoreconnect-v1"},
                               self.p8, algorithm="ES256", headers={"kid": self.key_id, "typ": "JWT"})
        return self._tok

    def call(self, method: str, url: str, params=None, body=None) -> dict:
        if url.startswith("/"):
            url = BASE + url
        try:
            r = httpx.request(method, url, params=params, json=body, timeout=60,
                              headers={"Authorization": f"Bearer {self.token()}"})
        except httpx.HTTPError as e:
            raise ASCError(f"Couldn't reach Apple: {e}")
        if r.status_code >= 400:
            code = None
            try:
                errs = r.json().get("errors", [])
                code = errs[0].get("code") if errs else None
                msg = "; ".join(f"{e.get('title', '')} - {e.get('detail', '')}".strip(" -") for e in errs)
            except Exception:
                msg = r.text[:300]
            raise ASCError(f"Apple API {r.status_code}: {msg or r.text[:300]}", r.status_code, code)
        return r.json() if r.content else {}

    def all(self, path: str, params=None) -> list:
        out, url, p = [], path, dict(params or {})
        while url:
            j = self.call("GET", url, params=p)
            out += j.get("data", [])
            url, p = (j.get("links") or {}).get("next"), None
        return out

    # -- certificates
    def certificates(self) -> list:
        return self.all("/v1/certificates", {"filter[certificateType]": "DISTRIBUTION,IOS_DISTRIBUTION", "limit": 200})

    def create_certificate(self, csr_pem: str) -> dict:
        def body(csr):
            return {"data": {"type": "certificates", "attributes": {"certificateType": "DISTRIBUTION", "csrContent": csr}}}
        try:
            return self.call("POST", "/v1/certificates", body=body(csr_pem))
        except ASCError as e:
            if e.status not in (400, 409) or "csr" not in str(e).lower():
                raise
            stripped = "".join(l for l in csr_pem.splitlines() if "-----" not in l)
            return self.call("POST", "/v1/certificates", body=body(stripped))

    # -- bundle ids
    def bundle_ids(self) -> list:
        return self.all("/v1/bundleIds", {"limit": 200})

    def create_bundle_id(self, identifier: str, name: str) -> dict:
        return self.call("POST", "/v1/bundleIds", body={"data": {"type": "bundleIds", "attributes": {
            "identifier": identifier, "name": name, "platform": "IOS"}}})

    # -- devices
    def devices(self) -> list:
        return self.all("/v1/devices", {"limit": 200})

    def register_device(self, name: str, udid: str) -> dict:
        return self.call("POST", "/v1/devices", body={"data": {"type": "devices", "attributes": {
            "name": name, "udid": udid, "platform": "IOS"}}})

    def set_device_status(self, device_id: str, status: str) -> dict:
        return self.call("PATCH", f"/v1/devices/{device_id}", body={"data": {
            "type": "devices", "id": device_id, "attributes": {"status": status}}})

    # -- profiles
    def create_profile(self, name: str, bundle_id: str, cert_id: str, device_ids: list) -> dict:
        return self.call("POST", "/v1/profiles", body={"data": {
            "type": "profiles",
            "attributes": {"name": name, "profileType": "IOS_APP_ADHOC"},
            "relationships": {
                "bundleId": {"data": {"type": "bundleIds", "id": bundle_id}},
                "certificates": {"data": [{"type": "certificates", "id": cert_id}]},
                "devices": {"data": [{"type": "devices", "id": i} for i in device_ids]},
            }}})
