"""A fake identity API for the tests: real Ed25519 keys, no network."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from murkio import Murkio

PUBLISHABLE_KEY = "pk_python_test"
APPLICATION = "app-1"
ISSUER = "enterprise-auth"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class FakeApi:
    def __init__(self, jwks: Optional[Dict[str, Any]] = None, application: str = APPLICATION, issuer: str = ISSUER) -> None:
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.jwks = jwks or {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "x": b64(public)}]}
        self.application = application
        self.issuer = issuer
        self.calls: List[str] = []
        self.revoked: set = set()

    def transport(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, bytes]:
        path = "/" + url.split("/", 3)[3]
        self.calls.append(f"{method} {path}")
        if path == "/v1/client":
            if headers.get("Authorization") != f"Bearer {PUBLISHABLE_KEY}":
                return 401, json.dumps({"details": [{"code": "bss-01"}]}).encode()
            data = {
                "application_id": self.application, "issuer": self.issuer, "jwks_url": "/jwks.json",
                "config": {}, "canvas": {"version": 0, "document": {"note": "</script><b>& "}},
            }
            return 200, json.dumps({"data": data}).encode()
        if path == "/jwks.json":
            return 200, json.dumps(self.jwks).encode()
        if path == "/v1/me":
            return 200, json.dumps({"data": {"id": "user-1", "session_id": "session-1", "email": "ana@example.com", "email_verified": True, "roles": ["user"], "mfa_enabled": False, "created_at": "2026-10-10T00:00:00Z"}}).encode()
        if path == "/v1/sessions/verify":
            token = json.loads(body or b"{}").get("access_token")
            return 200, json.dumps({"data": {"active": token not in self.revoked}}).encode()
        return 404, b"{}"

    def token(self, kid: str = "k1", **claims: Any) -> str:
        payload = {
            "iss": self.issuer, "sub": "user-1", "aud": self.application, "aid": self.application, "sid": "session-1",
            "roles": ["user"], "iat": int(time.time()), "exp": int(time.time()) + 900, "jti": "j1",
        }
        payload.update(claims)
        signing = b64(json.dumps({"alg": "EdDSA", "kid": kid}).encode()) + "." + b64(json.dumps(payload).encode())
        return signing + "." + b64(self.private.sign(signing.encode()))

    def client(self, **options: Any) -> Murkio:
        return Murkio(PUBLISHABLE_KEY, api_url="https://api.example.com", transport=self.transport, **options)
