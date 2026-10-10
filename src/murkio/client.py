"""The Murkio client for a backend: verifies sessions with only the publishable key."""

from __future__ import annotations

import base64
import binascii
import html
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import _cdn

DEFAULT_API_URL = "https://api.mukio.com"

_BOOTSTRAP_TTL = 60.0
_USER_TTL = 60.0
_REVOCATION_TTL = 30.0
_JWKS_RETRY = 60.0
_CACHE_LIMIT = 10_000
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_HANDSHAKE_GUARD = "murkio_handshake"

Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, bytes]]


class TokenError(Exception):
    """The access token was refused. ``reason`` is ``invalid`` or ``expired``."""

    reason = "invalid"


class ExpiredToken(TokenError):
    reason = "expired"


class ApiError(Exception):
    """An error answer of the identity API."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"murkio: api answered {status} ({code})")
        self.status = status
        self.code = code


class Markup(str):
    """HTML that is already escaped. Jinja2 and Django do not escape it again."""

    def __html__(self) -> "Markup":
        return self


@dataclass(frozen=True)
class Session:
    """A verified access token."""

    user_id: str
    session_id: str
    application_id: str
    roles: Tuple[str, ...]
    claims: Mapping[str, Any]
    token: str

    def has_role(self, *roles: str) -> bool:
        return any(role in self.roles for role in roles)


@dataclass(frozen=True)
class User:
    """The profile of ``POST /v1/me``."""

    id: str
    session_id: str
    email: Optional[str]
    email_verified: bool
    roles: Tuple[str, ...]
    mfa_enabled: bool
    created_at: str


@dataclass
class AuthResult:
    """Who is behind a request. ``session`` is None when nobody is signed in."""

    session: Optional[Session] = None
    user: Optional[User] = None
    #: Why there is no session: missing, invalid, expired, revoked or csrf.
    reason: Optional[str] = None
    #: The browser holds a session, even if this request's token is missing or expired.
    signed_in_hint: bool = False


@dataclass
class Response:
    """An answer to send instead of running the route (401, 403, redirect or handshake)."""

    status: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""


def fnv1a32(value: str) -> str:
    """The hash that names the cookies of a publishable key (same as @murkio/html)."""
    result = 0x811C9DC5
    for byte in value.encode("utf-8"):
        result ^= byte
        result = (result * 0x01000193) & 0xFFFFFFFF
    return f"{result:08x}"


def _b64url(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as error:
        raise TokenError("malformed token") from error


def _json_segment(segment: str) -> Dict[str, Any]:
    try:
        value = json.loads(_b64url(segment))
    except (ValueError, UnicodeDecodeError) as error:
        raise TokenError("malformed token") from error
    if not isinstance(value, dict):
        raise TokenError("malformed token")
    return value


def _urllib_transport(timeout: float) -> Transport:
    def send(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - the URL is the configured API
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    return send


def _attributes(pairs: Sequence[Tuple[str, Optional[str]]]) -> str:
    return "".join(f' {name}="{html.escape(value, quote=True)}"' for name, value in pairs if value)


class Murkio:
    """Verifies the sessions of one application. Create one per process and share it.

    The only setting is the publishable key (``MURKIO_PUBLISHABLE_KEY``): ``GET
    /v1/client`` gives the application, the token issuer and the JWKS, and the
    access tokens are verified locally (Ed25519, issuer, audience, expiry), so a
    request costs no call to the API. The backend never signs anyone in: the
    browser SDK does that, because the API rate-limits by the user's IP.
    """

    def __init__(
        self,
        publishable_key: Optional[str] = None,
        *,
        api_url: Optional[str] = None,
        cookie_domain: Optional[str] = None,
        script_url: Optional[str] = None,
        integrity: Optional[str] = None,
        timeout: float = 10.0,
        transport: Optional[Transport] = None,
    ) -> None:
        key = publishable_key or os.environ.get("MURKIO_PUBLISHABLE_KEY", "")
        if not key.startswith("pk_"):
            raise ValueError("murkio: set publishable_key (or MURKIO_PUBLISHABLE_KEY) to the application's publishable key (pk_...)")
        self.publishable_key = key
        self.api_url = (api_url or os.environ.get("MURKIO_API_URL") or DEFAULT_API_URL).rstrip("/")
        self.key_hash = fnv1a32(key)
        self.cookie_domain = cookie_domain
        self.script_url = script_url or os.environ.get("MURKIO_SCRIPT_URL") or None
        self.integrity = integrity or os.environ.get("MURKIO_SCRIPT_INTEGRITY") or None
        self._send = transport or _urllib_transport(timeout)
        self._lock = threading.Lock()
        self._bootstrap: Optional[Tuple[float, Dict[str, Any]]] = None
        self._keys: Dict[str, Ed25519PublicKey] = {}
        self._keys_at = 0.0
        self._users: Dict[str, Tuple[float, User]] = {}
        self._actives: Dict[str, Tuple[float, bool]] = {}

    # --- API -------------------------------------------------------------

    def _call(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> Any:
        headers = {"Authorization": f"Bearer {self.publishable_key}", "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        status, raw = self._send(method, self.api_url + path, headers, data)
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {}
        if status >= 300 or "data" not in payload:
            details = payload.get("details") if isinstance(payload, dict) else None
            code = details[0].get("code") if details else f"http-{status}"
            raise ApiError(status, str(code))
        return payload["data"]

    def bootstrap(self) -> Dict[str, Any]:
        """``GET /v1/client``: the application, its config and published canvas (cached a minute)."""
        with self._lock:
            if self._bootstrap and time.monotonic() - self._bootstrap[0] < _BOOTSTRAP_TTL:
                return self._bootstrap[1]
        data = self._call("GET", "/v1/client")
        with self._lock:
            self._bootstrap = (time.monotonic(), data)
        return data

    def _public_key(self, bootstrap: Mapping[str, Any], kid: str) -> Ed25519PublicKey:
        with self._lock:
            key = self._keys.get(kid)
            if key is not None:
                return key
            if self._keys_at and time.monotonic() - self._keys_at < _JWKS_RETRY:
                raise TokenError("unknown key")
            self._keys_at = time.monotonic()

        url = urllib.parse.urljoin(self.api_url + "/", str(bootstrap.get("jwks_url", "")))
        status, raw = self._send("GET", url, {"Accept": "application/json"}, None)
        if status != 200:
            raise ApiError(status, f"http-{status}")
        keys: Dict[str, Ed25519PublicKey] = {}
        for jwk in json.loads(raw).get("keys", []):
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            try:
                material = _b64url(str(jwk.get("x", "")))
                if len(material) == 32:
                    keys[str(jwk.get("kid"))] = Ed25519PublicKey.from_public_bytes(material)
            except (TokenError, ValueError):
                continue
        with self._lock:
            self._keys = keys
        if kid not in keys:
            raise TokenError("unknown key")
        return keys[kid]

    def verify(self, token: str) -> Session:
        """Verifies an access token locally. Raises ``ExpiredToken`` or ``TokenError``."""
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("malformed token")
        header = _json_segment(parts[0])
        if header.get("alg") != "EdDSA":
            raise TokenError("unsupported algorithm")

        bootstrap = self.bootstrap()
        key = self._public_key(bootstrap, str(header.get("kid", "")))
        try:
            key.verify(_b64url(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"))
        except (InvalidSignature, UnicodeEncodeError) as error:
            raise TokenError("invalid signature") from error

        claims = _json_segment(parts[1])
        expires = claims.get("exp")
        if (
            claims.get("iss") != bootstrap.get("issuer")
            or claims.get("aud") != bootstrap.get("application_id")
            or not claims.get("sub")
            or not claims.get("sid")
            or not isinstance(expires, (int, float))
            or isinstance(expires, bool)
        ):
            raise TokenError("invalid claims")
        if time.time() >= expires:
            raise ExpiredToken("expired token")

        roles = claims.get("roles")
        return Session(
            user_id=str(claims["sub"]),
            session_id=str(claims["sid"]),
            application_id=str(bootstrap.get("application_id")),
            roles=tuple(str(role) for role in roles) if isinstance(roles, list) else (),
            claims=claims,
            token=token,
        )

    def user(self, session: Session) -> User:
        """The profile of the session's user (``POST /v1/me``), cached a minute per session."""
        with self._lock:
            hit = self._users.get(session.session_id)
            if hit and time.monotonic() - hit[0] < _USER_TTL:
                return hit[1]
        data = self._call("POST", "/v1/me", {"access_token": session.token})
        user = User(
            id=str(data.get("id")),
            session_id=str(data.get("session_id")),
            email=data.get("email"),
            email_verified=bool(data.get("email_verified")),
            roles=tuple(data.get("roles") or ()),
            mfa_enabled=bool(data.get("mfa_enabled")),
            created_at=str(data.get("created_at", "")),
        )
        with self._lock:
            if len(self._users) >= _CACHE_LIMIT:
                self._users.clear()
            self._users[session.session_id] = (time.monotonic(), user)
        return user

    def is_active(self, session: Session) -> bool:
        """False when the API says the session was revoked (logout, ban). Cached 30 s."""
        key = str(session.claims.get("jti") or session.token)
        with self._lock:
            hit = self._actives.get(key)
            if hit and time.monotonic() - hit[0] < _REVOCATION_TTL:
                return hit[1]
        active = bool(self._call("POST", "/v1/sessions/verify", {"access_token": session.token}).get("active"))
        with self._lock:
            if len(self._actives) >= _CACHE_LIMIT:
                self._actives.clear()
            self._actives[key] = (time.monotonic(), active)
        return active

    # --- requests --------------------------------------------------------

    def _cookie_names(self, host: str) -> List[Tuple[str, str]]:
        names = [(f"__Host-murkio_session_{self.key_hash}", f"__Host-murkio_uat_{self.key_hash}")]
        if self.cookie_domain:
            names.append((f"__Secure-murkio_session_{self.key_hash}", f"__Secure-murkio_uat_{self.key_hash}"))
        hostname = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        if hostname.strip("[]") in ("localhost", "127.0.0.1", "::1") or host.startswith("[::1]"):
            names.append((f"murkio_session_{self.key_hash}", f"murkio_uat_{self.key_hash}"))
        return names

    def authenticate(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
        load_user: bool = False,
        check_revocation: bool = False,
    ) -> AuthResult:
        """Finds and verifies the session of a request.

        The token comes from ``Authorization: Bearer`` or from the session
        cookie the browser SDK writes. The cookie goes with every request to
        the site, including ones another site makes the browser send, so it
        only counts for GET, HEAD and OPTIONS or for same-origin requests.
        """
        lower = {name.lower(): value for name, value in headers.items()}
        names = self._cookie_names(host)
        result = AuthResult(signed_in_hint=any(cookies.get(uat) == "1" for _, uat in names))

        token = ""
        authorization = lower.get("authorization", "")
        if authorization.startswith("Bearer "):
            value = authorization[7:].strip()
            if not value.startswith(("pk_", "sk_")):
                token = value
        if not token:
            token = next((cookies[name] for name, _ in names if cookies.get(name)), "")
            if not token:
                result.reason = "missing"
                return result
            if method.upper() not in _SAFE_METHODS and not self._same_origin(lower, scheme, host):
                result.reason = "csrf"
                return result

        try:
            session = self.verify(token)
        except TokenError as error:
            result.reason = error.reason
            return result

        if check_revocation:
            try:
                active = self.is_active(session)
            except (ApiError, OSError):
                active = False
            if not active:
                result.reason = "revoked"
                return result
        if load_user:
            try:
                result.user = self.user(session)
            except (ApiError, OSError):
                result.user = None
        result.session = session
        return result

    @staticmethod
    def _same_origin(headers: Mapping[str, str], scheme: str, host: str) -> bool:
        site = headers.get("sec-fetch-site")
        if site:
            return site == "same-origin"
        origin = headers.get("origin")
        return bool(origin) and origin == f"{scheme}://{host}"

    def protect(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        path: str,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
        required: bool = False,
        roles: Optional[Sequence[str]] = None,
        sign_in_url: Optional[str] = None,
        handshake: bool = True,
        load_user: bool = False,
        check_revocation: bool = False,
    ) -> Tuple[AuthResult, Optional[Response]]:
        """Authenticates a request and decides what to answer.

        Returns the result and a ``Response`` to send instead of running the
        route (401, 403, a redirect to ``sign_in_url`` or the handshake page
        that refreshes an expired session cookie), or None to go on.
        """
        result = self.authenticate(
            method=method, scheme=scheme, host=host, headers=headers, cookies=cookies,
            load_user=load_user, check_revocation=check_revocation,
        )
        if result.session is not None:
            if roles and not result.session.has_role(*roles):
                return result, _json_response(403, "forbidden")
            return result, None

        lower = {name.lower(): value for name, value in headers.items()}
        navigation = method.upper() == "GET" and (
            lower.get("sec-fetch-mode") == "navigate" or "text/html" in lower.get("accept", "")
        )
        if (
            handshake and navigation and result.signed_in_hint
            and result.reason in ("missing", "expired") and not cookies.get(_HANDSHAKE_GUARD)
        ):
            return result, self._handshake(scheme)

        if not required and not roles:
            return result, None
        if navigation and sign_in_url:
            separator = "&" if "?" in sign_in_url else "?"
            location = f"{sign_in_url}{separator}redirect={urllib.parse.quote(path, safe='')}"
            return result, Response(302, [("Location", location), ("Cache-Control", "no-store")])
        return result, _json_response(401, "unauthorized")

    def _handshake(self, scheme: str) -> Response:
        nonce = secrets.token_urlsafe(16)
        script = urllib.parse.urlsplit(self.script_url or _cdn.URL)
        script_origin = f"{script.scheme}://{script.netloc}" if script.netloc else "https://cdn.jsdelivr.net"
        api = urllib.parse.urlsplit(self.api_url)
        page = (
            '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title></title>\n'
            f"{self._script_tag(nonce=nonce)}\n"
            f'<script nonce="{nonce}">(async function(){{try{{var m=window.Murkio&&window.Murkio.getMurkio();'
            "if(m)await m.getToken();}catch(e){}location.replace(location.href);})();</script>\n"
            "</head><body></body></html>"
        )
        secure = "; Secure" if scheme == "https" else ""
        return Response(
            200,
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Cache-Control", "no-store"),
                (
                    "Content-Security-Policy",
                    f"default-src 'none'; script-src 'nonce-{nonce}' {script_origin}; "
                    f"connect-src {api.scheme}://{api.netloc}; base-uri 'none'; frame-ancestors 'none'",
                ),
                ("Set-Cookie", f"{_HANDSHAKE_GUARD}=1; Path=/; Max-Age=30; SameSite=Lax{secure}"),
            ],
            page.encode("utf-8"),
        )

    # --- pages -----------------------------------------------------------

    def _script_tag(
        self,
        *,
        nonce: Optional[str] = None,
        after_login: Optional[str] = None,
        locale: Optional[str] = None,
        oauth_redirect_url: Optional[str] = None,
    ) -> str:
        integrity = self.integrity if self.script_url else _cdn.INTEGRITY
        return "<script" + _attributes([
            ("src", self.script_url or _cdn.URL),
            ("integrity", integrity),
            ("crossorigin", "anonymous" if integrity else None),
            ("nonce", nonce),
            ("data-murkio-key", self.publishable_key),
            ("data-murkio-api", self.api_url),
            ("data-murkio-locale", locale),
            ("data-murkio-after-login", after_login),
            ("data-murkio-oauth-redirect", oauth_redirect_url),
        ]) + "></script>"

    def head(
        self,
        *,
        after_login: Optional[str] = None,
        locale: Optional[str] = None,
        oauth_redirect_url: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Markup:
        """The ``<script>`` that loads the browser SDK, pinned with its SRI hash. Put it in ``<head>``."""
        return Markup(self._script_tag(nonce=nonce, after_login=after_login, locale=locale, oauth_redirect_url=oauth_redirect_url))

    def bootstrap_script(self) -> Markup:
        """Inlines ``GET /v1/client`` so the browser draws the canvas without fetching it.

        ``<``, ``>``, ``&`` and the U+2028/U+2029 separators become ``\\u``
        escapes, so the JSON cannot end the ``<script>`` tag.
        """
        raw = json.dumps(self.bootstrap(), ensure_ascii=True, separators=(",", ":"))
        raw = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        stamp = int(time.time() * 1000)
        return Markup(f'<script type="application/json" id="murkio-bootstrap" data-generated-at="{stamp}">{raw}</script>')

    @staticmethod
    def canvas(*, screen: Optional[str] = None, class_: Optional[str] = None, locale: Optional[str] = None, light_dom: bool = False) -> Markup:
        """``<murkio-identity-canvas>``: the login canvas designed in the dashboard."""
        attributes = _attributes([("screen", screen), ("class", class_), ("locale", locale)])
        return Markup(f"<murkio-identity-canvas{attributes}{' light-dom' if light_dom else ''}></murkio-identity-canvas>")

    @staticmethod
    def _field(tag: str, class_: Optional[str], form: Optional[str], placeholder: Optional[str] = None, label: Optional[str] = None) -> Markup:
        attributes = _attributes([("class", class_), ("form", form), ("placeholder", placeholder), ("label", label)])
        return Markup(f"<{tag}{attributes}></{tag}>")

    def email_input(self, *, class_: Optional[str] = None, placeholder: Optional[str] = None, label: Optional[str] = None, form: Optional[str] = None) -> Markup:
        return self._field("murkio-identity-email-input", class_, form, placeholder, label)

    def password_input(self, *, class_: Optional[str] = None, placeholder: Optional[str] = None, label: Optional[str] = None, form: Optional[str] = None) -> Markup:
        return self._field("murkio-identity-password-input", class_, form, placeholder, label)

    def keep_logged(self, label: str, *, class_: Optional[str] = None, form: Optional[str] = None) -> Markup:
        return self._field("murkio-identity-keep-logged", class_, form, label=label)

    def login_button(self, label: str, *, class_: Optional[str] = None, form: Optional[str] = None) -> Markup:
        return self._field("murkio-identity-login-button", class_, form, label=label)

    def register_button(self, label: str, *, class_: Optional[str] = None, form: Optional[str] = None) -> Markup:
        return self._field("murkio-identity-register-button", class_, form, label=label)

    def error_message(self, *, class_: Optional[str] = None, form: Optional[str] = None) -> Markup:
        return self._field("murkio-identity-error", class_, form)


def _json_response(status: int, message: str) -> Response:
    return Response(
        status,
        [("Content-Type", "application/json"), ("Cache-Control", "no-store")],
        json.dumps({"error": message}).encode("utf-8"),
    )


def parse_cookies(header: Optional[str]) -> Dict[str, str]:
    """Parses a ``Cookie`` header (the first value of a repeated name wins)."""
    cookies: Dict[str, str] = {}
    for part in (header or "").split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name and value and name not in cookies:
            cookies[name] = urllib.parse.unquote(value)
    return cookies
