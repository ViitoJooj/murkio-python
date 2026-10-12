import json
import pathlib
import unittest

from helpers import PUBLISHABLE_KEY, FakeApi
from murkio import AuthResult, ExpiredToken, Murkio, TokenError, fnv1a32, parse_cookies
from murkio.client import _urllib_transport

VECTORS = json.loads((pathlib.Path(__file__).resolve().parents[1] / "spec" / "server" / "vectors.json").read_text())
HASH = fnv1a32(PUBLISHABLE_KEY)


def request(method="GET", host="app.example.com", scheme="https", headers=None, cookies=None):
    return {"method": method, "scheme": scheme, "host": host, "headers": headers or {}, "cookies": cookies or {}}


class SharedVectors(unittest.TestCase):
    """The same tokens must get the same verdict in every server SDK (spec/server)."""

    def test_cookie_hash(self):
        for value, expected in VECTORS["cookie_hash"].items():
            self.assertEqual(fnv1a32(value), expected)

    def test_tokens(self):
        for case in VECTORS["cases"]:
            with self.subTest(case["name"]):
                api = FakeApi(jwks=VECTORS["jwks"], application=VECTORS["application_id"], issuer=VECTORS["issuer"])
                client = api.client()
                if case["expect"] == "valid":
                    session = client.verify(case["token"])
                    self.assertEqual(session.user_id, case["session"]["user_id"])
                    self.assertEqual(session.session_id, case["session"]["session_id"])
                    self.assertEqual(list(session.roles), case["session"]["roles"])
                elif case["expect"] == "expired":
                    with self.assertRaises(ExpiredToken):
                        client.verify(case["token"])
                else:
                    with self.assertRaises(TokenError) as raised:
                        client.verify(case["token"])
                    self.assertNotIsInstance(raised.exception, ExpiredToken)


class Configuration(unittest.TestCase):
    def test_refuses_secret_keys(self):
        with self.assertRaises(ValueError):
            Murkio("sk_secret")

    def test_caches_the_bootstrap_and_fetches_the_jwks_once(self):
        api = FakeApi()
        client = api.client()
        client.verify(api.token())
        client.verify(api.token())
        with self.assertRaises(TokenError):
            client.verify(api.token(kid="rotated"))
        self.assertEqual(api.calls, ["GET /v1/client", "GET /jwks.json"], "an unknown kid within a minute must not refetch the JWKS")


class Authenticate(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.client = self.api.client()
        self.token = self.api.token(roles=["admin"])

    def test_bearer_token(self):
        result = self.client.authenticate(**request(headers={"Authorization": f"Bearer {self.token}"}))
        self.assertEqual(result.session.user_id, "user-1")
        self.assertTrue(result.session.has_role("admin"))

    def test_an_api_key_is_not_a_session(self):
        result = self.client.authenticate(**request(headers={"authorization": f"Bearer {PUBLISHABLE_KEY}"}))
        self.assertEqual((result.session, result.reason), (None, "missing"))

    def test_cookie_and_csrf(self):
        cookies = {f"__Host-murkio_session_{HASH}": self.token, f"__Host-murkio_uat_{HASH}": "1"}
        self.assertIsNotNone(self.client.authenticate(**request(cookies=cookies)).session)
        blocked = self.client.authenticate(**request("POST", cookies=cookies, headers={"Sec-Fetch-Site": "cross-site"}))
        self.assertEqual(blocked.reason, "csrf")
        self.assertTrue(blocked.signed_in_hint)
        self.assertIsNotNone(self.client.authenticate(**request("POST", cookies=cookies, headers={"Sec-Fetch-Site": "same-origin"})).session)
        self.assertIsNotNone(self.client.authenticate(**request("POST", cookies=cookies, headers={"Origin": "https://app.example.com"})).session)
        self.assertEqual(self.client.authenticate(**request("POST", cookies=cookies, headers={"Origin": "https://evil.example"})).reason, "csrf")

    def test_cookie_names(self):
        plain = {f"murkio_session_{HASH}": self.token}
        self.assertEqual(self.client.authenticate(**request(cookies=plain)).reason, "missing")
        self.assertIsNotNone(self.client.authenticate(**request(host="localhost:8000", scheme="http", cookies=plain)).session)
        secure = {f"__Secure-murkio_session_{HASH}": self.token}
        self.assertEqual(self.client.authenticate(**request(cookies=secure)).reason, "missing")
        self.assertIsNotNone(self.api.client(cookie_domain=".example.com").authenticate(**request(cookies=secure)).session)

    def test_expired_and_invalid(self):
        expired = self.api.token(exp=1)
        self.assertEqual(self.client.authenticate(**request(headers={"Authorization": f"Bearer {expired}"})).reason, "expired")
        other = self.api.token(aud="app-2")
        self.assertEqual(self.client.authenticate(**request(headers={"Authorization": f"Bearer {other}"})).reason, "invalid")

    def test_user_and_revocation_are_cached(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        for _ in range(2):
            result = self.client.authenticate(**request(headers=headers), load_user=True, check_revocation=True)
        self.assertEqual(result.user.email, "ana@example.com")
        self.assertEqual(self.api.calls.count("POST /v1/me"), 1)
        self.assertEqual(self.api.calls.count("POST /v1/sessions/verify"), 1)

        revoked = self.api.token(jti="revoked")
        self.api.revoked.add(revoked)
        result = self.client.authenticate(**request(headers={"Authorization": f"Bearer {revoked}"}), check_revocation=True)
        self.assertEqual((result.session, result.reason), (None, "revoked"))


class Protect(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.client = self.api.client()
        self.token = self.api.token()
        self.page = {"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}

    def protect(self, path="/dashboard", headers=None, cookies=None, **options):
        return self.client.protect(**request(headers=headers, cookies=cookies), path=path, **options)

    def test_unauthorized_and_redirect(self):
        _, response = self.protect("/api", required=True)
        self.assertEqual(response.status, 401)
        _, response = self.protect("/dashboard?tab=1", headers=self.page, required=True, sign_in_url="/login")
        self.assertEqual(response.status, 302)
        self.assertEqual(dict(response.headers)["Location"], "/login?redirect=%2Fdashboard%3Ftab%3D1")

    def test_roles_and_optional(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        self.assertEqual(self.protect(headers=headers, roles=["admin"])[1].status, 403)
        self.assertIsNone(self.protect(headers=headers, roles=["user"])[1])
        result, response = self.protect()
        self.assertIsNone(response)
        self.assertIsInstance(result, AuthResult)

    def test_handshake(self):
        cookies = {f"__Host-murkio_uat_{HASH}": "1"}
        _, response = self.protect(headers=self.page, cookies=cookies, required=True)
        headers = dict(response.headers)
        nonce = headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
        body = response.body.decode()
        self.assertEqual(response.status, 200)
        self.assertIn(f'nonce="{nonce}"', body)
        self.assertIn(f'data-murkio-key="{PUBLISHABLE_KEY}"', body)
        self.assertIn("connect-src https://api.example.com;", headers["Content-Security-Policy"])
        self.assertIn("murkio_handshake=1", headers["Set-Cookie"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        cookies["murkio_handshake"] = "1"
        self.assertEqual(self.protect(headers=self.page, cookies=cookies, required=True)[1].status, 401)
        self.assertEqual(self.protect(headers=self.page, cookies={f"__Host-murkio_uat_{HASH}": "1"}, required=True, handshake=False)[1].status, 401)


class Pages(unittest.TestCase):
    def test_helpers_escape_and_pin_the_bundle(self):
        from murkio import _cdn

        client = FakeApi().client()
        head = client.head(after_login="/home")
        self.assertIn(f'integrity="{_cdn.INTEGRITY}"', head)
        self.assertIn('crossorigin="anonymous"', head)
        self.assertIn('data-murkio-after-login="/home"', head)
        self.assertEqual(head.__html__(), head)
        self.assertEqual(client.canvas(), "<murkio-identity-canvas></murkio-identity-canvas>")
        self.assertEqual(
            client.canvas(class_='" onload="x', light_dom=True), '<murkio-identity-canvas class="&quot; onload=&quot;x" light-dom></murkio-identity-canvas>'
        )
        self.assertEqual(
            client.email_input(class_="input", placeholder="you@example.com"),
            '<murkio-identity-email-input class="input" placeholder="you@example.com"></murkio-identity-email-input>',
        )
        self.assertEqual(
            client.login_button("Entrar", class_="btn"), '<murkio-identity-login-button class="btn" label="Entrar"></murkio-identity-login-button>'
        )

        inline = client.bootstrap_script()
        self.assertNotIn("</script><b>", inline)
        self.assertIn("data-generated-at=", inline)
        payload = inline.split(">", 1)[1].rsplit("</script>", 1)[0]
        self.assertEqual(json.loads(payload)["canvas"]["document"]["note"], "</script><b>&\u2028")
        self.assertNotIn("\u2028", payload)

    def test_self_hosted_script(self):
        client = FakeApi().client(script_url="https://static.example.com/murkio.js")
        self.assertNotIn("integrity", client.head())
        self.assertIn('src="https://static.example.com/murkio.js"', client.head())

    def test_parse_cookies(self):
        self.assertEqual(parse_cookies("a=1; b=x%20y; a=2; empty="), {"a": "1", "b": "x y"})

    def test_only_http_is_requested(self):
        # The address of the keys comes from the API: urllib would also open file: and ftp: URLs.
        send = _urllib_transport(1.0)
        for url in ("file:///etc/hostname", "ftp://example.com/keys", "/etc/hostname"):
            with self.assertRaises(OSError, msg=url):
                send("GET", url, {}, None)


if __name__ == "__main__":
    unittest.main()
