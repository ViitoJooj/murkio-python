"""The middlewares and the framework helpers. Flask, Django and FastAPI tests
are skipped when the framework is not installed."""

import asyncio
import unittest

from helpers import PUBLISHABLE_KEY, FakeApi
from murkio import fnv1a32
from murkio.asgi import MurkioMiddleware as AsgiMiddleware
from murkio.wsgi import MurkioMiddleware as WsgiMiddleware

HASH = fnv1a32(PUBLISHABLE_KEY)


def wsgi_call(app, path="/", method="GET", headers=None):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "", "wsgi.url_scheme": "https", "HTTP_HOST": "app.example.com"}
    for name, value in (headers or {}).items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    captured = {}

    def start_response(status, response_headers):
        captured["status"] = int(status.split()[0])
        captured["headers"] = dict(response_headers)

    captured["body"] = b"".join(app(environ, start_response))
    return captured


class Wsgi(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.client = self.api.client()

        def app(environ, start_response):
            session = environ["murkio"].session
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [f"hello {session.user_id if session else 'guest'}".encode()]

        self.app = app

    def test_optional_and_required(self):
        self.assertEqual(wsgi_call(WsgiMiddleware(self.app, self.client))["body"], b"hello guest")
        protected = WsgiMiddleware(self.app, self.client, required=True, sign_in_url="/login")
        self.assertEqual(wsgi_call(protected, "/api")["status"], 401)
        redirect = wsgi_call(protected, "/dashboard", headers={"Accept": "text/html"})
        self.assertEqual((redirect["status"], redirect["headers"]["Location"]), (302, "/login?redirect=%2Fdashboard"))
        signed = wsgi_call(protected, "/api", headers={"Authorization": f"Bearer {self.api.token()}"})
        self.assertEqual(signed["body"], b"hello user-1")

    def test_session_cookie(self):
        cookie = f"__Host-murkio_session_{HASH}={self.api.token()}; other=1"
        self.assertEqual(wsgi_call(WsgiMiddleware(self.app, self.client), headers={"Cookie": cookie})["body"], b"hello user-1")


class Asgi(unittest.TestCase):
    def call(self, app, path="/", headers=None):
        scope = {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "query_string": b"",
            "headers": [(b"host", b"app.example.com")] + [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        }
        sent = []

        async def run():
            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(message):
                sent.append(message)

            await app(scope, receive, send)

        asyncio.run(run())
        return sent

    def test_middleware(self):
        api = FakeApi()

        async def app(scope, receive, send):
            session = scope["murkio"].session
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": (session.user_id if session else "guest").encode()})

        protected = AsgiMiddleware(app, api.client(), required=True)
        self.assertEqual(self.call(protected)[0]["status"], 401)
        signed = self.call(protected, headers={"Authorization": f"Bearer {api.token()}"})
        self.assertEqual((signed[0]["status"], signed[1]["body"]), (200, b"user-1"))


class FlaskAdapter(unittest.TestCase):
    def test_init_app_and_protect(self):
        try:
            import flask
        except ImportError:
            self.skipTest("flask is not installed")
        from murkio.flask import current, init_app, protect

        api = FakeApi()
        client = api.client()
        app = flask.Flask(__name__)
        init_app(app, client)

        @app.get("/")
        def home():
            return flask.render_template_string("{{ murkio.canvas() }}|{{ 'in' if murkio_auth.session else 'out' }}")

        @app.get("/dashboard")
        @protect(client, required=True, sign_in_url="/login", load_user=True)
        def dashboard():
            return f"hello {current().user.email}"

        http = app.test_client()
        self.assertEqual(http.get("/").get_data(as_text=True), "<murkio-identity-canvas></murkio-identity-canvas>|out")
        redirect = http.get("/dashboard", headers={"Accept": "text/html"})
        self.assertEqual((redirect.status_code, redirect.headers["Location"]), (302, "/login?redirect=%2Fdashboard"))
        signed = http.get("/dashboard", headers={"Authorization": f"Bearer {api.token()}"})
        self.assertEqual(signed.get_data(as_text=True), "hello ana@example.com")


class DjangoAdapter(unittest.TestCase):
    def test_middleware_and_decorator(self):
        try:
            import django
            from django.conf import settings
        except ImportError:
            self.skipTest("django is not installed")
        if not settings.configured:
            settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], MURKIO={"sign_in_url": "/login"}, DEFAULT_CHARSET="utf-8")
            django.setup()
        from django.http import HttpResponse
        from django.test import RequestFactory

        import murkio.django as adapter

        api = FakeApi()
        adapter._client = api.client()

        @adapter.protect(required=True, load_user=True)
        def dashboard(request):
            return HttpResponse(f"hello {request.murkio.user.email}")

        factory = RequestFactory()
        redirect = dashboard(factory.get("/dashboard", HTTP_ACCEPT="text/html"))
        self.assertEqual((redirect.status_code, redirect["Location"]), (302, "/login?redirect=%2Fdashboard"))
        signed = dashboard(factory.get("/dashboard", HTTP_AUTHORIZATION=f"Bearer {api.token()}"))
        self.assertEqual(signed.content, b"hello ana@example.com")

        middleware = adapter.MurkioMiddleware(lambda request: HttpResponse("in" if request.murkio.session else "out"))
        self.assertEqual(middleware(factory.get("/")).content, b"out")
        adapter._client = None


class FastApiAdapter(unittest.TestCase):
    def test_dependencies(self):
        try:
            from fastapi import Depends, FastAPI
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest("fastapi is not installed")
        from murkio import Session
        from murkio.fastapi import require_session

        api = FakeApi()
        app = FastAPI()
        app.add_middleware(AsgiMiddleware, murkio=api.client())

        @app.get("/api/orders")
        def orders(session: Session = Depends(require_session())):
            return {"user": session.user_id}

        @app.get("/api/admin")
        def admin(session: Session = Depends(require_session(["admin"]))):
            return {"user": session.user_id}

        http = TestClient(app)
        self.assertEqual(http.get("/api/orders").status_code, 401)
        headers = {"Authorization": f"Bearer {api.token()}"}
        self.assertEqual(http.get("/api/orders", headers=headers).json(), {"user": "user-1"})
        self.assertEqual(http.get("/api/admin", headers=headers).status_code, 403)


if __name__ == "__main__":
    unittest.main()
