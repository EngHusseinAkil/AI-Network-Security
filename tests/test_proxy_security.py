from flask import Flask, request

from backend.app_factory import create_app
from backend.security import setup_security_middleware


def test_untrusted_forwarded_headers_are_ignored_and_bad_host_rejected():
    app = create_app({
        "TESTING": True, "TRUSTED_PROXY_HOPS": 0,
        "TRUSTED_HOSTS": ("localhost",),
    })
    app.add_url_rule("/scheme", "scheme", lambda: request.scheme)
    client = app.test_client()
    assert client.get(
        "/scheme", headers={"X-Forwarded-Proto": "https"}
    ).get_data(as_text=True) == "http"
    assert client.get("/scheme", headers={"Host": "attacker.example"}).status_code == 400


def test_explicit_proxy_hop_is_honored():
    app = create_app({
        "TESTING": True, "TRUSTED_PROXY_HOPS": 1,
        "TRUSTED_HOSTS": ("security.example",),
    })
    app.add_url_rule("/scheme", "scheme", lambda: request.scheme)
    response = app.test_client().get(
        "/scheme",
        headers={"Host": "proxy", "X-Forwarded-Host": "security.example",
                 "X-Forwarded-Proto": "https"},
    )
    assert response.get_data(as_text=True) == "https"


def test_hsts_only_for_secure_production_request():
    app = Flask(__name__)
    app.config["ENVIRONMENT"] = "production"
    setup_security_middleware(app)
    app.add_url_rule("/", "index", lambda: "ok")
    client = app.test_client()
    assert "Strict-Transport-Security" not in client.get("/").headers
    assert "Strict-Transport-Security" in client.get(
        "/", environ_overrides={"wsgi.url_scheme": "https"}
    ).headers
