from backend.app_factory import create_app


def test_request_id_generated_accepted_and_malformed_replaced():
    app = create_app({"TESTING": True})
    client = app.test_client()
    generated = client.get("/api/v1/_internal/ping").headers["X-Request-ID"]
    assert generated
    accepted = client.get(
        "/api/v1/_internal/ping", headers={"X-Request-ID": "edge:request-42"}
    ).headers["X-Request-ID"]
    assert accepted == "edge:request-42"
    replaced = client.get(
        "/api/v1/_internal/ping", headers={"X-Request-ID": "../unsafe value"}
    ).headers["X-Request-ID"]
    assert replaced != "../unsafe value"
    assert len(replaced) <= 64
