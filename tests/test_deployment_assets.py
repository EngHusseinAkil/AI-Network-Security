from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_container_uses_non_root_wsgi_server_and_healthcheck():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER app" in dockerfile
    assert '"gunicorn"' in dockerfile
    assert "/health/live" in dockerfile
    assert "flask run" not in dockerfile
    assert "pip install" in dockerfile
    assert "--requirement requirements.txt" in dockerfile


def test_image_excludes_secrets_and_operations_document_limitations():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "PRODUCTION_OPERATIONS.md").read_text(encoding="utf-8")
    assert ".env" in ignored and ".git" in ignored
    assert "separate" in docs and "migration" in docs
    assert "Worker-local" in docs
    assert "cannot be recovered" in docs
