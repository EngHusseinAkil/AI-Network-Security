"""Gunicorn configuration; migrations remain a separate deployment step."""
import os

bind = os.getenv("BIND", "0.0.0.0:8000")
workers = int(os.getenv("WEB_WORKER_COUNT", "2"))
threads = int(os.getenv("WEB_THREADS", "2"))
timeout = 30
graceful_timeout = 15
accesslog = "-"
errorlog = "-"
capture_output = True

def worker_exit(server, worker):
    app = getattr(worker, "wsgi", None)
    dependencies = getattr(app, "extensions", {}).get("dependencies")
    if dependencies is not None:
        dependencies.shutdown_coordinator.shutdown()
