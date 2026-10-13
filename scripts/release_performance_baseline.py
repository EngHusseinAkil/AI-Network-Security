"""Bounded local timing harness for release evidence; never sends network traffic."""
from statistics import median
from pathlib import Path
import os
import sys
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("LOG_DESTINATION", "stdout")

from backend.app_factory import create_app


def measure(label, operation, iterations=25):
    samples = []
    for _ in range(iterations):
        started = perf_counter()
        response = operation()
        elapsed = (perf_counter() - started) * 1000
        if getattr(response, "status_code", 200) >= 500:
            raise RuntimeError(f"{label} returned {response.status_code}")
        samples.append(elapsed)
    print(f"{label}: median={median(samples):.3f} ms, max={max(samples):.3f} ms, n={iterations}")


def main():
    started = perf_counter()
    app = create_app({"TESTING": True, "AUTHENTICATION_REQUIRED": False})
    startup_ms = (perf_counter() - started) * 1000
    client = app.test_client()
    print(f"app_startup: elapsed={startup_ms:.3f} ms, n=1")
    measure("liveness_get", lambda: client.get("/health/live"))
    measure("readiness_get", lambda: client.get("/health/ready"))
    measure("monitoring_status_get", lambda: client.get("/api/v1/monitoring/status"))
    print("Processing, evaluation, and alert rendering use bounded focused pytest workflows.")


if __name__ == "__main__":
    main()
