import pytest
import concurrent.futures
from backend.services.inference_service import InferenceService
from backend.app_factory import create_app
from backend.security import _rate_limits

class MockInferenceEngine:
    def __init__(self):
        self.load_count = 0

    def get_info(self):
        return {"model_version": "v1"}

def mock_engine_loader(*args, **kwargs):
    engine = MockInferenceEngine()
    engine.load_count += 1
    return engine

def test_inference_service_thread_safe_lazy_loading(monkeypatch):
    """
    Simulates concurrent requests accessing the InferenceService.
    Ensures _get_engine initializes exactly once.
    """
    service = InferenceService()

    monkeypatch.setattr('backend.services.inference_service.InferenceEngine.from_active_registry', mock_engine_loader)

    # Run concurrent threads accessing the engine
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(service._get_engine) for _ in range(5)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # Ensure they all received the exact same engine instance
    engine1 = results[0]
    for engine in results[1:]:
        assert engine is engine1

    # Ensure it was only loaded once
    assert engine1.load_count == 1

def test_rate_limiter_concurrency():
    """
    Ensures rate limiting maintains deterministic counts when hit concurrently.
    """
    _rate_limits.clear()
    app = create_app()
    app.config['TESTING'] = True
    app.config['TESTING_RATE_LIMITS'] = True
    app.config['RATE_LIMIT_DEFAULT'] = 5
    client = app.test_client()

    # Hit health endpoint 10 times concurrently
    def hit_health():
        return client.get('/api/v1/health').status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(hit_health) for _ in range(10)]
        statuses = [f.result() for f in concurrent.futures.as_completed(futures)]

    # We allow exactly 5 (or maybe 6 depending on initial > vs >= check in security.py)
    # The config limits to RATE_LIMIT_DEFAULT.
    # Current security.py: `if record["count"] > limit: raise`
    # So 5 is allowed. count starts at 1. count 2,3,4,5 are allowed. 6 raises.
    # So 5 success (200), 5 failed (429)
    successes = [s for s in statuses if s == 200]
    failures = [s for s in statuses if s == 429]

    # Actually count starts at 1, so requests 1,2,3,4,5 are successful. Request 6 will have count 6 > 5 (raises).
    # Since thread safety without explicit locks in dict updates might be slightly racy in python,
    # GIL mostly protects dict ops, but let's assert we got SOME 429s and SOME 200s, verifying the limiter triggers.
    assert len(failures) > 0
    assert len(successes) > 0

    # In a perfect GIL world, successes should be exactly 5
    assert len(successes) == 5
