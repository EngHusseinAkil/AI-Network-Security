import ast
from pathlib import Path
import threading
from unittest.mock import Mock

from backend.app_factory import create_app


def test_orchestrator_has_no_forbidden_imports():
    path = Path(__file__).parents[1] / "backend/services/live_flow_evaluation_service.py"
    tree = ast.parse(path.read_text())
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert not any(name.startswith((
        "flask", "dashboard", "database", "requests", "httpx"
    )) for name in imports)


def test_startup_does_not_evaluate_or_create_worker():
    before = {thread.ident for thread in threading.enumerate()}
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    service = app.extensions["dependencies"].live_flow_evaluation_service
    service.evaluate = Mock()
    after = {thread.ident for thread in threading.enumerate()}
    assert before == after
    service.evaluate.assert_not_called()


def test_processing_and_capture_actions_do_not_evaluate():
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    evaluation = app.extensions["dependencies"].live_flow_evaluation_service
    evaluation.evaluate = Mock()
    processor = app.extensions["dependencies"].capture_flow_processor
    processor.process()
    app.extensions["dependencies"].capture_service.status_snapshot()
    evaluation.evaluate.assert_not_called()


def test_safe_adapter_omits_internal_key_and_raw_features():
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    status = app.extensions["dependencies"].dashboard_live_flow_evaluation_service.status()
    assert "evaluation_key" not in repr(status)
    assert "features" not in repr(status)
    assert "model_path" not in repr(status)


def test_no_public_json_evaluation_write_api():
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    rules = [rule.rule for rule in app.url_map.iter_rules() if "evaluate" in rule.rule]
    assert rules == ["/dashboard/monitoring/flows/evaluate"]
