"""Public, low-detail deployment probes."""
from flask import Blueprint, current_app, jsonify


operations_bp = Blueprint("operations", __name__)


@operations_bp.get("/health/live")
def liveness():
    return jsonify({"status": "alive"}), 200


@operations_bp.get("/health/ready")
def readiness():
    report = current_app.extensions["dependencies"].readiness_service.check(
        current_app.config
    )
    return jsonify(report), 200 if report["status"] == "ready" else 503
