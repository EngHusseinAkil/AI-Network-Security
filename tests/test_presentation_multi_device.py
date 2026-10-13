from config import settings
from backend.app_factory import create_app
from dashboard.routes import _select_device_evaluation


class _Flows:
    def __init__(self, flows):
        self.flows = flows

    def get_completed_flow(self, flow_id):
        return self.flows.get(flow_id)


def record(evaluation_id, flow_id, risk, compatible=True):
    return {
        "evaluation_id": evaluation_id, "flow_id": flow_id,
        "feature_compatible": compatible, "inference_status": "success",
        "predicted_canonical_label": "benign", "confidence_score": .8,
        "risk_score": risk, "policy_status": "success", "alert_recommended": False,
        "model_version": "demo-1.0.0", "recommendation_token": None,
    }


def flow(flow_id, device_ip, packets=2):
    return {
        "flow_id": flow_id, "source_ip": device_ip, "destination_ip": "8.8.8.8",
        "source_mac": None, "destination_mac": None, "protocol": "TCP",
        "direction": "outbound", "packet_count": packets, "total_bytes": 200,
        "duration_seconds": 1.0, "minimum_packet_length": 100,
        "maximum_packet_length": 100, "mean_packet_length": 100.0,
    }


def test_device_evaluation_selection_is_per_device_and_not_risk_biased():
    status = {"recent_live_evaluations": (
        record("a-old", "flow-a-old", .99),
        record("b", "flow-b", .67),
        record("a-new", "flow-a-new", .10),
    )}
    flows = _Flows({
        "flow-a-old": flow("flow-a-old", "192.168.137.16", packets=1),
        "flow-a-new": flow("flow-a-new", "192.168.137.16", packets=2),
        "flow-b": flow("flow-b", "192.168.137.17", packets=2),
    })

    selected_a = _select_device_evaluation(status, flows, "192.168.137.16")
    selected_b = _select_device_evaluation(status, flows, "192.168.137.17")
    selected_c = _select_device_evaluation(status, flows, "192.168.137.18")

    assert selected_a[0]["evaluation_id"] == "a-new"
    assert selected_b[0]["evaluation_id"] == "b"
    assert selected_c == (None, None)


def test_presentation_demo_renders_all_selected_devices_and_waiting_state(monkeypatch):
    settings.LOG_DESTINATION = "console"
    app = create_app({"TESTING": True, "SECRET_KEY": "presentation-multi"})
    deps = app.extensions["dependencies"]
    monkeypatch.setattr(deps.dashboard_capture_service, "devices", lambda: (
        {"ip_address": "192.168.137.16", "mac_address": "AA:00:00:00:00:16", "hostname": "TECNO-POVA-6", "status": "reachable", "selected": True},
        {"ip_address": "192.168.137.17", "mac_address": "AA:00:00:00:00:17", "hostname": "iPhone", "status": "reachable", "selected": True},
        {"ip_address": "192.168.137.18", "mac_address": None, "hostname": None, "status": "seen", "selected": True},
    ))
    monkeypatch.setattr(deps.dashboard_live_flow_evaluation_service, "presentation", lambda csrf: {
        "recent_live_evaluations": (record("a", "flow-a", .62), record("b", "flow-b", .67)),
    })
    monkeypatch.setattr(deps.dashboard_flow_processing_service, "get_completed_flow", _Flows({
        "flow-a": flow("flow-a", "192.168.137.16"),
        "flow-b": flow("flow-b", "192.168.137.17"),
    }).get_completed_flow)

    response = app.test_client().get("/dashboard/presentation-demo")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "TECNO-POVA-6" in body and "iPhone" in body
    assert "192.168.137.18" in body and "WAITING FOR TRAFFIC" in body
    assert "2 EVALUATED" in body and "1 WAITING" in body
    detail = app.test_client().get("/dashboard/presentation-demo?device_ip=192.168.137.17")
    assert detail.status_code == 200
    assert b"192.168.137.16" in detail.data and b"192.168.137.17" in detail.data
