import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ServiceUnavailableError
from network.features import FLOW_FEATURE_ORDER

class FakeInferenceService:
    def __init__(self):
        self.should_fail_load = False
        self.last_batch = None
        self.predict_result = {"predicted_canonical_label": "benign", "model_version": "v1"}
        self.predict_batch_result = {
            "count": 1,
            "model_version": "v1",
            "predictions": [{"predicted_canonical_label": "benign"}]
        }

    def predict_flow(self, safe_features):
        if self.should_fail_load:
            raise ServiceUnavailableError("model_unavailable: Active model could not be loaded safely.")
        return self.predict_result

    def predict_flows(self, safe_features_list):
        if self.should_fail_load:
            raise ServiceUnavailableError("model_unavailable: Active model could not be loaded safely.")
        self.last_batch = safe_features_list
        return {
            **self.predict_batch_result,
            "count": len(safe_features_list),
            "predictions": [
                {"predicted_canonical_label": f"result-{index}"}
                for index, _ in enumerate(safe_features_list)
            ],
        }

@pytest.fixture
def app():
    deps = DependencyContainer()
    deps.inference_service = FakeInferenceService()

    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_infer_flow_success(client):
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
        "direction_enc": 2.0
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["data"]["predicted_canonical_label"] == "benign"

def test_infer_flow_missing_field(client):
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0
        # missing direction_enc
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Missing required fields" in data["error"]["message"]

def test_infer_flow_extra_field(client):
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
        "direction_enc": 2.0,
        "extra": 99.0
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "extra fields" in data["error"]["message"]

def test_infer_flow_forbidden_label(client):
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
        "direction_enc": 2.0,
        "label": "benign"
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 400

def test_infer_flow_invalid_type(client):
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
        "direction_enc": "2.0" # string
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 400

def test_infer_flow_invalid_protocol(client):
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 99.0, # invalid
        "direction_enc": 2.0
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 400

def test_infer_flow_wrong_content_type(client):
    response = client.post('/api/v1/inference/flow', data="not json", content_type='text/plain')
    assert response.status_code == 415

def test_infer_flow_malformed_json(client):
    response = client.post('/api/v1/inference/flow', data="{bad json", content_type='application/json')
    assert response.status_code == 400

def test_infer_flow_no_active_model(app, client):
    app.extensions['dependencies'].inference_service.should_fail_load = True
    payload = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
        "direction_enc": 2.0
    }
    response = client.post('/api/v1/inference/flow', json=payload)
    assert response.status_code == 503
    data = response.get_json()
    assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert "model_unavailable" in data["error"]["message"]

def test_infer_batch_flows_success(client):
    payload = {
        "flows": [
            {
                "duration": 1.0,
                "packet_count": 2,
                "byte_count": 3,
                "min_packet_size": 4,
                "max_packet_size": 5,
                "avg_packet_size": 6.0,
                "protocol_enc": 1.0,
                "direction_enc": 2.0
            }
        ]
    }
    response = client.post('/api/v1/inference/flows', json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["data"]["count"] == 1
    assert data["data"]["predictions"][0]["predicted_canonical_label"] == "result-0"


def test_infer_batch_flows_two_rows_are_plain_canonical_dicts(app, client):
    first = {
        "direction_enc": 2,
        "protocol_enc": 1,
        "avg_packet_size": 150.0,
        "max_packet_size": 150,
        "min_packet_size": 64,
        "byte_count": 1500,
        "packet_count": 10,
        "duration": 1.5,
    }
    second = {
        **first,
        "duration": 10.0,
        "packet_count": 10000,
        "byte_count": 640000,
        "max_packet_size": 64,
        "avg_packet_size": 64.0,
        "direction_enc": 3,
    }

    response = client.post("/api/v1/inference/flows", json={"flows": [first, second]})

    assert response.status_code == 200
    safe_batch = app.extensions["dependencies"].inference_service.last_batch
    assert all(type(row) is dict for row in safe_batch)
    assert all(list(row) == FLOW_FEATURE_ORDER for row in safe_batch)
    assert [row["duration"] for row in safe_batch] == [1.5, 10.0]
    labels = [
        item["predicted_canonical_label"]
        for item in response.get_json()["data"]["predictions"]
    ]
    assert labels == ["result-0", "result-1"]

def test_infer_batch_flows_missing_wrapper(client):
    payload = {
        "not_flows": []
    }
    response = client.post('/api/v1/inference/flows', json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "exactly the 'flows' key" in data["error"]["message"]

def test_infer_batch_flows_empty(client):
    payload = {
        "flows": []
    }
    response = client.post('/api/v1/inference/flows', json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "Empty batch" in data["error"]["message"]

def test_infer_batch_flows_exceeds_max(app, client):
    app.config['MAX_INFERENCE_BATCH_SIZE'] = 1
    payload = {
        "flows": [
            {
                "duration": 1.0, "packet_count": 2, "byte_count": 3,
                "min_packet_size": 4, "max_packet_size": 5, "avg_packet_size": 6.0,
                "protocol_enc": 1.0, "direction_enc": 2.0
            },
            {
                "duration": 1.0, "packet_count": 2, "byte_count": 3,
                "min_packet_size": 4, "max_packet_size": 5, "avg_packet_size": 6.0,
                "protocol_enc": 1.0, "direction_enc": 2.0
            }
        ]
    }
    response = client.post('/api/v1/inference/flows', json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "exceeded limit" in data["error"]["message"]

def test_infer_batch_flows_invalid_item(client):
    payload = {
        "flows": [
            {
                "duration": 1.0, "packet_count": 2, "byte_count": 3,
                "min_packet_size": 4, "max_packet_size": 5, "avg_packet_size": 6.0,
                "protocol_enc": 1.0, "direction_enc": 2.0
            },
            {
                "duration": -1.0, # invalid
                "packet_count": 2, "byte_count": 3,
                "min_packet_size": 4, "max_packet_size": 5, "avg_packet_size": 6.0,
                "protocol_enc": 1.0, "direction_enc": 2.0
            }
        ]
    }
    response = client.post('/api/v1/inference/flows', json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "Validation failed for item in batch" in data["error"]["message"]
    assert "flows[1].duration cannot be negative" in data["error"]["message"]
    assert data["error"]["details"]["item_index"] == 1


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("protocol_enc", 9, "flows[1].protocol_enc is unsupported"),
        ("direction_enc", 9, "flows[1].direction_enc is unsupported"),
        ("packet_count", "many", "flows[1].packet_count must be an integer or float"),
    ],
)
def test_infer_batch_flows_reports_indexed_field_error(client, field, value, expected):
    valid = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
        "direction_enc": 2.0,
    }
    invalid = {**valid, field: value}

    response = client.post("/api/v1/inference/flows", json={"flows": [valid, invalid]})

    assert response.status_code == 400
    assert expected in response.get_json()["error"]["message"]


def test_infer_batch_flows_reports_index_for_missing_feature(client):
    flow = {
        "duration": 1.0,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": 1.0,
    }

    response = client.post("/api/v1/inference/flows", json={"flows": [flow]})

    assert response.status_code == 400
    assert "flows[0].direction_enc" in response.get_json()["error"]["message"]


def test_infer_batch_flows_malformed_json(client):
    response = client.post(
        "/api/v1/inference/flows",
        data='{"flows": [}',
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json()["error"]["message"] == "Malformed JSON body."
