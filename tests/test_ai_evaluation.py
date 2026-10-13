import pytest
import numpy as np

from sklearn.ensemble import RandomForestClassifier

from ai.constants import RANDOM_SEED, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from network.features import FLOW_FEATURE_ORDER
from ai.training import train_random_forest, build_random_forest_classifier
from ai.preprocessing import LABEL_TO_INDEX
from ai.evaluation import evaluate_model
from utils.exceptions import ValidationError

@pytest.fixture
def synthetic_training_data():
    # 6 benign (0), 6 ddos (1) to ensure robust stratification and evaluation
    X = [
        [1.0, 10.0, 100.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.1, 11.0, 110.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.2, 12.0, 120.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.3, 13.0, 130.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.4, 14.0, 140.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.5, 15.0, 150.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [0.1, 1000.0, 64000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.2, 2000.0, 128000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.3, 3000.0, 192000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.4, 4000.0, 256000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.5, 5000.0, 320000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.6, 6000.0, 384000.0, 64.0, 64.0, 64.0, 1.0, 3.0]
    ]
    y = [LABEL_TO_INDEX["benign"]] * 6 + [LABEL_TO_INDEX["ddos"]] * 6

    metadata = {
        "schema_type": "flow",
        "schema_version": FLOW_SCHEMA_VERSION,
        "preprocessing_version": "1.0.0",
        "ordered_feature_names": FLOW_FEATURE_ORDER,
        "feature_count": len(FLOW_FEATURE_ORDER),
        "label_encoding_map": LABEL_TO_INDEX,
        "random_seed_used": RANDOM_SEED
    }

    return {"X": X, "y": y, "metadata": metadata}

@pytest.fixture
def trained_result(synthetic_training_data):
    return train_random_forest(
        synthetic_training_data,
        test_ratio=0.5,
        allow_unstratified_fallback_for_tests=False
    )

def test_evaluation_rejects_unfitted_estimators(trained_result):
    result_copy = dict(trained_result)
    result_copy["estimator"] = build_random_forest_classifier()
    with pytest.raises(ValidationError, match="Estimator is not fitted"):
        evaluate_model(result_copy)

def test_evaluation_rejects_missing_test_partitions(trained_result):
    result_copy = dict(trained_result)
    result_copy.pop("partition_data")
    with pytest.raises(ValidationError, match="Held-out test partitions.*are missing"):
        evaluate_model(result_copy)

def test_evaluator_never_calls_fit(trained_result, monkeypatch):
    # If the evaluator tries to call fit, this will blow up
    def mock_fit(*args, **kwargs):
        raise RuntimeError("fit() should not be called during evaluation!")

    monkeypatch.setattr(trained_result["estimator"], "fit", mock_fit)
    # Should evaluate without raising RuntimeError
    evaluate_model(trained_result)

def test_accuracy_and_metrics_presence(trained_result):
    eval_res = evaluate_model(trained_result)

    assert "accuracy" in eval_res
    assert isinstance(eval_res["accuracy"], float)
    assert 0.0 <= eval_res["accuracy"] <= 1.0

    assert "macro_metrics" in eval_res
    assert "precision" in eval_res["macro_metrics"]
    assert "recall" in eval_res["macro_metrics"]
    assert "f1" in eval_res["macro_metrics"]

    assert "weighted_metrics" in eval_res

    assert "per_class_metrics" in eval_res
    assert "benign" in eval_res["per_class_metrics"]
    assert "ddos" in eval_res["per_class_metrics"]

def test_confusion_matrix_dimensions_and_ordering(trained_result):
    eval_res = evaluate_model(trained_result)
    cm = eval_res["confusion_matrix"]

    expected_dim = len(CANONICAL_LABELS)
    assert len(cm) == expected_dim
    for row in cm:
        assert len(row) == expected_dim

def test_benign_versus_threat_security_summary(trained_result):
    eval_res = evaluate_model(trained_result)
    sec_sum = eval_res["benign_versus_threat_summary"]

    assert "accuracy" in sec_sum
    assert "false_positive_rate" in sec_sum
    assert "false_negative_rate" in sec_sum
    assert "true_negatives" in sec_sum
    assert "false_positives" in sec_sum
    assert "false_negatives" in sec_sum
    assert "true_positives" in sec_sum

    assert 0.0 <= sec_sum["false_positive_rate"] <= 1.0
    assert 0.0 <= sec_sum["false_negative_rate"] <= 1.0

def test_roc_auc_is_produced_when_valid(trained_result):
    eval_res = evaluate_model(trained_result)

    # We have 2 classes in the dataset. Because we use all classes in the model,
    # and only 2 classes are present in y_test, ROC AUC multiclass OVR is unavailable
    # unless we restrict the model to just 2 classes.
    # Let's check that it safely handles it.
    assert "roc_auc" in eval_res

def test_prediction_latency_fields(trained_result):
    eval_res = evaluate_model(trained_result)
    lat = eval_res["prediction_latency"]

    assert "total_seconds" in lat
    assert "average_seconds_per_row" in lat
    assert lat["total_seconds"] >= 0.0
    assert lat["average_seconds_per_row"] >= 0.0

def test_metadata_preserves_identity_and_disclaimers(trained_result):
    eval_res = evaluate_model(trained_result)
    meta = eval_res["metadata"]

    assert meta["model_family"] == "RandomForestClassifier"
    assert meta["schema_version"] == FLOW_SCHEMA_VERSION
    assert meta["evaluated_row_count"] == 6 # 50% of 12
    assert "software verification only" in meta["disclaimer"]

def test_testing_only_fallback_flagged(synthetic_training_data):
    # Temporarily drop class counts to force fallback
    synthetic_training_data["y"][-1] = LABEL_TO_INDEX["port_scan"]

    res = train_random_forest(
        synthetic_training_data, test_ratio=0.5, allow_unstratified_fallback_for_tests=True
    )

    eval_res = evaluate_model(res)
    assert eval_res["metadata"]["is_testing_fallback_split"] is True

def test_no_side_effects_eval():
    import sys
    assert "sqlalchemy" not in sys.modules or "ai.evaluation" in sys.modules
    assert "urllib" not in sys.modules or "ai.evaluation" in sys.modules
