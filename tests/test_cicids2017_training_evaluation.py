import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from ai.cicids2017_preprocessing import encode_protocol
from ai.model_persistence import load_model_artifact
from ai.cicids2017_training_evaluation import LABELS, feature_only_hash, sha256_file


SUBSET_MANIFEST = Path("data/processed/cicids2017/training_subset/training_subset_manifest.json")
TEST_SPLIT = Path("data/processed/cicids2017/splits/primary_test.csv")
REGISTRY = Path("models/registry.json")


def test_feature_only_hash_excludes_label_by_contract():
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 1, 2]
    assert feature_only_hash(values) == feature_only_hash(values)
    assert feature_only_hash(values) != feature_only_hash(values[:-1] + [3])


def test_training_labels_are_exactly_the_five_approved_classes():
    assert LABELS == ["benign", "ddos", "port_scan", "brute_force", "botnet"]


def test_protocol_mapping_matches_raw_cicids_contract():
    assert [encode_protocol(str(value)) for value in (0, 6, 17, 1)] == [0, 1, 2, 3]


def test_primary_group_split_has_support_and_zero_overlap():
    audit = json.loads(Path("data/processed/cicids2017/splits/primary_split_audit.json").read_text())
    assert audit["feature_hash_overlap"] == 0
    assert set(audit["train_counts"]) == set(LABELS)
    assert set(audit["test_counts"]) == set(LABELS)
    assert min(audit["test_counts"].values()) > 0


def test_training_subset_retains_all_mandatory_threat_groups_and_is_deterministic():
    manifest = json.loads(SUBSET_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["algorithm_version"] == "cicids2017-training-subset-v1"
    assert manifest["seed"] == 42
    assert manifest["mandatory_group_count"] == 112621
    assert manifest["mandatory_rows"] == 275883
    assert manifest["actual_rows"] == 500001
    assert manifest["feature_group_count"] == 296356
    assert manifest["feature_hash_overlap_with_test"] == 0
    assert manifest["output_sha256"]["training_subset.csv"] == "8245ded29e52e6e86f07e335695d5986cfe334af1745111254a3c9fe3c915467"


def test_training_subset_and_model_workflow_preserve_test_and_registry_state():
    manifest = json.loads(SUBSET_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["untouched_test_sha256_before"] == manifest["untouched_test_sha256_after"]
    assert manifest["untouched_test_sha256_after"] == sha256_file(TEST_SPLIT)
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert registry["active_model_version"] == "demo-1.0.0"
    assert "cicids2017-rf-1.0.0" not in registry["registered_models"]
    assert Path("models/model_cicids2017-rf-1.0.0/estimator.joblib").exists()


def test_saved_evaluation_metrics_recompute_from_confusion_and_saved_estimator():
    summary = json.loads(Path("data/processed/cicids2017/splits/training_evaluation_summary.json").read_text(encoding="utf-8"))
    primary = summary["primary"]
    cm = np.asarray(primary["confusion_matrix_counts"], dtype=np.int64)
    support = cm.sum(axis=1)
    true_positive = np.diag(cm)
    precision = true_positive / cm.sum(axis=0)
    recall = true_positive / support
    f1 = 2 * precision * recall / (precision + recall)
    total = int(cm.sum())
    assert total == 516085
    assert math.isclose(float(true_positive.sum() / total), primary["accuracy"], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(float(precision.mean()), primary["macro_precision"], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(float(recall.mean()), primary["macro_recall"], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(float(f1.mean()), primary["macro_f1"], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(float(np.average(precision, weights=support)), primary["weighted_precision"], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(float(np.average(recall, weights=support)), primary["weighted_recall"], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(float(np.average(f1, weights=support)), primary["weighted_f1"], rel_tol=0, abs_tol=1e-15)
    for index, label in enumerate(LABELS):
        reported = primary["per_class"][label]
        assert math.isclose(float(precision[index]), reported["precision"], rel_tol=0, abs_tol=1e-15)
        assert math.isclose(float(recall[index]), reported["recall"], rel_tol=0, abs_tol=1e-15)
        assert math.isclose(float(f1[index]), reported["f1-score"], rel_tol=0, abs_tol=1e-15)
        assert int(support[index]) == reported["support"]

    benign_false_positives = int(cm[0, 1:].sum())
    threat_false_negatives = int(cm[1:, 0].sum())
    assert benign_false_positives == 72690
    assert threat_false_negatives == 2391
    binary = primary["binary_benign_threat"]
    assert binary["fp"] == benign_false_positives
    assert binary["fn"] == threat_false_negatives
    assert math.isclose(binary["false_positive_rate"], benign_false_positives / support[0], rel_tol=0, abs_tol=1e-15)
    assert math.isclose(binary["false_negative_rate"], threat_false_negatives / support[1:].sum(), rel_tol=0, abs_tol=1e-15)

    test = pd.read_csv(TEST_SPLIT)
    estimator = load_model_artifact("models/model_cicids2017-rf-1.0.0")["estimator"]
    features = ["duration", "packet_count", "byte_count", "min_packet_size", "max_packet_size", "avg_packet_size", "protocol_enc", "direction_enc"]
    y = test["label"].map({label: index for index, label in enumerate(LABELS)}).to_numpy()
    probabilities = estimator.predict_proba(test[features])
    assert math.isclose(roc_auc_score(y, probabilities, multi_class="ovr", average="macro"), primary["roc_auc_ovr_macro"], rel_tol=0, abs_tol=1e-15)
