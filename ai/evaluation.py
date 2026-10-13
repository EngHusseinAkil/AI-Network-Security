"""
AI Formal Evaluation Framework.

Computes mathematically rigorous and deterministic security performance metrics
using only held-out test data. Strictly separated from model fitting logic.
"""

import time
from typing import Dict, Any, List

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    roc_auc_score
)
from sklearn.utils.validation import check_is_fitted

from ai.constants import CANONICAL_LABELS
from utils.exceptions import ValidationError

def evaluate_model(training_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates a fitted estimator using its held-out test partition.
    Returns a comprehensive security-focused metrics report.
    """
    # 1. Input Validation and Extraction
    estimator = training_result.get("estimator")
    if estimator is None:
        raise ValidationError("Evaluation requires a fitted estimator.")

    try:
        check_is_fitted(estimator)
    except Exception as e:
        raise ValidationError("Estimator is not fitted. Evaluation aborted.") from e

    partition_data = training_result.get("partition_data", {})
    X_test = partition_data.get("X_test")
    y_test = partition_data.get("y_test")

    if not X_test or not y_test:
        raise ValidationError("Held-out test partitions (X_test, y_test) are missing.")

    if len(X_test) != len(y_test):
        raise ValidationError("X_test and y_test lengths do not match.")

    model_metadata = training_result.get("model_metadata", {})
    label_encoding_map = model_metadata.get("label_encoding_map", {})
    if not label_encoding_map:
        raise ValidationError("Label encoding map is missing.")

    # Reverse mapping
    index_to_label = {v: k for k, v in label_encoding_map.items()}

    # 2. Latency Measurement (Inference Only)
    start_time = time.perf_counter()
    y_pred = estimator.predict(X_test)
    end_time = time.perf_counter()

    total_latency_sec = end_time - start_time
    per_row_latency_sec = total_latency_sec / len(X_test)

    # 3. Standard Multiclass Metrics
    accuracy = float(accuracy_score(y_test, y_pred))

    # zero_division=0 ensures we don't crash or get warnings when a class is absent
    # We use all classes explicitly to ensure deterministic metric lengths
    all_classes = sorted(list(label_encoding_map.values()))
    canonical_class_names = [index_to_label[c] for c in all_classes]

    precisions, recalls, f1s, supports = precision_recall_fscore_support(
        y_test, y_pred, labels=all_classes, zero_division=0
    )

    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average='macro', zero_division=0
    )

    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average='weighted', zero_division=0
    )

    conf_matrix = confusion_matrix(y_test, y_pred, labels=all_classes)

    per_class_metrics = {}
    for i, class_name in enumerate(canonical_class_names):
        per_class_metrics[class_name] = {
            "precision": float(precisions[i]),
            "recall": float(recalls[i]),
            "f1": float(f1s[i]),
            "support": int(supports[i])
        }

    # 4. Security Binary Threat Summary
    # Treat "benign" as the negative class (0), and anything else as threat (1)
    benign_idx = label_encoding_map.get("benign")
    if benign_idx is None:
        raise ValidationError("Canonical 'benign' label missing from encoding map.")

    y_test_binary = [0 if y == benign_idx else 1 for y in y_test]
    y_pred_binary = [0 if y == benign_idx else 1 for y in y_pred]

    # Binary confusion matrix explicitly using [0, 1]
    tn, fp, fn, tp = confusion_matrix(y_test_binary, y_pred_binary, labels=[0, 1]).ravel()

    # FP Rate = FP / (FP + TN)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    # FN Rate = FN / (FN + TP)
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    binary_accuracy = float(accuracy_score(y_test_binary, y_pred_binary))

    # 5. ROC-AUC Calculation
    roc_auc_result = "unavailable"
    unique_test_classes = set(y_test)

    if len(unique_test_classes) >= 2 and hasattr(estimator, "predict_proba"):
        try:
            y_proba = estimator.predict_proba(X_test)

            if len(all_classes) == 2:
                # Binary case
                # We need the probability of the positive class
                if len(unique_test_classes) == 2:
                    # estimator.classes_ tells us which column is which
                    positive_class_col = list(estimator.classes_).index(all_classes[1])
                    roc_auc_result = float(roc_auc_score(y_test, y_proba[:, positive_class_col]))
            else:
                # Multiclass one-vs-rest
                # This only works if all classes in the model are present in y_test, OR
                # if we specify the labels explicitly.
                # However, sklearn's roc_auc_score strictly requires all classes to be present in y_test
                # or multi_class='ovr' will fail or behave unpredictably with missing test classes.
                # Since we don't know if the test set contains all classes (especially with stratified splits on tiny sets)
                # we wrap it safely.
                if len(unique_test_classes) == len(all_classes):
                    roc_auc_result = float(roc_auc_score(y_test, y_proba, multi_class="ovr", labels=all_classes))
                else:
                    roc_auc_result = "unavailable: not all classes present in test set for multiclass ovr"
        except Exception as e:
            roc_auc_result = f"unavailable: {str(e)}"

    # 6. Final Result Assembly
    eval_metadata = {
        "model_family": model_metadata.get("model_family"),
        "schema_version": training_result.get("schema_metadata", {}).get("schema_version"),
        "evaluated_row_count": len(y_test),
        "ordered_canonical_classes": canonical_class_names,
        "is_testing_fallback_split": model_metadata.get("stratification_status") == "disabled_testing_fallback",
        "disclaimer": (
            "Metrics generated on synthetic/sample fixtures are for software verification only. "
            "They do NOT represent zero-day detection capability, production readiness, or real-world accuracy. "
            "Latency measurements are environment-specific."
        )
    }

    return {
        "metadata": eval_metadata,
        "accuracy": accuracy,
        "macro_metrics": {
            "precision": float(macro_p),
            "recall": float(macro_r),
            "f1": float(macro_f1)
        },
        "weighted_metrics": {
            "precision": float(weighted_p),
            "recall": float(weighted_r),
            "f1": float(weighted_f1)
        },
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": conf_matrix.tolist(),
        "benign_versus_threat_summary": {
            "accuracy": binary_accuracy,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "roc_auc": roc_auc_result,
        "prediction_latency": {
            "total_seconds": float(total_latency_sec),
            "average_seconds_per_row": float(per_row_latency_sec)
        }
    }
