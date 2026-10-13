# CICIDS2017: why a single accuracy score is insufficient

Evidence reviewed on 13 October 2026. This is a historical local benchmark, not real-world deployment performance. The dataset is not redistributed.

## Pipeline and evidence

The inspected implementation derives eight numeric features: duration, packet count, byte count, minimum/maximum/average packet size, protocol encoding, and direction encoding. The processed table contains those eight columns plus a canonical label.

An independent streaming count confirmed **2,575,538 data rows**. SHA-256 was recomputed as `b925f77db5af43ee42156a70cf413431f7fd0d7ff305c1468ad3d6e646cdc154`, matching the preprocessing manifest. Raw-data provenance and licensing were not independently re-audited in this portfolio task.

Saved model metadata records a 100-tree Random Forest fitted on a **500,001-row reduced training subset**, evaluated on a **516,085-row primary test partition**. The saved evaluation and local report describe a label-independent feature-group-aware split. The full 2,059,453-row primary training partition was not fitted because of a RAM safety gate. The preprocessing count must not be advertised as the training count.

## Recorded primary results

| Measure | Recorded value |
| --- | ---: |
| Overall accuracy | 0.854487 |
| Macro F1 | 0.649419 |
| Brute-force recall | 0.225273 |
| Botnet precision | 0.005908 |
| Botnet recall | 0.995360 |

The saved confusion matrix and metadata were inspected; no new training or full evaluation was run here. The current suite includes a saved-metric recomputation test that passed in the original run. These results describe this benchmark and selected representation, not universal IDS accuracy.

## What the errors taught us

The historical audit identifies 554 feature vectors with conflicting labels, covering 323,407 rows. An identical eight-feature vector cannot be separated by any classifier using only those features. High botnet recall with extremely low precision can generate many false alerts; it is not reliable botnet protection. Training reduction changes prevalence, and raw model scores are not calibrated attack probabilities.

The trained CICIDS2017 artifact is **inactive**. The original registry selects a separate synthetic `demo-1.0.0` artifact and contains a stale absolute path after a directory move. Public source excludes both model binaries and that machine-specific registry. Create the synthetic demo through the documented CLI; do not activate a benchmark artifact by editing the registry.

## Reproduction boundary

`ai/cicids2017_preprocessing.py` and `ai/cicids2017_training_evaluation.py` implement the local adapter and training/evaluation workflow. Acquire any third-party input separately under its terms; raw data, processed tables, and serialized models remain ignored. Follow source contracts and inspect manifests before running a resource-intensive benchmark. This repository does not promise a one-command recreation without the authorized input and machine resources.

No malware, zero-day, autonomous blocking, operational detection accuracy, or deployed protection claim is made.
