# Dataset Policy

## Policy Overview
This project processes network telemetry data, which inherently poses significant privacy and compliance risks. To enforce strict regulatory compliance and safeguard source control, this repository prohibits the inclusion of massive, real-world packet captures (PCAP) or raw flow datasets (e.g., CIC-IDS2017).

## Allowed Data Fixtures
Only highly condensed, purely synthetic representations of network flow tables are permitted in the repository (e.g., `data/samples/tiny_flow_sample.csv`).

These tiny synthetic datasets must:
1. Contain **no real captured traffic**.
2. Contain **no raw payloads**.
3. Contain **no credentials, tokens, cookies, or personal data**.
4. Be small enough for safe Git tracking without Blobs.
5. Use exclusively the canonical labels defined in `ai/schema.py`.

## Model Evaluation and Scientific Disclaimers
The included 8-20 row synthetic fixtures are used solely to verify pipeline execution mechanics (e.g., data loading routines, preprocessing determinism, and integration boundaries). They make **no scientific claims** about real-world performance, zero-day threat detection capabilities, or production accuracy.

## Lifecycle and CI Environment Data
- **Git Ignore Constraints:** All raw and processed directories (`data/raw/`, `data/processed/`) are strictly ignored via `.gitignore` to prevent developer mistakes from leaking real internal traffic.
- **Leakage Prevention:** To avoid data leakage across subsets, training pipelines explicitly use independent testing/training splits, restricting scaling fits to the training set only. Testing data is never utilized during metric optimization or transformations.
