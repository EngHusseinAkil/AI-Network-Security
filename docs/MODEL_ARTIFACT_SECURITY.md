# Model Artifact Security

## Critical Security Limitations of Deserialization

> [!CAUTION]
> Machine Learning model artifacts exported with `Joblib` or `Pickle` are not secure formats. They serialize complete Python object hierarchies and can silently execute arbitrary code during the `joblib.load()` process.

### Trust vs. Integrity
- **SHA-256 Hashes detect modification but do not prove trust:** A valid SHA-256 hash inside a model manifest merely guarantees that the model file has not been altered since the manifest was created. It does *not* prove that the model is non-malicious. An attacker who supplies a malicious model can easily supply a matching SHA-256 manifest.
- **Strict Sourcing Requirement:** Only project-controlled artifacts directly built within trusted environments may be loaded. No model should be accepted from email, chat, unknown websites, or untrusted repositories.

## Zero Payload Processing Policy
Under no circumstances should raw traffic payloads (the contents of network packets beyond headers) enter the AI features pipeline. Doing so exposes the platform to payload injection attacks, adversarial text crafting, and severe privacy violations. The parser discards payloads immediately.

## Pseudonymization Disclaimer
Network flows track IP addresses and ports to monitor behavior. When writing to logs or performing diagnostics, flow identifiers are obfuscated via hashed opaque identifiers.
> [!IMPORTANT]
> Flow identifiers are pseudonymized (via hashing), which provides pseudonymization, not anonymization. Hashing is not anonymization and predictable network identifiers may remain guessable.

## Action Mitigation and Risk Scores
- **No Automated Mitigation (Yet):** No automated blocking or MAC banning is currently authorized or technically enforced in the pipeline.
- **Confidence vs. Certainty:** The AI engine outputs confidence scores (e.g., 94% chance of DDoS), but confidence is not certainty.
- **Risk Scores:** The AI risk score is derived from the statistical label. It is not equivalent to actual business impact. High-risk traffic hitting an unused honeypot port has zero true business impact compared to low-risk anomalous traffic targeting a mission-critical database.
