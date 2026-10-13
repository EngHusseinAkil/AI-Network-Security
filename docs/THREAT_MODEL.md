# Threat Model and Security Review

Scope: the 1.0.0 Flask/dashboard boundary, process-local monitoring pipeline,
database, model artifacts, and injected providers. Test references are repository
files or focused test families.

| Asset | Threat | Mitigation | Residual risk | Evidence |
| --- | --- | --- | --- | --- |
| Accounts | brute force/default credentials/plaintext | no default users; CLI provisioning; adaptive hashes; rate limits | distributed guessing; operator password quality | `test_authentication*`, `test_user_account*`, `test_database_seed.py` |
| Session | fixation or reuse after logout/user change | session clear at login/logout; user-bound purpose tokens | stolen active cookie until expiry | `test_authentication.py`, action-token tests |
| Browser mutation | CSRF | POST-only forms and per-session CSRF validation | compromised same-origin script | `test_dashboard_*`, `test_csrf*` |
| Authorization | viewer mutation/operator user admin | centralized role requirements and route tests | mistaken role assignment | `test_authorization*`, `test_user_management*` |
| Action effects | token replay/cross-purpose use | expiry, purpose and user/session binding, constant-time checks | valid token theft within window | notification/defensive/alert token tests |
| Durable effects | duplicate alerts/deliveries/denies | unique idempotency keys, transaction conflict handling | provider succeeds before ambiguous failure | replay and concurrency tests |
| Capture host | malicious packet content | strict parsing, numeric metadata, bounds, no payload retention | parser/library defects and metadata DoS | `test_network_*`, capture tests |
| Privacy | raw payload or interface leakage | metadata-only records; opaque interface keys; safe status DTOs | aggregate timing/count inference | monitoring and flow-model tests |
| Model filesystem | model-path leakage/malicious artifact | safe registry views, artifact integrity validation, trusted local artifacts | compromised deployment filesystem | `test_ai_*`, `MODEL_ARTIFACT_SECURITY.md` |
| Provider secrets | credentials in UI/log/status | configuration-only injection, sanitized errors/log fields | host/environment compromise | notification and structured-log tests |
| Host firewall | defensive-action abuse | explicit confirmation, role check, bounded duration, fake/unavailable defaults | future real provider must add controls | `test_defensive_action*` |
| Proxy identity | spoofed forwarded headers | explicit trusted hop count and host allowlist | proxy topology misconfiguration | `test_production_config.py`, middleware tests |
| Signing | weak secrets/debug production | production startup rejects placeholders, short secrets, debug | poor secret storage/rotation | `test_production_config.py` |
| Schema/data | migration loss or drift | explicit status, backup-first confirmations, transactional migrations | unsupported engine differences | migration test families |
| Live state | process restart/worker split | bounded and explicitly documented process-local state; single owner | history loss is inherent | runtime capability/readiness tests |
| Availability | request/queue exhaustion | payload, rate, queue, batch, history, duration, and count bounds | single-process resource exhaustion | rate-limit, capture, flow tests |
| Reports | malicious cell/file values and CSV formulas | safe serializers, escaping/sanitization, no payload fields | spreadsheet behavior varies | simulation report/export tests |
| Navigation | open redirect | local-path-only `next` validation | application route confusion | authentication tests |
| Logs | secrets, paths, tokens, payloads | structured allowlisted fields and sanitized categories | operator-entered labels may be sensitive | structured logging/security tests |

Security assumptions: the host, database account, deployment environment, TLS
termination, model artifact directory, and administrator terminal are trusted.
The system does not provide network isolation, malware sandboxing, MFA, SSO, or
centralized revocation. Operators must review AI recommendations and comply with
capture, privacy, retention, and notification law.
