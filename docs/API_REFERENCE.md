# API Reference 1.0.0

API version `v1` uses safe JSON envelopes and `X-Request-ID`. Errors expose a
stable category/message, never stack traces, credentials, tokens, replay keys,
model paths, native interfaces, packet payloads, or request features. Payload and
rate limits apply.

Except public liveness/readiness, API routes require an authenticated session when
`AUTHENTICATION_REQUIRED` is enabled. Dashboard forms additionally require CSRF;
internal signed confirmation/recommendation tokens are not reusable public APIs.

## Public Operations Health

| Method/path | Authorization | Behavior |
| --- | --- | --- |
| `GET /health/live` | public | process liveness only |
| `GET /health/ready` | public | read-only configuration/dependency/migration readiness |

## API v1

| Method/path | Minimum access | Safe purpose |
| --- | --- | --- |
| `GET /api/v1/version` | authenticated | application/API version metadata |
| `GET /api/v1/health` | authenticated | aggregate health |
| `GET /api/v1/health/ai` | authenticated | safe AI availability |
| `GET /api/v1/health/backend` | authenticated | backend readiness |
| `GET /api/v1/models` | authenticated | safe model summaries |
| `GET /api/v1/models/active` | authenticated | active model summary |
| `POST /api/v1/inference/flow` | permitted authenticated user | explicit numeric flow inference |
| `POST /api/v1/inference/flows` | permitted authenticated user | explicit bounded batch inference |
| `GET /api/v1/devices[/{id}]` | authenticated | durable device views |
| `GET /api/v1/traffic[/{id}]` | authenticated | durable traffic views |
| `GET /api/v1/threats[/{id}]` | authenticated | durable threat views |
| `GET /api/v1/alerts[/<public-id>]` | authenticated | durable alert views |
| `GET /api/v1/monitoring/status` | authenticated | safe worker-local counters/latest summaries |

Inference accepts the documented numeric schema only; it performs no capture,
persistence, policy, alert, notification, or defense. Monitoring status performs
no draining, aggregation, feature extraction, inference, or mutation.

## Dashboard Surface

Dashboard GETs render overview, health, models, devices, traffic, threats,
inference, monitoring/history/reports, and alerts. Mutation POSTs cover login and
logout; capture interface refresh/start/stop; simulation; metadata processing;
flow evaluation; explicit recommendation-to-alert; alert lifecycle; notification;
defensive apply/removal; and user administration through server CLI.

All dashboard operational mutations require authentication, the role assigned by
the route policy, POST, and CSRF. Purpose-bound tokens additionally protect alert,
notification, lifecycle, and defensive actions. Expected errors include `400`
validation/CSRF, `401` unauthenticated, `403` forbidden, `404` absent,
`409` replay/concurrency conflict, `413` payload too large, `415` media type,
`429` rate limit, and `503` unavailable dependency.

Response DTOs are intentionally narrower than internal schemas. Consult route and
view-model tests for the exact stable safe fields; internal token payloads,
credential schemas, and deduplication material are deliberately undocumented.
