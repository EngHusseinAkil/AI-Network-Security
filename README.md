# AI-assisted Network Security Monitoring

A defensive network-monitoring reference application built with Flask, SQLAlchemy,
Scapy abstractions, and scikit-learn. It turns bounded packet metadata into
operator-reviewed AI recommendations. It does not retain packet payloads and does
not take operational action automatically.

## Portfolio status

Research/prototype developed by Hussein Nabil Akil. This public source snapshot excludes raw/processed datasets, saved models, databases, packet captures, logs, and private academic reports. It does not establish a deployed IDS or production intrusion prevention.

**Start with:** [benchmark case study](docs/BENCHMARK_CASE_STUDY.md), [current verification](docs/VERIFICATION.md), and [synthetic demo instructions](docs/DEMO_GUIDE.md).

The source includes explicit packet-capture and human-reviewed workflow implementations. The current branch also includes endpoint metadata for presentation joins; payload-free does not mean anonymous. Review the privacy impact before enabling capture. Some tests still expect the previous metadata contract.

## Capabilities

- Controlled, disabled-by-default capture through real or fake packet sources.
- Bounded metadata aggregation and exact eight-field feature extraction.
- Explicit single-flow and batch inference.
- Explicit policy recommendation, alert creation, notification, and temporary
  defensive-action workflows.
- Authenticated dashboard, viewer/operator/admin RBAC, CSRF protection, signed
  action tokens, durable audit records, and idempotent side-effect records.
- Liveness, readiness, migration, reporting, Docker, and Gunicorn foundations.

## Architecture

```text
packet source -> capture queue -> metadata-flow aggregation -> 8 features
  -> explicit inference -> explicit policy recommendation -> explicit alert
  -> explicit notification -> explicit temporary deny -> explicit removal
```

Authentication, authorization, CSRF, replay controls, and auditing surround every
mutation. Database entities are durable; interfaces, active/completed metadata
flows, evaluations, and some counters are process-local and bounded. See
[Architecture](docs/ARCHITECTURE.md) and [Threat model](docs/THREAT_MODEL.md).

## Security Model

- No default users or credentials. Passwords are adaptively hashed.
- Browser mutations require an authenticated permitted role, POST, CSRF, and
  purpose-bound signed confirmation where applicable.
- Capture stores metadata only; payload bytes and native interface identifiers
  are excluded from metadata-flow records and status responses.
- Alert, notification, and defensive-action idempotency is enforced durably.
- Production startup rejects weak secrets, debug/demo mode, fake providers,
  unsafe hosts, invalid proxy trust, and invalid database configuration.
- AI output is a recommendation for human review, never proof of an attack.

## Requirements

- Python 3.11 or later
- A supported SQLAlchemy database (SQLite for local use)
- Scapy and packet-capture permissions only when approved real capture is used
- Docker optionally, for the production image

## Development Setup

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:APP_ENV = "development"
$env:SECRET_KEY = "replace-with-a-long-random-development-value"
```

Never commit `.env` files, databases, logs, credentials, or generated tokens.

## Database and First Admin

Create a new schema, then provision the first account explicitly:

```powershell
.\venv\Scripts\flask.exe --app wsgi:app system schema-create
.\venv\Scripts\flask.exe --app wsgi:app users create
```

For an existing installation, back up first, inspect status, and run migrations:

```powershell
.\venv\Scripts\flask.exe --app wsgi:app system migration-status
.\venv\Scripts\flask.exe --app wsgi:app system migration-upgrade
```

Application startup never migrates the database automatically.

## Run

Development:

```powershell
.\venv\Scripts\flask.exe --app wsgi:app run
```

Tests:

```powershell
.\venv\Scripts\python.exe -m pytest --collect-only -q
.\venv\Scripts\python.exe -m pytest -v
```

Production uses `wsgi:app` through Gunicorn and the supplied non-root Docker
image. Configure secrets, database, trusted hosts/proxies, writable data/log
paths, and migrations before starting. Do not use Flask's development server.
See [Production operations](docs/PRODUCTION_OPERATIONS.md).

## Health

- `GET /health/live`: process liveness; no authentication and no secrets.
- `GET /health/ready`: dependency and migration readiness; no mutation.
- `flask system readiness`: operator-readable readiness with nonzero failure exit.
- `GET /api/v1/health`: authenticated application health.

## Demo

The deterministic demo uses fake capture, fake notification, and fake defensive
providers. It requires `DEMO_MODE=true`, preserves login/RBAC/CSRF, performs no
external request or OS/firewall operation, and is rejected in production.
Follow [Demo guide](docs/DEMO_GUIDE.md). Optional historical seed data is created
only after confirmation:

```powershell
.\venv\Scripts\flask.exe --app wsgi:app demo seed
```

## Configuration Reference

| Setting | Purpose | Safe default |
| --- | --- | --- |
| `APP_ENV` | `development`, `testing`, or `production` | `development` |
| `SECRET_KEY` | Session and action-token signing | placeholder; rejected in production |
| `DATABASE_URI` | SQLAlchemy connection URI | local SQLite in development |
| `DEMO_MODE` | Labels and permits local demo seeding | `false` |
| `CAPTURE_ENABLED` | Permits capture ownership | `false` |
| `CAPTURE_SOURCE` | `scapy` or development-only `fake` | `scapy` |
| `WEB_WORKER_COUNT` | Declared web workers | `1` |
| `TRUSTED_HOSTS` | Accepted hosts | local hosts |
| `TRUSTED_PROXY_HOPS` | Explicit proxy chain length | `0` |
| `MIGRATION_STRICT` | Fail readiness/startup on drift | production `true` |
| `ALERT_NOTIFICATIONS_ENABLED` | Enables explicit delivery requests | `false` |
| `DEFENSIVE_ACTIONS_ENABLED` | Enables explicit deny requests | `false` |

Provider-specific settings are documented in the administrator and production
guides. `.env.example` contains placeholders only.

## Known Limitations

- Real capture is disabled by default and requires a single owning worker.
- No distributed capture, endpoint agent, multi-tenancy, SSO/MFA, or centralized
  session revocation exists.
- Interface, flow, evaluation, and selected runtime histories are worker-local
  and disappear on restart.
- Metadata-flow keys are interface/protocol/direction/time-window aggregates,
  not TCP/IP five-tuples.
- No retry worker, scheduler, automatic inference, alerting, notification, or
  blocking exists.
- Fake providers are demonstration-only; real notification and firewall
  integrations require separate configuration or implementation.
- Defensive target mapping is intentionally limited.
- False positives and false negatives are possible; zero-day detection is not
  guaranteed. Local timing is not a production capacity benchmark.

## Ethics and Legal Use

Use the software only on networks you own or are authorized to monitor. Packet
capture can be legally restricted. Human review is required because blocking a
legitimate user can cause harm. Operators are responsible for privacy, retention,
recipient authorization, and protection of audit data. The software provides no
warranty of complete threat prevention.

## Troubleshooting

- Startup rejects configuration: run `flask system readiness` and correct every
  named error; never bypass production checks.
- Readiness reports migration required: back up and run the explicit migration.
- Capture will not start: verify one worker, enabled capture, approved interface,
  source permissions, and demo-only gates for `fake`.
- Mutation returns 401/403/400: sign in, verify role, reload the form for a fresh
  CSRF/action token, and submit once.
- Model unavailable: inspect authenticated AI health and registry metadata; paths
  are intentionally not exposed.

## Project Structure

`backend/` API, application factory, services; `dashboard/` server-rendered UI;
`network/` capture and metadata flows; `ai/` schemas, training, evaluation, and
inference; `alerts/`, `notifications/`, `defense/` explicit workflows;
`auth/` identity and authorization; `database/` models, repositories, migrations;
`config/` environment settings; `docs/` operational and academic documentation;
`tests/` security, unit, integration, and release verification.

## Contribution and roadmap

Local development history attributes the inspected commits to Hussein Akil. The public snapshot was selected from the current working source, including ongoing changes; it does not claim historical commits or uncommitted features are a released product. Private academic material and historical Git objects were not imported.

Priorities: make the full suite reproducible, reconcile capture privacy-contract tests, remove environment-dependent health assumptions, and evaluate improvements to minority-class precision/recall without leakage. A schema change requires a new compatible live-feature pipeline and model, not merely another benchmark score.

Source license: [MIT](LICENSE).
