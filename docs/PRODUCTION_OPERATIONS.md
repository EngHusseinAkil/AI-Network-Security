# Production Operations

## Deployment Boundary

Production uses `wsgi:app` behind Gunicorn and HTTPS termination. Set
`APP_ENV=production`, inject secrets from a protected environment or external
secret manager, configure an explicit database URL and trusted hosts, and keep
debug disabled. `TRUSTED_PROXY_HOPS` must equal the number of controlled reverse
proxy hops; forwarded headers are ignored when it is zero.

Run migrations as a separate, backed-up deployment step. Web-worker startup
never creates schema, users, capture workers, evaluations, alerts,
notifications, or defensive actions. Inspect state with:

```text
flask system migration-status
flask system readiness
flask system schema-create
flask system migration-upgrade
flask system migration-downgrade
```

Provision the first administrator through `flask users create`; never place its
password on the command line. For an empty database, run the confirmation-gated
`schema-create` once before provisioning. Existing deployments use the
backup-gated migration commands instead.

## Runtime State

| Component | Classification |
| --- | --- |
| Users, audit, alerts, notification deliveries, defensive actions | Database shared |
| Durable action idempotency | Database uniqueness and transactions |
| Signed session | Client cookie; role and active state reloaded from database |
| Interface discovery keys | Worker-local, expiring |
| Capture lifecycle and metadata queue | Single-owner process only |
| Flow aggregation | Worker-local, reconstructable, not recoverable |
| Evaluation reservations and history | Worker-local, reconstructable |
| HTTP rate limits | Worker-local; durable account lockout remains shared |

Live capture is disabled by default and rejected when `WEB_WORKER_COUNT != 1`.
Use a designated single-owner process or documented single-worker deployment.
Flow and evaluation controls do not provide cross-worker unified history.

## Health And Shutdown

`GET /health/live` is a public, write-free process check. `GET /health/ready`
checks safe configuration, database connectivity, inferred schema revision, and
runtime compatibility without provider calls or mutations.

Gunicorn invokes the idempotent shutdown coordinator on worker exit. It requests
bounded capture shutdown, closes providers, and disposes an existing database
engine. Flask's development server does not guarantee production-grade signal
handling.

## Migration, Backup, And Recovery

Before every migration, stop mutation traffic and create a database-native
consistent backup containing users, audit events, alerts, notification
deliveries, defensive actions, and schema metadata. Record the application
commit and migration revision. Restore into an isolated database, run
`flask system migration-status`, then run application readiness.

For rollback, stop workers, restore the verified backup or execute a supported
downgrade, deploy the matching commit, and verify liveness, readiness, login,
and representative reads before reopening traffic. Rotating `SECRET_KEY`
intentionally logs everyone out because sessions and signed action tokens
become invalid.

Back up configuration and secret-manager definitions separately. Capture
queues, interface keys, flow aggregation, evaluation history, and process-local
rate-limit buckets cannot be recovered.

`requirements.txt` is the pinned reproducible environment used by this
repository and currently includes both runtime and test tooling. Production
images install it during image construction only; they never install packages
at container startup.

## Incident Response

Preserve the database and protected structured logs. Disable capture/providers
when containment requires it and retain append-only audit data. No notification
retry, capture, evaluation, alert creation, or blocking runs automatically
during recovery.
