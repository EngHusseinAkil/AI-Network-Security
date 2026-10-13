# Administrator Guide

## Bootstrap and Roles

Set a long random `SECRET_KEY`, database URI, trusted hosts/proxy hops, HTTPS
cookies, and strict migrations. Create the schema or explicitly migrate, then run:

```powershell
.\venv\Scripts\flask.exe --app wsgi:app users create
```

Viewer is read-only; operator performs approved workflows; admin manages users.
Use `users list`, `activate`, `deactivate`, `role`, and `reset-password`. Account
changes are audited. Final-admin protection prevents removal of the last active
administrator.

## Migrations and Backups

Run `system migration-status`, take and verify a backup, then run
`system migration-upgrade`. Startup never migrates. Downgrade is an explicit,
limited recovery operation and must be tested with the selected database engine.
Follow [Production operations](PRODUCTION_OPERATIONS.md) and
[Production operations](PRODUCTION_OPERATIONS.md). Historical local migration-verification reports are not distributed in this public snapshot.

For local SQLite, stop writes, copy the database and its migration state, open the
copy with SQLite integrity checking, and compare user, alert, delivery, action,
and audit counts. Protect backups like production data and test restoration.

## Providers and Capture

Capture is disabled by default and requires a single declared owner. Scapy needs
host-specific capture privileges. Fake capture/notification/defense require demo
gates and are rejected in production. No real firewall provider implementation is
shipped. Configure notification credentials only in the deployment environment;
never logs, source, or dashboard fields.

## Operations

- `GET /health/live`: load-balancer liveness.
- `GET /health/ready`: dependency/migration readiness.
- `flask system readiness`: deployment gate.
- Structured logs contain request IDs and safe categories, not tokens/passwords.
- Rotate secrets by scheduling session invalidation, replacing environment
  values, restarting workers, and verifying readiness. Existing signed actions
  become invalid.
- For suspected compromise, stop capture, preserve logs/database, disable affected
  accounts/providers, rotate secrets, inspect audit records, and restore only from
  a verified backup.

Repeated login failures are rate limited but there is no distributed account
lockout or centralized session revocation. Deactivate accounts deliberately and
rotate the signing secret for emergency global session invalidation.

Live interfaces, flows, evaluations, and counters are process-local and lost on
restart. Multi-worker live capture is unsupported; durable alerts, deliveries,
actions, users, and audits remain database-backed.
