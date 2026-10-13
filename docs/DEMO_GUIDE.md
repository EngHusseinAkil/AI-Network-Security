# Deterministic Demo Guide

This workflow is local and synthetic. It preserves authentication, permissions,
CSRF, explicit actions, and audit. It performs no real capture, external request,
or OS/firewall change. Production rejects demo mode and fake providers.

## Configure

Use a disposable local SQLite database and PowerShell session:

```powershell
$env:APP_ENV = "development"
$env:DEMO_MODE = "true"
$env:SECRET_KEY = "replace-with-a-long-random-demo-only-value"
$env:DATABASE_URI = "sqlite:///data/demo.db"
$env:CAPTURE_ENABLED = "true"
$env:CAPTURE_SOURCE = "fake"
$env:CAPTURE_DEMO_ENABLED = "true"
$env:ALERT_NOTIFICATIONS_ENABLED = "true"
$env:ALERT_NOTIFICATION_PROVIDER = "fake"
$env:ALERT_NOTIFICATION_DEMO_ENABLED = "true"
$env:DEFENSIVE_ACTIONS_ENABLED = "true"
$env:DEFENSIVE_ACTION_PROVIDER = "fake"
$env:DEFENSIVE_ACTION_DEMO_ENABLED = "true"
```

Delete only the disposable `data/demo.db` between demonstrations, then recreate
it. There is deliberately no public reset endpoint.

## Initialize

```powershell
.\venv\Scripts\flask.exe --app wsgi:app system schema-create
.\venv\Scripts\flask.exe --app wsgi:app users create
.\venv\Scripts\flask.exe --app wsgi:app demo seed
.\venv\Scripts\flask.exe --app wsgi:app demo model
.\venv\Scripts\flask.exe --app wsgi:app run
```

Choose the `admin` role when prompted and supply your own password. The seed
command asks for confirmation, creates deterministic sample records, is
idempotent where records already exist, and never creates a user or credential.
The model command validates the eight-row sample, trains the existing
deterministic Random Forest baseline, securely persists and activates
`demo-1.0.0`, and performs one smoke inference. It refuses production and
existing versions. Because rare classes cannot support a representative
stratified holdout, it creates no `evaluation.json` and makes no accuracy claim.

## Walkthrough

1. Open `/login`; confirm the visible `DEMO MODE` label and sign in.
2. Open Monitoring and explicitly refresh interfaces. A demo-safe opaque
   interface appears; no native adapter identifier is rendered.
3. Start fake capture. The fake source emits deterministic metadata only.
4. Stop capture explicitly, or let the configured packet/duration bound complete.
5. Select Process metadata. Expect a bounded batch count and completed flows.
6. Select Evaluate completed flows. Expect immutable evaluation summaries.
7. Inspect one recommendation. It is labeled advisory and is not an alert.
8. Create the alert explicitly. Replaying the same recommendation resolves to the
   existing durable alert rather than duplicating it.
9. On alert detail, explicitly request a fake notification. Expect a durable fake
   delivery outcome and no network request.
10. Confirm and apply a fake temporary deny. Expect a durable active action and
    no OS/firewall command.
11. Remove the fake deny explicitly. Expect the action to show removed.
12. Inspect alert history and the security audit views/records for actor, action,
    outcome, and request correlation.
13. Check `/health/live`, `/health/ready`, and `flask system readiness`.
14. Verify there are no packet files, external delivery, firewall changes,
    background workers, or automatically created downstream actions.

Exact recommendation content depends on the active approved model. If no model
artifact is active, inference fails safely; this is an honest demonstration of
the availability boundary, not a reason to install an unevaluated model.
