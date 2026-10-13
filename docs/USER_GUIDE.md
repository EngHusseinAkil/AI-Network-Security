# User Guide

## Roles and Sign-In

Open `/login` and use an administrator-provisioned account. There are no default
credentials. Viewer can inspect; operator can run approved monitoring and alert
workflows; admin can also administer users. Sign out when finished.

## Monitoring Workflow

1. **Overview and health:** inspect service state and warnings. Health/status GETs
   do not drain queues, evaluate flows, or create side effects.
2. **Capture:** refresh interfaces, choose the approved opaque key, start, then
   stop. Real capture may require host permission. Demo capture is clearly
   labeled and synthetic.
3. **Simulation:** run the bounded simulation separately from capture. Reports
   describe simulated cycles, not observed attacks.
4. **Process:** explicitly drain a server-bounded metadata batch into completed
   protocol-window aggregates. These are not endpoint five-tuples.
5. **Evaluate:** explicitly score completed compatible flows. A score and policy
   result are recommendations requiring human review.
6. **Alert:** inspect the recommendation, then create an alert explicitly.
7. **Lifecycle:** acknowledge, resolve, or dismiss through the confirmation view.
8. **Notification:** explicitly send through the configured provider. A fake
   result means only that the demo provider recorded the request.
9. **Defensive action:** confirm a bounded temporary deny, inspect its status,
   and remove it explicitly. The repository's fake provider changes no firewall.
10. **History/reports/audit:** review monitoring history and safe JSON/CSV
    reports. Security audit records are administrator operational evidence.

## Safety and Common Errors

- `401`: sign in. `403`: your role is not permitted. `400`: reload the form for
  fresh CSRF/action state. `409`: an idempotent or concurrent operation already
  exists. `503`: a model, provider, capture source, or dependency is unavailable.
- Never treat an AI result as proof. Validate context before alerting or denying.
- Stop capture when no longer needed. Use only authorized interfaces/networks.
- Report CSV cells are sanitized, but review files before opening in spreadsheets.
- Demo labels mean synthetic/fake behavior; real capture is never silently used.
