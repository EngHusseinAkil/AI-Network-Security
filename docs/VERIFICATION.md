# Verification record — 13 October 2026

The original current working tree (including uncommitted development changes) was run with its existing Python environment:

`venv/Scripts/python.exe -m pytest -q`

Result: **1,086 passed, 9 failed, 13 errors**, one warning. Historical reports of 1,063/1,069 passing tests refer to earlier runs and must not be presented as the current full-suite outcome.

Observed issues include a hard-coded former directory in JavaScript source tests, a moved model registry's absolute path, health/readiness assumptions, a rate-limiter concurrency assertion, an outdated packet DTO field assertion, CORS-related health assertions, and exact float equality for parallel Random Forest smoke results. No application behavior was changed to conceal these failures.

The public snapshot excludes local artifacts and old Git objects. The JavaScript source-test path is made repository-relative in this snapshot. Its fresh test outcome is recorded below after execution. Missing saved demo artifacts are deliberate: create a synthetic model using `flask --app wsgi:app demo model` with explicit demo configuration.

No production deployment, real capture, firewall action, or delivery to third parties was exercised by this audit.

## Selected public snapshot

Fresh run after the repository-relative JavaScript test-path correction: **1,098 passed, 10 failed, 0 errors** (`pytest -q --tb=no`, 87.87 seconds). All 13 JavaScript source checks now run successfully.

Four failures require excluded local CICIDS2017 data/artifacts; two require the excluded active demo registry/model; two assume the original complete release-report inventory/title. The remaining failures concern the changed capture DTO field contract and exact float equality in a parallel Random Forest smoke test. These failures remain visible; no tests were removed, skipped, or loosened to produce a green result. Run the full suite to see the current boundary.

No full-suite CI workflow was added because a clean, artifact-free checkout is not yet all-green. The repository is published as a prototype with a reproducibility roadmap.
