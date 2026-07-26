# Managed Validation Runner Readiness

This runbook is the production gate for ThreatGenix hosted SaaS validation.
The API is the control plane. Scanner execution belongs only in the managed
worker process or in self-hosted deployments.

## Success Path

1. Deploy API and worker from the same image.
2. Run migrations to the current Alembic head.
3. Keep API processes in the default execution context.
4. Run the worker with:
   - `THREATGENIX_VALIDATION_RUNTIME_MODE=managed`
   - `THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED=true`
   - `THREATGENIX_VALIDATION_EXECUTION_CONTEXT=worker`
   - `THREATGENIX_VALIDATION_SANDBOX_MODE=process` only for no-network tools
     running on a dedicated private worker VM, or `container` for tools that
     need target/advisory egress
   - `THREATGENIX_VALIDATION_ALLOWED_PATHS` scoped to mounted tenant artifacts
5. Verify `GET /api/health?deep=true` returns `status=ok`, `database=connected`,
   and a fresh validation runner heartbeat.
6. Run the production-safe smoke gate:

```bash
cd /path/to/threatgenix-v1/backend
./.venv/bin/python scripts/production_saas_smoke.py \
  --base-url https://threatgenix.vercel.app \
  --threat-model-id 00000000-0000-0000-0000-000000000010 \
  --heartbeat-proof \
  --expected-source-version "$(git rev-parse HEAD)"
```

For the read-only authenticated Validation Lab API check, provide a short-lived
tenant token from an approved source:

```bash
THREATGENIX_PROD_E2E_TOKEN="<approved-token>" \
./.venv/bin/python scripts/production_saas_smoke.py
```

If no approved short-lived tenant token is available, run the synthetic
authenticated smoke instead. It creates a disposable tenant/model, verifies the
authenticated Validation Lab API, saves/lists/deletes a dummy BYOK key without
calling the provider, and sends one synthetic Ask AI/copilot prompt:

```bash
./.venv/bin/python scripts/production_saas_smoke.py \
  --heartbeat-proof \
  --synthetic-auth \
  --synthetic-assistant \
  --expected-source-version "$(git rev-parse HEAD)"
```

To prove the managed worker can execute no-network scanners from hosted SaaS
artifact staging, add the upload proof flag. It uploads a synthetic zip bundle,
queues scanner jobs against the returned hosted `tgx-target://` reference, and
verifies egress-requiring tools fail closed:

```bash
./.venv/bin/python scripts/production_saas_smoke.py \
  --heartbeat-proof \
  --synthetic-auth \
  --synthetic-assistant \
  --synthetic-validation-upload \
  --expected-source-version "$(git rev-parse HEAD)"
```

The default smoke gate must not submit a scanner run, upload a bundle, or send
customer data. The scanner proof is explicit and must use a synthetic fixture
only. The gate checks health, auth rejection for anonymous API access, the SPA
route, optional authenticated Validation Lab summary, optional live AI smoke,
and optional no-network scanner execution.

## Failure Conditions

- API starts with a stale Alembic revision or missing runner columns.
- Deep health reports no active worker while managed runner mode is enabled.
- Deep health does not report the expected Alembic revision.
- Deep health does not report the expected source version.
- The managed runner heartbeat does not advance across the heartbeat proof.
- Anonymous `/api/auth/me` returns anything other than `401` or `403`.
- Validation Lab route fails to return the app shell.
- Process sandbox advisory-DB egress is enabled in production or staging.
- A validation archive contains duplicate member paths.
- Nuclei, OSV, or any egress-requiring tool is enabled without a per-scan
  isolated network policy.

## Tool Execution Rules

- Nuclei URL scans require explicit authorization, target safety checks, and an
  egress-isolated runner in hosted SaaS.
- Semgrep, Trivy, Checkov, and TruffleHog should run with no network.
- OSV Scanner requires advisory database egress and must use an isolated
  container network in production.
- The process runner may use `THREATGENIX_VALIDATION_PROCESS_ADVISORY_DB_NETWORK`
  only for local development proof. Production and staging ignore that opt-in.
- Runner output must stay below each tool policy cap and execution artifacts
  must store redacted command metadata only.

## Customer Journey QA Checklist

- Register creates a tenant organization and does not expose verification or
  reset tokens in production.
- Login and `/api/auth/me` enforce active user, active organization, and email
  verification policy.
- Threat model routes deny cross-tenant collaborator JSON matches.
- DFD node binding rejects target nodes from another threat model.
- Validation Lab shows runner mode, tool readiness, evidence count, binding
  status, and clear blocked reasons.
- Try Sandbox and artifact bundle import remain available without live scanner
  execution.
- Managed-runner live submissions queue work but API processes never execute
  scanner binaries inline.
- Evidence bound to DFD nodes remaps semantic threat status and leaves unmatched
  findings visible as unbound evidence.

## Rollback

If the worker degrades after deploy:

1. Confirm `GET /api/health?deep=true`.
2. Stop the worker machine or disable submissions with
   `THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED=false`.
3. Keep Try Sandbox and artifact import available for demos.
4. Inspect failed `scan_jobs.failure_code`, `scan_execution_artifacts`, and
   `validation_worker_heartbeats`.
5. Re-enable managed submissions only after a fresh heartbeat and zero stale
   running jobs.
