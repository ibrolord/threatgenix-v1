# ThreatGenix — Lessons Learned

Running log of mistakes, root causes, and what to do differently. Updated after each significant debugging or implementation session. Read this before diagnosing any new issue.

---

## Format

```
### YYYY-MM-DD — <short title>
**What happened:** <one sentence>
**Root cause:** <why it happened>
**Rule going forward:** <concrete behavior change>
```

---

## 2026-04-15 — False root cause: onPaneContextMenu wiring

**What happened:** Diagnosed that `onPaneContextMenu` was not wired into `<ReactFlow>` — it was already wired at `DFDCanvas.tsx:1077`.

**Root cause:** Could not read the file directly; formed a plausible hypothesis and stated it as a confirmed finding instead of labeling it tentative.

**Rule going forward:** Never state "X is missing/broken" without a grep or read confirmation. Label all unverified root causes as tentative. One grep before asserting.

---

## 2026-04-15 — Phantom model field: mitigation_status

**What happened:** Suggested exporting `threat.mitigation_status` in the PDF export feature. That field does not exist.

**Real fields** (`backend/app/models/threat.py:49`, `backend/app/schemas/threat.py:26`):
`status`, `mitigation_plan`, `mitigation_owner`, `due_date`, `mitigation_notes`, `closed_at`

**Root cause:** Pattern-matched from general threat model knowledge instead of checking the schema file.

**Rule going forward:** Before naming any model field in advice or code, grep the schema. No exceptions.

---

## 2026-04-15 — Over-prescribed DFD interaction fix

**What happened:** Pushed toward `onConnectEnd` / incomplete-connection handling for the DFD canvas. The correct smaller fix was: keep drag-connect on React Flow `Handle`, add visible `+` spawn buttons for branching.

**Root cause:** Defaulted to the more complete solution without checking whether the smaller path would suffice.

**Rule going forward:** For DFD canvas changes, default to the minimal safe path. Only escalate to a larger interaction refactor if the small fix provably can't solve the problem.

---

## 2026-04-15 — Mixed code fixes with operator guidance in migration advice

**What happened:** Included `alembic stamp head` as part of the migration implementation path alongside idempotent migration guards.

**Root cause:** Conflated "what the developer commits" with "what an operator runs during recovery."

**Rule going forward:** Idempotent migration guards = code fix, goes in the PR. `alembic stamp head` = operator recovery command, documented separately with an explicit warning about schema drift risk. Never put it in the implementation steps.

---

## What has worked well

- Reusing the shared triage workflow on the detail page (correct direction)
- Making migrations idempotent (correct direction)
- Keeping fixes small and avoiding large refactors as the default instinct
