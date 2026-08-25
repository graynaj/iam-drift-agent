# Findings

Observations made while building the agent, on the agent's own project.
These are real, not synthetic: no permission below was granted deliberately
for demonstration purposes.

## F-01 — Default compute service account holds roles/editor

**Observed:** 2026-08-25, project `iam-drift-agent`
**Evidence:** `baseline/finding-default-compute-editor.json`

The service account `283566602051-compute@developer.gserviceaccount.com`
holds `roles/editor` on the project. Nobody granted it. Google Cloud attaches
this binding automatically when Compute Engine and related APIs are enabled.

This is a textbook example of the drift this project targets: a broad
permission that appears without a human decision, is never reviewed, and is
invisible unless something is watching for it.

It is also directly relevant to the agent's own deployment. Cloud Run uses
this account by default. Deploying without an explicit `--service-account`
flag would have given the agent edit rights over the entire project —
including the IAM policy it is supposed to monitor. The agent runs instead
as `audit-agent-sa`, which holds only:

- `roles/iam.securityReviewer` (read IAM policies)
- `roles/datastore.user` (write findings to Firestore)
- `roles/aiplatform.user` (call Gemini)

No role in that set can modify IAM. See "Security model" in the README.

## F-02 — Baseline is required to distinguish drift from normal state

**Observed:** 2026-08-25

The project owner holds `roles/owner`. A detector that scores individual
events in isolation flags this as critical every time, which is noise: the
binding predates the agent and is expected.

Drift is defined against a reference point, not in the abstract. The initial
IAM snapshot in `baseline/iam-baseline-20260825.json` was captured before any
agent infrastructure existed, and is committed separately so the ordering is
verifiable in the git history. Bindings present in that snapshot are the
project's known state; bindings that appear afterwards are drift.

The first drift the agent should report is therefore its own service account —
created after the baseline, with three roles attached.