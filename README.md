# IAM Drift Agent

Detects drift between declared and actual IAM policy in a Google Cloud project,
assesses the security impact of each change, and reports it to the right owner.

- **Hackathon:** All Things Agentic (Devpost)
- **Category:** Taskmaster
- **GCP Project ID:** `iam-drift-agent`
- **Model:** `gemini-3.7-flash` via Vertex AI

## Authentication
Uses Vertex AI with Application Default Credentials rather than Gemini API keys.
No long-lived credentials are stored in the repository or environment. On Cloud Run
the service will authenticate via its attached service account.

## Architecture
_TBD — see docs/architecture.png_

Scope decision: for now the observed project and the observing agent are the same
project. In production these should be separated, with the agent holding read-only
access to the observed project. Documented here as a deliberate choice, not an oversight.

## Setup & Run
```bash
git clone https://github.com/<user>/iam-drift-agent.git
cd iam-drift-agent
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

gcloud auth application-default login
gcloud config set project iam-drift-agent
gcloud services enable aiplatform.googleapis.com

python risk.py
```

## Open questions
- Severity assignment is non-deterministic at `temperature=0.1` (see `tests/cases.md`).
  Alert routing depends on the threshold, so this needs resolving before the agent
  can page anyone.
- Pub/Sub delivers at-least-once; `messageId` will be the deduplication key in Firestore.
-Coś w duchu: Drift is the gradual divergence between a project's actual IAM state and its intended state. Individual changes rarely look alarming; the risk accumulates. The agent tracks cha

## Deployment

The service is deployed to Cloud Run directly from source, with no Dockerfile:

```bash
gcloud run deploy iam-drift-agent \
  --source . \
  --region=europe-west1 \
  --no-allow-unauthenticated \
  --service-account=audit-agent-sa@iam-drift-agent.iam.gserviceaccount.com \
  --min-instances=0
```

Google Cloud Buildpacks detects the Python project, installs
`requirements.txt`, and reads `Procfile` for the start command:
web: gunicorn -b :$PORT main:app


`$PORT` is injected by Cloud Run at runtime. A Dockerfile would work too, but
buildpacks keep the repository smaller and remove a base image to maintain —
the container definition is one line instead of a dozen.

Two dependency files are kept deliberately:

- `requirements.txt` — runtime only (Flask, gunicorn, google-genai, pydantic)
- `requirements-dev.txt` — full local environment, including `google-adk` for
  the ADK dev UI

The ADK agent is a development and demonstration interface; the deployed
service does not need it, so it stays out of the container.

### Flags that matter

- `--no-allow-unauthenticated` — the service is a Pub/Sub receiver, not a
  public API. Only authenticated push requests reach it.
- `--service-account` — without this flag Cloud Run falls back to the default
  compute service account, which holds `roles/editor` on the project. See
  F-01 in `docs/findings.md`.
- `--min-instances=0` — the service scales to zero when idle.

## Event pipeline

The agent does not poll. Two Google Cloud sources push IAM events to the
Cloud Run service as they happen:

| Source | Topic | Endpoint | What it carries |
|---|---|---|---|
| Cloud Audit Logs (Admin Activity) | `audit-events` | `/audit` | Who changed what, and when |
| Cloud Asset Inventory feed | `asset-events` | `/asset` | Resource state before and after |

Both sources are needed. Audit logs identify the actor and the method;
the asset feed carries `priorAsset`, which is what makes before/after
comparison possible.

IAM change
├─→ Cloud Audit Logs ──→ log sink ──→ audit-events ──→ audit-push ──→ /audit
└─→ Asset Inventory ─────── feed ───→ asset-events ──→ asset-push ──→ /asset


Push subscriptions authenticate as a dedicated `pubsub-pusher` service
account; the Cloud Run service rejects unauthenticated requests.

Observed latency from IAM change to log line in Cloud Run: roughly
10–20 seconds for audit events.

### Two permissions that fail silently

Setting this up has two failure modes that produce no error anywhere —
the pipeline simply stays quiet:

- **The log sink has its own writer identity**, created with the sink and
  distinct from the caller. Without `roles/pubsub.publisher` on the topic,
  the sink drops every message without logging a failure.
- **The Pub/Sub service agent mints the OIDC tokens** used for authenticated
  push. Without `roles/iam.serviceAccountTokenCreator` at project level,
  messages are never delivered and eventually expire. A missing
  `roles/run.invoker` is easier to spot — it surfaces as 403s in the
  subscription's delivery metrics.


### Audit log scope

The sink filter is restricted to Admin Activity logs and `SetIamPolicy`:
logName:"cloudaudit.googleapis.com%2Factivity"
AND protoPayload.methodName:"SetIamPolicy"


Data Access logs are deliberately excluded — they are high volume and
billable, and they carry nothing this agent needs.