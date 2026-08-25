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