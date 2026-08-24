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