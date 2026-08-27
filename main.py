"""Cloud Run receiver for IAM audit and asset events.

/audit runs deterministic drift detection, then asks the model to assess
each finding. The rule-based floor wins: the model may raise severity,
never lower it. Findings are persisted in Firestore keyed by fingerprint,
so redelivery updates a counter instead of creating a duplicate.
"""

import base64
import json
import logging

from flask import Flask, request

from audit import actor, to_findings
from risk import assess
from store import record

logging.getLogger("google_genai.models").setLevel(logging.ERROR)

app = Flask(__name__)

LEVELS = ["low", "medium", "high", "critical"]
MAX_ASSESSMENTS = 5  # stay inside the push ack deadline


def unwrap(envelope):
    """Unwrap a Pub/Sub push envelope. Returns (message_id, payload)."""
    if not envelope or "message" not in envelope:
        return None, None
    msg = envelope["message"]
    raw = base64.b64decode(msg.get("data", "")).decode("utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"_raw": raw}
    return msg.get("messageId"), payload


def emit(severity, message, **fields):
    """Cloud Run turns JSON on stdout into structured log entries."""
    print(json.dumps({"severity": severity, "message": message, **fields}),
          flush=True)


@app.post("/audit")
def audit():
    envelope = request.get_json(silent=True)
    msg_id, payload = unwrap(envelope)

    if msg_id is None:
        emit("INFO", "bad or empty envelope")
        return ("", 204)

    try:
        who = actor(payload)
        insert_id = payload.get("insertId", "unknown")
        findings = to_findings(payload)

        if not findings:
            emit("INFO", "no drift in event", msg_id=msg_id,
                 insertId=insert_id, actor=who,
                 method=payload.get("protoPayload", {}).get("methodName"))
            return ("", 204)

        for f in findings[:MAX_ASSESSMENTS]:
            if f.change == "revoked":
                is_new, seen = record(f, actor=who)
                emit("INFO", "permission revoked", role=f.role,
                     member=f.member_raw, actor=who,
                     fingerprint=f.fingerprint, msg_id=msg_id,
                     is_new=is_new, times_seen=seen)
                continue

            a = assess(f.as_event())
            final, raised = a.level, None
            if LEVELS.index(a.level) < LEVELS.index(f.floor):
                final, raised = f.floor, a.level

            is_new, seen = record(f, assessment=a, actor=who,
                                  final_level=final, raised_from=raised)

            emit("WARNING" if final in ("high", "critical") else "NOTICE",
                 f"IAM DRIFT [{final.upper()}] {f.role} -> {f.member_raw}",
                 level=final, floor=f.floor, rule=f.rule, raised_from=raised,
                 role=f.role, member=f.member_raw, actor=who,
                 reasoning=a.reasoning, recommendation=a.recommendation,
                 fingerprint=f.fingerprint, insertId=insert_id, msg_id=msg_id,
                 is_new=is_new, times_seen=seen)

        return ("", 204)

    except Exception as exc:
        # Never 500 here: a non-2xx makes Pub/Sub redeliver, and at-least-once
        # turns one parser bug into an unbounded retry loop against the model.
        emit("ERROR", "audit handler failed", error=repr(exc), msg_id=msg_id)
        return ("", 204)


@app.post("/asset")
def asset():
    msg_id, payload = unwrap(request.get_json(silent=True))
    if msg_id is None:
        return ("bad envelope", 400)
    asset = payload.get("asset") or payload.get("priorAsset") or {}
    print(json.dumps({
        "source": "asset",
        "msg_id": msg_id,
        "name": asset.get("name"),
        "type": asset.get("assetType"),
        "has_prior": bool(payload.get("priorAsset")),
    }), flush=True)
    return ("", 204)


@app.get("/healthz")
def healthz():
    return ("ok", 200)