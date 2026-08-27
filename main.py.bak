"""Cloud Run receiver for IAM audit and asset events."""

import base64
import json
from flask import Flask, request

app = Flask(__name__)


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


@app.post("/audit")
def audit():
    msg_id, payload = unwrap(request.get_json(silent=True))
    if msg_id is None:
        return ("bad envelope", 400)
    p = payload.get("protoPayload", {})
    print(json.dumps({
        "source": "audit",
        "msg_id": msg_id,
        "actor": p.get("authenticationInfo", {}).get("principalEmail"),
        "method": p.get("methodName"),
        "service": p.get("serviceName"),
        "resource": p.get("resourceName"),
        "timestamp": payload.get("timestamp"),
    }), flush=True)
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