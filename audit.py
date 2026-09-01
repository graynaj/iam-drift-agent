"""Parse Cloud Audit Log SetIamPolicy entries into drift findings.

Rule-based only. No model call happens here.
"""

import base64
import json
from pathlib import Path

from drift import DriftFinding, load_bindings, normalize_member, severity_floor

BASELINE = Path(__file__).parent / "baseline" / "iam-baseline-20260825.json"
GRANT_ACTIONS = {"ADD"}
REVOKE_ACTIONS = {"REMOVE"}

_baseline_pairs = None


def baseline_pairs() -> set[tuple[str, str]]:
    """Load once. Ships with the image, so it is read from disk not IAM."""
    global _baseline_pairs
    if _baseline_pairs is None:
        _baseline_pairs = load_bindings(BASELINE) if BASELINE.exists() else set()
    return _baseline_pairs


def unwrap_push(body: dict) -> dict:
    """Pub/Sub push envelope -> the log entry it carries. {} if empty."""
    data = (body.get("message") or {}).get("data")
    if not data:
        return {}
    return json.loads(base64.b64decode(data).decode("utf-8"))


def binding_deltas(entry: dict) -> list[dict]:
    """Delta lives under serviceData on older events, metadata on newer ones."""
    payload = entry.get("protoPayload") or {}
    for container in (payload.get("serviceData"), payload.get("metadata")):
        if not container:
            continue
        deltas = (container.get("policyDelta") or {}).get("bindingDeltas")
        if deltas:
            return deltas
    return []


def actor(entry: dict) -> str:
    payload = entry.get("protoPayload") or {}
    return (payload.get("authenticationInfo") or {}).get("principalEmail", "unknown")


def resource_name(entry: dict) -> str:
    """Fully-qualified resource whose policy changed.

    resourceName is authoritative, but for service accounts it uses the
    placeholder form projects/-/serviceAccounts/<numeric-id>: no project,
    no email, unusable in a command. In that case request.resource carries
    the readable path, so fall back to it.
    """
    payload = entry.get("protoPayload") or {}
    name = payload.get("resourceName", "") or ""
    if "/-/" in name:
        request = payload.get("request") or {}
        readable = request.get("resource")
        if isinstance(readable, str) and readable:
            return readable
    return name


def is_iam_change(entry: dict) -> bool:
    """Match SetIamPolicy across services.

    Resource Manager logs it as "SetIamPolicy"; IAM logs the same operation
    as "google.iam.admin.v1.SetIAMPolicy", with different capitalisation.
    The Cloud Logging sink filter survives this because its ":" operator is
    case-insensitive. Python is not, so compare in lower case.
    """
    payload = entry.get("protoPayload") or {}
    return payload.get("methodName", "").lower().endswith("setiampolicy")


def to_findings(entry: dict) -> list[DriftFinding]:
    """One audit event -> zero or more findings. Never raises on odd shapes."""
    if not is_iam_change(entry):
        return []

    known = baseline_pairs()
    resource = resource_name(entry)
    findings = []
    for delta in binding_deltas(entry):
        action = (delta.get("action") or "").upper()
        role = delta.get("role") or ""
        raw = delta.get("member") or ""
        member = normalize_member(raw)
        if not role or not member:
            continue

        if action in GRANT_ACTIONS:
            if (role, member) in known:
                continue  # in baseline: known state, not drift
            floor, rule = severity_floor(role, member)
            findings.append(
                DriftFinding("granted", role, member, floor, rule, raw, resource)
            )
        elif action in REVOKE_ACTIONS:
            findings.append(
                DriftFinding("revoked", role, member, "low", "none", raw, resource)
            )
    return findings


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/push-envelope.json"
    body = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    entry = unwrap_push(body) if "message" in body else (body[0] if isinstance(body, list) else body)

    print(f"actor: {actor(entry)}")
    print(f"iam change: {is_iam_change(entry)}")
    print(f"resource: {resource_name(entry)}")
    print(f"raw deltas: {len(binding_deltas(entry))}")
    for f in to_findings(entry):
        print(f"  [{f.floor:8}] {f.change} {f.role} -> {f.member_raw} ({f.rule})")
        if f.revert_command:
            print(f"           revert: {f.revert_command}")