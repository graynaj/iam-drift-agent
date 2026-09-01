"""Persist drift findings in Firestore.

The document id is the finding's fingerprint, so redelivery of the same
change updates the existing document instead of creating a new one.
Pub/Sub is at-least-once, and the same change can also arrive from two
sources; the fingerprint absorbs both cases.

The fingerprint covers the resource as well as the binding, because the
same role granted to the same member at project level and on a single
service account are different changes with different blast radius.
"""

from google.cloud import firestore

COLLECTION = "findings"

_client = None


def client() -> firestore.Client:
    """Lazy singleton: one connection per container instance."""
    global _client
    if _client is None:
        _client = firestore.Client()
    return _client


def record(finding, assessment=None, actor="unknown", final_level=None,
           raised_from=None) -> tuple[bool, int]:
    """Store or update a finding. Returns (is_new, times_seen)."""
    doc = client().collection(COLLECTION).document(finding.fingerprint)
    snapshot = doc.get()

    payload = {
        "change": finding.change,
        "role": finding.role,
        "member": finding.member_raw or finding.member,
        "resource": finding.target,
        "floor": finding.floor,
        "rule": finding.rule,
        "actor": actor,
        "last_seen": firestore.SERVER_TIMESTAMP,
        "times_seen": firestore.Increment(1),
    }

    # Absent rather than null, matching how emit() filters the log line.
    revert = finding.revert_command
    if revert is not None:
        payload["revert_command"] = revert

    if assessment is not None:
        payload.update({
            "level": final_level or assessment.level,
            "reasoning": assessment.reasoning,
            "recommendation": assessment.recommendation,
        })
        if raised_from is not None:
            payload["raised_from"] = raised_from

    if snapshot.exists:
        doc.update(payload)
        seen = (snapshot.to_dict().get("times_seen") or 0) + 1
        return False, seen

    payload["first_seen"] = firestore.SERVER_TIMESTAMP
    payload["status"] = "open"
    doc.set(payload)
    return True, 1


if __name__ == "__main__":
    import json
    from pathlib import Path

    from audit import to_findings, unwrap_push

    body = json.loads(
        Path("tests/fixtures/push-add.json").read_text(encoding="utf-8-sig"))
    for f in to_findings(unwrap_push(body)):
        is_new, seen = record(f, actor="local-test")
        state = "new" if is_new else "repeat"
        print(f"{state:7} seen={seen}  {f.role} -> {f.member_raw}")
        print(f"        on {f.target}  [{f.fingerprint}]")