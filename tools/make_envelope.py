"""Wrap a saved log entry in a Pub/Sub push envelope.

python tools/make_envelope.py tests/fixtures/real-setiampolicy-add.json tests/fixtures/push-add.json
"""

import base64
import json
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
raw = json.loads(src.read_text(encoding="utf-8-sig"))
entry = raw[0] if isinstance(raw, list) else raw

envelope = {
    "message": {
        "data": base64.b64encode(json.dumps(entry).encode()).decode(),
        "messageId": f"replay-{dst.stem}",
        "attributes": {},
    },
    "subscription": "projects/iam-drift-agent/subscriptions/audit-push",
}
dst.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
print(f"{dst} <- {src} ({entry.get('insertId', '?')})")