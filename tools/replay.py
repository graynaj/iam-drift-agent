"""Replay a saved Pub/Sub push envelope against /audit.

Local:  python tools/replay.py http://localhost:8080/audit
Cloud:  python tools/replay.py https://iam-drift-agent-....run.app/audit --auth

Optional second argument: path to a different envelope fixture.
"""

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_FIXTURE = Path("tests/fixtures/push-add.json")


def identity_token() -> str:
    out = subprocess.run(
        ["gcloud", "auth", "print-identity-token"],
        capture_output=True, text=True, shell=True, check=True,
    )
    return out.stdout.strip()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    url = sys.argv[1]
    fixture = DEFAULT_FIXTURE
    for arg in sys.argv[2:]:
        if not arg.startswith("--"):
            fixture = Path(arg)

    body = fixture.read_bytes()
    headers = {"Content-Type": "application/json"}
    if "--auth" in sys.argv:
        headers["Authorization"] = f"Bearer {identity_token()}"

    print(f"POST {url}  <- {fixture}")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            print(f"{resp.status} {resp.read().decode() or '(empty)'}")
    except urllib.error.HTTPError as exc:
        print(f"{exc.code} {exc.read().decode()}")
    except urllib.error.URLError as exc:
        print(f"connection failed: {exc.reason}")


if __name__ == "__main__":
    main()