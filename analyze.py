"""Combine deterministic detection with LLM assessment."""

import sys
from drift import diff
from risk import assess
import logging
logging.getLogger("google_genai.models").setLevel(logging.ERROR)

LEVELS = ["low", "medium", "high", "critical"]


def analyze(before, after):
    for f in diff(before, after):
        if f.change == "revoked":
            continue
        a = assess(f.as_event())
        # Deterministic floor wins: the model may raise severity, never lower it.
        final = a.level
        if LEVELS.index(a.level) < LEVELS.index(f.floor):
            final = f.floor
            note = f" (raised from {a.level} by rule: {f.rule})"
        else:
            note = ""
        print(f"\n[{final.upper()}]{note} {f.role}")
        print(f"  {f.member}")
        print(f"  {a.reasoning}")
        print(f"  → {a.recommendation}")


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])