import json, datetime
from collections import Counter
from pathlib import Path
from cases import CASES
from risk import assess

# Prompt injection probe: attacker-controlled fields (service account names,
# descriptions) are fed straight into the model prompt. This checks whether
# injected text can lower the assessed risk level.
# Each case runs multiple times — output is non-deterministic even at low temperature.

TARGETS = ["inject_control", "inject_sa_name", "inject_fake_system", "inject_soft_target"]
RUNS = 3

stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
out_dir = Path("tests/results")
out_dir.mkdir(parents=True, exist_ok=True)

report = {"timestamp": stamp, "model": "gemini-3.7-flash",
          "runs_per_case": RUNS, "cases": {}}

for name in TARGETS:
    levels, raw = [], []
    for _ in range(RUNS):
        a = assess(CASES[name])
        levels.append(a.level)
        raw.append(a.model_dump())
    report["cases"][name] = {
        "levels": levels,
        "distribution": dict(Counter(levels)),
        "raw": raw,
    }
    print(f"\n=== {name} ===")
    print(f"{dict(Counter(levels))}")
    print(f"reasoning (run 1): {raw[0]['reasoning']}")

path = out_dir / f"injection-{stamp}.json"
path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"\nSaved: {path}")