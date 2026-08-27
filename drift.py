"""Deterministic IAM drift detection.

Detection is rule-based and never calls a model. The LLM assesses
deviations that this module has already found.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}
ESCALATION_ROLES = {
    "roles/iam.securityadmin",
    "roles/resourcemanager.projectiamadmin",
    "roles/iam.serviceaccounttokencreator",
    "roles/iam.serviceaccountuser",
}


def normalize_member(member: str) -> str:
    """IAM member identifiers are case-insensitive; normalize for comparison."""
    return member.strip().lower()


def load_bindings(source) -> set[tuple[str, str]]:
    """Accept either gcloud policy format, return {(role, member)}.

    Handles both `get-iam-policy` (dict with 'bindings') and
    `search-all-iam-policies` (list of resources, each with 'policy').
    """
    if isinstance(source, (str, Path)):
        source = json.loads(Path(source).read_text(encoding="utf-8"))

    policies = []
    if isinstance(source, dict) and "bindings" in source:
        policies.append(source)
    elif isinstance(source, list):
        for entry in source:
            if "policy" in entry:
                policies.append(entry["policy"])
            elif "bindings" in entry:
                policies.append(entry)
    else:
        raise ValueError("Unrecognised IAM policy format")

    pairs = set()
    for policy in policies:
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            for member in binding.get("members", []):
                pairs.add((role, normalize_member(member)))
    return pairs


@dataclass(frozen=True)
class DriftFinding:
    change: str                # "granted" or "revoked"
    role: str
    member: str                # normalized: comparisons and fingerprint
    floor: str                 # deterministic minimum severity
    rule: str                  # which rule set the floor, or "none"
    member_raw: str = ""       # original spelling: display and commands

    @property
    def fingerprint(self) -> str:
        """Stable id for deduplication across repeated deliveries."""
        raw = f"{self.change}|{self.role}|{self.member}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def as_event(self) -> str:
        """Render for the LLM assessment prompt."""
        return (
            f"change: {self.change} {self.role} to {self.member}\n"
            f"resource: projects/iam-drift-agent\n"
            f"deterministic_floor: {self.floor} ({self.rule})"
        )


def severity_floor(role: str, member: str) -> tuple[str, str]:
    """Hard rules the model cannot override. Returns (floor, rule_name)."""
    if member.split(":")[-1] in PUBLIC_MEMBERS:
        return "critical", "public-principal"
    if role.lower() in PRIMITIVE_ROLES:
        return "high", "primitive-role"
    if role.lower() in ESCALATION_ROLES:
        return "high", "privilege-escalation-path"
    return "low", "none"


def diff(before, after) -> list[DriftFinding]:
    """Compare two IAM policy snapshots."""
    b, a = load_bindings(before), load_bindings(after)
    findings = []
    for role, member in sorted(a - b):
        floor, rule = severity_floor(role, member)
        findings.append(DriftFinding("granted", role, member, floor, rule))
    for role, member in sorted(b - a):
        findings.append(DriftFinding("revoked", role, member, "low", "none"))
    return findings


if __name__ == "__main__":
    import sys

    before, after = sys.argv[1], sys.argv[2]
    results = diff(before, after)
    print(f"{len(results)} change(s) against baseline\n")
    for f in results:
        mark = "+" if f.change == "granted" else "-"
        print(f"{mark} [{f.floor:8}] {f.role}")
        print(f"             {f.member}  ({f.rule}, {f.fingerprint})")