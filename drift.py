"""Deterministic IAM drift detection.

Detection is rule-based and never calls a model. The LLM assesses
deviations that this module has already found. The revert command is
generated from the finding itself, never from model output: the agent
must not gain a write path through the operator's clipboard.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ID = (
    os.environ.get("PROJECT_ID")
    or os.environ.get("GOOGLE_CLOUD_PROJECT")
    or "iam-drift-agent"
)

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
    resource: str = ""         # resource whose policy changed; "" = project

    @property
    def target(self) -> str:
        """Resource whose policy changed.

        The same role and member can be granted at project level and on a
        single service account. Those are different changes with different
        blast radius, so the resource has to travel with the finding.
        Empty means project level, which is what findings built from
        policy snapshots carry.
        """
        return self.resource or f"projects/{PROJECT_ID}"

    @property
    def fingerprint(self) -> str:
        """Stable id for deduplication across repeated deliveries."""
        raw = f"{self.change}|{self.role}|{self.member}|{self.target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def revert_command(self) -> str | None:
        """Undo line for a grant, or None when no safe command exists.

        Built only from fields of this finding. Model output is never an
        input here, so the assessment cannot influence what a human runs.
        Revocations return None so the field stays absent from the log
        rather than appearing as an empty value.

        Determinism guarantees repeatability, not correctness: the command
        must match the resource the binding actually sits on. For resource
        types this function does not know how to revert, it returns None.
        An operator running nothing is better off than an operator running
        a confident command aimed at the wrong resource.
        """
        if self.change != "granted":
            return None

        member = self.member_raw or self.member
        parts = self.target.split("/")

        if len(parts) == 4 and parts[0] == "projects" and parts[2] == "serviceAccounts":
            project, account = parts[1], parts[3]
            if project == "-" or "@" not in account:
                return None  # placeholder form: no usable command
            return (
                f"gcloud iam service-accounts remove-iam-policy-binding {account} "
                f'--member="{member}" --role="{self.role}" --project={project}'
            )

        if len(parts) == 2 and parts[0] == "projects" and parts[1] != "-":
            return (
                f"gcloud projects remove-iam-policy-binding {parts[1]} "
                f'--member="{member}" --role="{self.role}"'
            )

        return None

    def as_event(self) -> str:
        """Render for the LLM assessment prompt."""
        return (
            f"change: {self.change} {self.role} to {self.member}\n"
            f"resource: {self.target}\n"
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


def _self_check() -> None:
    """Offline check of revert command generation. No cloud, no model."""
    granted = DriftFinding(
        "granted", "roles/iam.securityAdmin",
        "user:grazynajunska@gmail.com", "high", "privilege-escalation-path",
        "user:GrazynaJunska@gmail.com",
    )
    legacy = DriftFinding(
        "granted", "roles/browser", "user:someone@example.com", "low", "none",
    )
    revoked = DriftFinding(
        "revoked", "roles/browser", "user:someone@example.com", "low", "none",
    )
    sa_level = DriftFinding(
        "granted", "roles/iam.serviceAccountTokenCreator",
        "serviceaccount:service-283566602051@gcp-sa-pubsub.iam.gserviceaccount.com",
        "high", "privilege-escalation-path",
        "serviceAccount:service-283566602051@gcp-sa-pubsub.iam.gserviceaccount.com",
        "projects/iam-drift-agent/serviceAccounts/pubsub-pusher@iam-drift-agent.iam.gserviceaccount.com",
    )
    placeholder = DriftFinding(
        "granted", "roles/iam.serviceAccountTokenCreator",
        "serviceaccount:someone@example.com", "high", "privilege-escalation-path",
        "serviceAccount:someone@example.com",
        "projects/-/serviceAccounts/114250812770448954199",
    )
    unknown = DriftFinding(
        "granted", "roles/storage.objectViewer", "allusers", "critical",
        "public-principal", "allUsers", "buckets/some-public-bucket",
    )

    print(f"project: {PROJECT_ID}\n")
    print("granted at project level (with member_raw):")
    print(f"  {granted.revert_command}\n")
    print("granted (no member_raw, older finding):")
    print(f"  {legacy.revert_command}\n")
    print("granted on a service account:")
    print(f"  {sa_level.revert_command}\n")
    print("revoked (must be None):")
    print(f"  {revoked.revert_command}\n")
    print("placeholder resource, no usable command (must be None):")
    print(f"  {placeholder.revert_command}\n")
    print("unsupported resource type (must be None):")
    print(f"  {unknown.revert_command}\n")

    assert granted.revert_command.count("\n") == 0, "must be a single line"
    assert "GrazynaJunska" in granted.revert_command, "must use original case"
    assert legacy.revert_command is not None, "must fall back to member"
    assert revoked.revert_command is None, "revocations have no revert"

    assert sa_level.revert_command is not None, "service accounts must revert"
    assert "iam service-accounts" in sa_level.revert_command, "wrong gcloud surface"
    assert "pubsub-pusher@" in sa_level.revert_command, "must target the account"
    assert sa_level.revert_command.count("\n") == 0, "must be a single line"

    assert placeholder.revert_command is None, "no command from a placeholder id"
    assert unknown.revert_command is None, "no command for unknown resource types"

    assert granted.fingerprint != sa_level.fingerprint, "resource must separate"
    same_binding_project = DriftFinding(
        "granted", "roles/iam.serviceAccountTokenCreator",
        "serviceaccount:service-283566602051@gcp-sa-pubsub.iam.gserviceaccount.com",
        "high", "privilege-escalation-path",
    )
    assert same_binding_project.fingerprint != sa_level.fingerprint, (
        "project-wide and account-level grants must not collide"
    )

    print("OK")


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 1:
        _self_check()
        raise SystemExit(0)

    before, after = sys.argv[1], sys.argv[2]
    results = diff(before, after)
    print(f"{len(results)} change(s) against baseline\n")
    for f in results:
        mark = "+" if f.change == "granted" else "-"
        print(f"{mark} [{f.floor:8}] {f.role}")
        print(f"             {f.member}  ({f.rule}, {f.fingerprint})")
        print(f"             on {f.target}")
        if f.revert_command:
            print(f"             revert: {f.revert_command}")