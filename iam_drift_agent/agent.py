"""ADK agent wrapping the IAM risk assessment tool."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from google.adk.agents import Agent
from risk import assess


def assess_iam_change(event: str) -> dict:
    """Assess the security risk of a single Google Cloud IAM policy change.

    Args:
        event: Raw IAM change event text, including principal, method,
            resource, the change itself, and timestamp.

    Returns:
        A dict with keys: level, reasoning, likely_intentional,
        blast_radius, recommendation.
    """
    return assess(event).model_dump()


root_agent = Agent(
    name="iam_drift_agent",
    model="gemini-3.7-flash",
    description="Analyses Google Cloud IAM policy changes for security drift.",
    instruction=(
        "You help a security engineer investigate IAM policy changes. "
        "When given an IAM change event, call assess_iam_change and present "
        "the result clearly. Never assess risk yourself — always use the tool."
    ),
    tools=[assess_iam_change],
)