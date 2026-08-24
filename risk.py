import os
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
os.environ["GOOGLE_CLOUD_PROJECT"] = "iam-drift-agent"
os.environ["GOOGLE_CLOUD_LOCATION"] = "global"

from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import Literal

MODEL = "gemini-3.7-flash"

SYSTEM_PROMPT = """You are a Google Cloud IAM security analyst.
You assess single IAM policy changes for risk.

Guidance:
- Grants of primitive roles (owner, editor) are almost always high or critical.
- allUsers or allAuthenticatedUsers as a member is critical regardless of role.
- Service accounts granted broad admin roles are high risk.
- Read-only roles granted to internal users are usually low.
- Removals of permissions are rarely risky, but note if they break least privilege monitoring.
- A change made by a CI/CD service account during business hours is more likely intentional
  than the same change made by a personal account at 3am.

Be specific. Never invent details that are not in the event."""


class RiskAssessment(BaseModel):
    level: Literal["low", "medium", "high", "critical"]
    reasoning: str = Field(description="Two sentences explaining the level")
    likely_intentional: bool = Field(description="Does this look like a planned change")
    blast_radius: str = Field(description="What an attacker could do with this, one sentence")
    recommendation: str = Field(description="One concrete action for the owner")


client = genai.Client()


def assess(event: str) -> RiskAssessment:
    r = client.models.generate_content(
        model=MODEL,
        contents=f"Assess this IAM change:\n\n{event}",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            response_schema=RiskAssessment,
            temperature=0.1,
        ),
    )
    return RiskAssessment.model_validate_json(r.text)


if __name__ == "__main__":
    from cases import CASES
    for name, event in CASES.items():
        a = assess(event)
        print(f"\n=== {name} ===")
        print(f"{a.level.upper()} | intentional: {a.likely_intentional}")
        print(a.reasoning)
        print(f"→ {a.recommendation}")