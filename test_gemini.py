import os
for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_CLOUD_PROJECT"):
    print(k, "=", os.environ.get(k))

from google import genai

client = genai.Client(
    vertexai=True,
    project="iam-drift-agent",
    location="global",
)
r = client.models.generate_content(
    model="gemini-3.7-flash",
    contents="Powiedz cześć po polsku",
)
print(r.text)