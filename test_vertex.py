import os
print("GEMINI_API_KEY:", os.environ.get("GEMINI_API_KEY"))
print("GOOGLE_API_KEY:", os.environ.get("GOOGLE_API_KEY"))

os.environ.pop("GEMINI_API_KEY", None)
os.environ.pop("GOOGLE_API_KEY", None)
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
os.environ["GOOGLE_CLOUD_PROJECT"] = "iam-drift-agent"
os.environ["GOOGLE_CLOUD_LOCATION"] = "global"

from google import genai

client = genai.Client()
print("Vertex mode:", client._api_client.vertexai)

r = client.models.generate_content(
    model="gemini-3.7-flash",
    contents="Powiedz cześć po polsku",
)
print(r.text)