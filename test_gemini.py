import os
from google import genai

client = genai.Client(
    api_key=os.environ["GEMINI_API_KEY"]
)

response = client.models.generate_content(
    model="gemini-3.5-flash-lite",
    contents="Explain what a network intrusion detection system does in 2 sentences."
)

print(response.text)
