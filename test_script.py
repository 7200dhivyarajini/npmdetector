
from google import genai

client = genai.Client(api_key="AIzaSyBkGal1VL6Gi5aN8hgeZSkZAaO32KUfaak")

models_to_test = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite", 
    "gemini-2.0-flash"
]

for model in models_to_test:
    try:
        response = client.models.generate_content(
            model=model,
            contents="Say 'test'"
        )
        print(f"✅ {model} works!")
    except Exception as e:
        print(f"❌ {model} failed: {str(e)[:50]}")