import requests
import json
import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "api")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

FALLBACK_RESPONSE = {
    "verdict": "SUSPICIOUS",
    "threat_score": 50,
    "triggered_keywords": [],
    "nlp_label": "Fallback",
    "nlp_confidence": 0.5,
    "findings": ["AI unavailable. Proceed with caution."]
}

def analyze_text_payload(user_text: str) -> dict:
    prompt = f"""
You are an elite cybersecurity AI specializing in detecting phishing, scams, and social engineering attacks.

Analyze the following text and detect ANY of these red flags:
- Asking for OTP, password, PIN, CVV, card number, or any credentials
- Urgency or pressure tactics ("act now", "immediately", "hurry")
- Impersonation (pretending to be bank, government, friend)
- Requests for money transfer or personal information
- Suspicious links or offers that seem too good to be true

EXAMPLES:
- "give your otp" -> PHISHING, score 95
- "click here to claim your prize" -> PHISHING, score 90
- "hello how are you" -> SAFE, score 0
- "your account will be blocked, share your password" -> PHISHING, score 99

Text to analyze: "{user_text}"

Return ONLY a valid JSON object with exactly these three keys:
- "verdict": strictly "SAFE", "SUSPICIOUS", or "PHISHING"
- "threat_score": integer from 0 to 100
- "findings": list of 1 or 2 strings explaining exactly what the threat is

Be aggressive — when in doubt, mark as SUSPICIOUS or PHISHING.
"""

    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.1
            },
            timeout=30
        )

        if response.status_code == 429:
            print("🚨 Quota exceeded (429). Returning fallback.")
            return FALLBACK_RESPONSE

        if response.status_code == 401:
            print("🚨 Invalid API key (401). Check your Groq key.")
            return FALLBACK_RESPONSE

        response.raise_for_status()

        data = response.json()
        raw_text = data['choices'][0]['message']['content']
        result = json.loads(raw_text)

        return {
            "verdict": result.get("verdict", "SUSPICIOUS"),
            "threat_score": result.get("threat_score", 50),
            "triggered_keywords": [],
            "nlp_label": "Analysis",
            "nlp_confidence": 0.99,
            "findings": result.get("findings", ["AI analysis complete."])
        }

    except requests.exceptions.Timeout:
        print("🚨 Request timed out.")
        return FALLBACK_RESPONSE

    except requests.exceptions.ConnectionError:
        print("🚨 Connection error. Check internet.")
        return FALLBACK_RESPONSE

    except Exception as e:
        print(f"🚨 Unexpected error: {e}")
        if 'response' in locals() and hasattr(response, 'text'):
            print(f"Groq says: {response.text}")
        return FALLBACK_RESPONSE
    


def analyze_url_payload(url_text: str) -> dict:
    prompt = f"""
    You are an elite cybersecurity AI. Analyze this URL for phishing, malware, typosquatting, or scams: "{url_text}"
    
    Look for:
    - Suspicious subdomains or hidden brand names
    - Strange top-level domains
    - Obfuscated paths
    
    Return ONLY a valid JSON object with exactly these keys:
    - "verdict": strictly "SAFE", "SUSPICIOUS", or "DANGEROUS"
    - "threat_score": integer from 0 to 100
    - "findings": list of 2 or 3 strings explaining the exact structural threats found in the URL
    """

    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.1
            },
            timeout=30
        )

        if response.status_code != 200:
            return {"verdict": "SUSPICIOUS", "threat_score": 50, "findings": ["AI unreachable"]}

        data = response.json()
        raw_text = data['choices'][0]['message']['content']
        result = json.loads(raw_text)

        return {
            "verdict": result.get("verdict", "SUSPICIOUS"),
            "threat_score": result.get("threat_score", 50),
            "findings": result.get("findings", ["Analysis complete."])
        }

    except Exception:
        return {"verdict": "SUSPICIOUS", "threat_score": 50, "findings": ["Error analyzing URL layout"]}