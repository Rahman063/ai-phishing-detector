import os
import json

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")

if API_KEY:
    client = OpenAI(api_key=API_KEY)
else:
    client = None


def analyze_email_with_ai(email_data, phishing_indicators, bec_result):
    if not client:
        return {
            "error": "OpenAI API key not configured"
        }

    headers = email_data["headers"]
    body = email_data["body"]

    prompt = f"""
You are a cybersecurity email analyst.

Analyze the following email for phishing, business email compromise,
social engineering, and signs of AI-generated content.

Do not assume that an email is malicious simply because it contains
suspicious-looking words. Base conclusions on the available evidence.

EMAIL HEADERS:
From: {headers.get("from")}
Sender email: {headers.get("sender_email")}
Reply-To: {headers.get("reply_to")}
To: {headers.get("to")}
Subject: {headers.get("subject")}
Date: {headers.get("date")}

EMAIL BODY:
{body}

RULE-BASED PHISHING INDICATORS:
{json.dumps(phishing_indicators, indent=2)}

BEC ANALYSIS:
{json.dumps(bec_result, indent=2)}

Return ONLY valid JSON using this structure:

{{
    "verdict": "BENIGN | SUSPICIOUS | PHISHING",
    "confidence": 0,
    "phishing_probability": 0,
    "bec_probability": 0,
    "ai_generated_probability": 0,
    "social_engineering_indicators": [],
    "reasoning": [],
    "recommended_action": ""
}}

Important:
- confidence and probabilities must be integers from 0 to 100.
- Do not claim that an email was AI-generated with certainty.
- AI-generated detection should be treated as an estimate based on writing characteristics.
- Keep reasoning tied to observable evidence.
"""

    try:
        response = client.responses.create(
            model="gpt-5.4-mini",
            input=prompt
        )

        result_text = response.output_text.strip()

        return json.loads(result_text)

    except json.JSONDecodeError:
        return {
            "error": "AI returned invalid JSON",
            "raw_response": result_text
        }

    except Exception as e:
        return {
            "error": f"OpenAI request failed: {e}"
        }