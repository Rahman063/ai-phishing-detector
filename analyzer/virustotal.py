import os
import base64
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"


def analyze_url(url):
    if not API_KEY:
        return {
            "error": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": API_KEY
    }

    # VirusTotal URL identifier
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    endpoint = f"{BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        elif response.status_code == 404:
            return {
                "url": url,
                "error": "URL not found in VirusTotal"
            }

        elif response.status_code == 401:
            return {
                "url": url,
                "error": "Invalid VirusTotal API key"
            }

        elif response.status_code == 429:
            return {
                "url": url,
                "error": "VirusTotal API rate limit reached"
            }

        else:
            return {
                "url": url,
                "error": f"VirusTotal HTTP {response.status_code}"
            }

    except requests.RequestException as e:
        return {
            "url": url,
            "error": f"Request failed: {e}"
        }