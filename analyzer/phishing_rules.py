import re
from urllib.parse import urlparse


def check_urgency(subject, body):
    keywords = [
        "urgent",
        "immediately",
        "action required",
        "account suspended",
        "verify now",
        "act now",
        "final warning"
    ]

    text = f"{subject} {body}".lower()

    matches = [word for word in keywords if word in text]

    return matches


def check_credential_request(body):
    keywords = [
        "password",
        "login",
        "username",
        "credentials",
        "verify your account",
        "sign in",
        "authentication"
    ]

    text = body.lower()

    matches = [word for word in keywords if word in text]

    return matches


def check_sender_reply_to(headers):
    sender = headers.get("sender_email")
    reply_to = headers.get("reply_to")

    if not sender or not reply_to:
        return None

    sender_domain = sender.split("@")[-1].lower()
    reply_domain = reply_to.split("@")[-1].lower()

    if sender_domain != reply_domain:
        return {
            "sender_domain": sender_domain,
            "reply_to_domain": reply_domain
        }

    return None


def check_urls(urls):
    suspicious = []

    for item in urls:
        url = item["url"]
        domain = item["domain"]

        parsed = urlparse(url)

        reasons = []

        if parsed.scheme != "https":
            reasons.append("URL does not use HTTPS")

        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            reasons.append("URL uses an IP address")

        suspicious_keywords = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "signin"
        ]

        if any(word in url.lower() for word in suspicious_keywords):
            reasons.append("URL contains credential-related keywords")

        if reasons:
            suspicious.append({
                "url": url,
                "domain": domain,
                "reasons": reasons
            })

    return suspicious