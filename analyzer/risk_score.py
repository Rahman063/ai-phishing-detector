def calculate_risk(email_data, urgency, credentials, reply_mismatch, suspicious_urls, vt_results):
    score = 0
    reasons = []

    # Urgency
    if urgency:
        points = min(len(urgency) * 10, 20)
        score += points
        reasons.append(
            f"Urgency indicators detected: {', '.join(urgency)}"
        )

    # Credential requests
    if credentials:
        points = min(len(credentials) * 15, 30)
        score += points
        reasons.append(
            f"Credential-related indicators detected: {', '.join(credentials)}"
        )

    # Sender / Reply-To mismatch
    if reply_mismatch:
        score += 25
        reasons.append(
            "Sender domain and Reply-To domain do not match"
        )

    # Suspicious URLs
    if suspicious_urls:
        for item in suspicious_urls:
            score += min(len(item["reasons"]) * 10, 20)

            for reason in item["reasons"]:
                reasons.append(
                    f"Suspicious URL indicator: {reason}"
                )

    # VirusTotal results
    for result in vt_results:

        if "error" in result:
            continue

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)

        if malicious > 0:
            score += 40
            reasons.append(
                f"VirusTotal detected the URL as malicious "
                f"by {malicious} engine(s)"
            )

        elif suspicious > 0:
            score += 20
            reasons.append(
                f"VirusTotal marked the URL suspicious "
                f"with {suspicious} engine(s)"
            )

    # Cap score
    score = min(score, 100)

    # Risk level
    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }