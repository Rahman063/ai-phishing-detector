import re


def detect_bec(headers, body):
    findings = []
    score = 0

    subject = headers.get("subject") or ""
    sender_name = headers.get("sender_name") or ""

    text = f"{subject} {body}".lower()

    # ---------------------------------------------------------
    # FINANCIAL REQUESTS
    # ---------------------------------------------------------

    financial_patterns = {
        "payment request": [
            "make a payment",
            "send payment",
            "process payment",
            "payment required",
            "wire transfer",
            "bank transfer",
            "transfer funds",
            "transfer the funds"
        ],
        "invoice request": [
            "invoice",
            "outstanding invoice",
            "pay this invoice",
            "invoice attached"
        ],
        "bank account change": [
            "new bank account",
            "updated bank account",
            "change bank details",
            "updated banking details",
            "new account details"
        ],
        "gift card request": [
            "gift card",
            "gift cards",
            "buy cards",
            "purchase gift cards"
        ]
    }

    financial_matches = []

    for category, keywords in financial_patterns.items():

        matches = [
            keyword
            for keyword in keywords
            if keyword in text
        ]

        if matches:

            findings.append({
                "category": category,
                "matches": matches
            })

            financial_matches.extend(matches)

            score += 20

    # ---------------------------------------------------------
    # URGENCY
    # ---------------------------------------------------------

    urgency_patterns = [
        "urgent",
        "immediately",
        "as soon as possible",
        "right away",
        "today",
        "within the hour",
        "time sensitive",
        "time-sensitive"
    ]

    urgency_matches = [
        keyword
        for keyword in urgency_patterns
        if keyword in text
    ]

    # Urgency becomes BEC evidence only when combined with
    # another BEC-related behavior such as a financial request,
    # authority impersonation, secrecy, or an action request.

    if urgency_matches:

        findings.append({
            "category": "urgency",
            "matches": urgency_matches
        })

        score += 10

    # ---------------------------------------------------------
    # AUTHORITY / EXECUTIVE IMPERSONATION
    # ---------------------------------------------------------

    authority_patterns = [
        "ceo",
        "chief executive",
        "director",
        "manager",
        "executive",
        "boss",
        "president"
    ]

    authority_matches = [
        keyword
        for keyword in authority_patterns
        if re.search(
            r"\b" + re.escape(keyword) + r"\b",
            text
        )
    ]

    if authority_matches:

        findings.append({
            "category": "authority impersonation indicators",
            "matches": authority_matches
        })

        score += 15

    # ---------------------------------------------------------
    # SECRECY
    # ---------------------------------------------------------

    secrecy_patterns = [
        "keep this confidential",
        "keep this private",
        "do not tell anyone",
        "don't tell anyone",
        "do not discuss",
        "don't discuss this"
    ]

    secrecy_matches = [
        keyword
        for keyword in secrecy_patterns
        if keyword in text
    ]

    if secrecy_matches:

        findings.append({
            "category": "secrecy request",
            "matches": secrecy_matches
        })

        score += 15

    # ---------------------------------------------------------
    # ACTION REQUEST
    # ---------------------------------------------------------

    action_patterns = [
        "please handle this",
        "please take care of this",
        "need you to",
        "i need you to",
        "can you handle",
        "take care of the payment",
        "process the payment",
        "complete the payment"
    ]

    action_matches = [
        keyword
        for keyword in action_patterns
        if keyword in text
    ]

    if action_matches:

        findings.append({
            "category": "action request",
            "matches": action_matches
        })

        score += 10

    # ---------------------------------------------------------
    # COMBINATION EVIDENCE
    # ---------------------------------------------------------

    # A strong BEC signal occurs when financial activity is
    # combined with urgency, authority, secrecy, or an action
    # request.

    supporting_behaviors = (
        bool(urgency_matches)
        or bool(authority_matches)
        or bool(secrecy_matches)
        or bool(action_matches)
    )

    financial_bec_pattern = (
        bool(financial_matches)
        and supporting_behaviors
    )

    # ---------------------------------------------------------
    # BEC VERDICT
    # ---------------------------------------------------------

    score = min(score, 100)

    if financial_bec_pattern and score >= 60:

        is_bec = True
        risk_level = "HIGH"

    elif financial_bec_pattern and score >= 30:

        is_bec = True
        risk_level = "MEDIUM"

    elif (
        bool(authority_matches)
        and bool(secrecy_matches)
        and bool(action_matches)
    ):

        is_bec = True
        risk_level = "MEDIUM"

    else:

        is_bec = False

        if score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

    return {
        "is_bec": is_bec,
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "sender_name": sender_name
    }