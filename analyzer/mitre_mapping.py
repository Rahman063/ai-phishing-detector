def map_mitre_attack(email_data, phishing_analysis, bec_analysis, qr_analysis, vt_results):
    """
    Map observed phishing behaviors to MITRE ATT&CK techniques.

    Mappings are evidence-based. The analyzer should not assign a
    technique merely because an email looks suspicious.
    """

    mappings = []

    headers = email_data.get("headers", {})
    body = email_data.get("body", "")
    urls = email_data.get("urls", [])
    attachments = email_data.get("attachments", [])

    urgency = phishing_analysis.get("urgency", [])
    credential_indicators = phishing_analysis.get(
        "credential_indicators", []
    )
    reply_to_mismatch = phishing_analysis.get(
        "reply_to_mismatch"
    )

    qr_results = qr_analysis.get("results", [])

    def add_mapping(
        technique_id,
        technique_name,
        tactic,
        evidence,
        confidence="Medium"
    ):
        mappings.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "confidence": confidence,
            "evidence": evidence
        })

    # ---------------------------------------------------------
    # T1566.002 - Spearphishing Link
    # ---------------------------------------------------------

    if urls:

        evidence = [
            f"Email contains {len(urls)} URL(s)."
        ]

        if credential_indicators:
            evidence.append(
                "Credential-related indicators were detected."
            )

        if urgency:
            evidence.append(
                "Urgency indicators were detected."
            )

        if reply_to_mismatch:
            evidence.append(
                "Sender and Reply-To domains do not match."
            )

        add_mapping(
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Initial Access",
            evidence,
            "Medium"
        )

    # ---------------------------------------------------------
    # QR phishing
    #
    # QR itself is not a separate ATT&CK technique here.
    # If the QR code resolves to a URL, the behavior maps to
    # Spearphishing Link.
    # ---------------------------------------------------------

    for qr in qr_results:

        qr_data = qr.get("data", "")

        if qr_data.startswith(("http://", "https://")):

            add_mapping(
                "T1566.002",
                "Phishing: Spearphishing Link",
                "Initial Access",
                [
                    "QR code in the email attachment decodes to a URL.",
                    f"Decoded QR destination: {qr_data}"
                ],
                "Medium"
            )

            add_mapping(
                "T1204.001",
                "User Execution: Malicious Link",
                "Execution",
                [
                    "The phishing flow requires the recipient to interact "
                    "with a QR code and follow the decoded link.",
                    f"Decoded QR destination: {qr_data}"
                ],
                "Low"
            )

    # ---------------------------------------------------------
    # T1566.001 - Spearphishing Attachment
    #
    # Only map this when an attachment is actually present.
    # ---------------------------------------------------------

    if attachments:

        attachment_names = [
            attachment.get("filename", "unknown attachment")
            for attachment in attachments
        ]

        add_mapping(
            "T1566.001",
            "Phishing: Spearphishing Attachment",
            "Initial Access",
            [
                "Email contains attachment(s).",
                "Attachments: " + ", ".join(attachment_names)
            ],
            "Medium"
        )

    # ---------------------------------------------------------
    # T1204.001 - User Execution: Malicious Link
    #
    # This represents the expected user interaction with a link.
    # We keep confidence lower because the analyzer cannot prove
    # that the recipient actually clicked it.
    # ---------------------------------------------------------

    if urls:

        evidence = [
            "Email contains a link that can require recipient interaction."
        ]

        if credential_indicators:
            evidence.append(
                "Credential-related language encourages interaction "
                "with the link."
            )

        if urgency:
            evidence.append(
                "Urgency language is used to encourage immediate action."
            )

        add_mapping(
            "T1204.001",
            "User Execution: Malicious Link",
            "Execution",
            evidence,
            "Low"
        )

    # ---------------------------------------------------------
    # BEC supporting evidence
    #
    # BEC itself is not automatically assigned a single ATT&CK
    # technique by this analyzer. We record it as contextual
    # evidence rather than inventing a technique.
    # ---------------------------------------------------------

    if bec_analysis.get("is_bec"):

        bec_score = bec_analysis.get("score", 0)

        if bec_score >= 60:
            confidence = "High"
        else:
            confidence = "Medium"

        mappings.append({
            "technique_id": None,
            "technique_name": "BEC / Social Engineering Context",
            "tactic": "Context",
            "confidence": confidence,
            "evidence": [
                "BEC indicators were detected.",
                f"BEC risk score: {bec_score}/100."
            ]
        })

    # ---------------------------------------------------------
    # Remove duplicate ATT&CK mappings while preserving evidence
    # ---------------------------------------------------------

    merged = {}

    for mapping in mappings:

        key = (
            mapping.get("technique_id"),
            mapping.get("technique_name")
        )

        if key not in merged:

            merged[key] = mapping

        else:

            existing = merged[key]

            for evidence_item in mapping.get("evidence", []):

                if evidence_item not in existing["evidence"]:
                    existing["evidence"].append(evidence_item)

            confidence_order = {
                "Low": 1,
                "Medium": 2,
                "High": 3
            }

            if (
                confidence_order.get(
                    mapping["confidence"], 0
                )
                >
                confidence_order.get(
                    existing["confidence"], 0
                )
            ):
                existing["confidence"] = mapping["confidence"]

    return list(merged.values())