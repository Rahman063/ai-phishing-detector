import sys
import os
import json
from datetime import datetime

from analyzer.email_parser import parse_email
from analyzer.phishing_rules import (
    check_urgency,
    check_credential_request,
    check_sender_reply_to,
    check_urls
)
from analyzer.virustotal import analyze_url
from analyzer.risk_score import calculate_risk
from analyzer.bec_detector import detect_bec
from analyzer.ai_analyzer import analyze_email_with_ai
from analyzer.qr_detector import detect_qr_code
from analyzer.mitre_mapping import map_mitre_attack
from analyzer.html_report import generate_html_report


def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python main.py <email.eml>"
        )

        sys.exit(1)

    email_path = sys.argv[1]

    if not os.path.exists(email_path):

        print(
            f"[!] Email file not found: {email_path}"
        )

        sys.exit(1)

    print()
    print("==============================================")
    print("       AI PHISHING EMAIL ANALYZER")
    print("==============================================")
    print()

    # ---------------------------------------------------------
    # EMAIL PARSING
    # ---------------------------------------------------------

    print("=== PARSING EMAIL ===")

    email_data = parse_email(email_path)

    headers = email_data["headers"]
    body = email_data["body"]
    urls = email_data["urls"]
    attachments = email_data["attachments"]

    print("[+] Email parsed successfully")
    print()

    # ---------------------------------------------------------
    # HEADERS
    # ---------------------------------------------------------

    print("=== EMAIL HEADERS ===")

    for key, value in headers.items():

        print(f"{key}: {value}")

    print()

    # ---------------------------------------------------------
    # BODY
    # ---------------------------------------------------------

    print("=== EMAIL BODY ===")
    print(body)
    print()

    # ---------------------------------------------------------
    # URL EXTRACTION
    # ---------------------------------------------------------

    print("=== EXTRACTED URLs ===")

    if urls:

        for item in urls:

            print(
                f"URL: {item['url']}"
            )

            print(
                f"Domain: {item['domain']}"
            )

            print(
                f"Scheme: {item['scheme']}"
            )

            print()

    else:

        print("[+] No URLs found")
        print()

    # ---------------------------------------------------------
    # PHISHING RULES
    # ---------------------------------------------------------

    print("=== PHISHING INDICATORS ===")

    urgency = check_urgency(
        headers.get("subject") or "",
        body
    )

    credentials = check_credential_request(
        body
    )

    reply_mismatch = check_sender_reply_to(
        headers
    )

    suspicious_urls = check_urls(
        urls
    )

    if urgency:
        print(
            "[!] Urgency indicators:",
            ", ".join(urgency)
        )

    if credentials:
        print(
            "[!] Credential indicators:",
            ", ".join(credentials)
        )

    if reply_mismatch:

        print(
            "[!] Sender/Reply-To mismatch:",
            f"{reply_mismatch['sender_domain']} -> "
            f"{reply_mismatch['reply_to_domain']}"
        )

    if suspicious_urls:

        for item in suspicious_urls:

            print(
                f"[!] Suspicious URL: {item['url']}"
            )

            for reason in item["reasons"]:

                print(
                    f"    - {reason}"
                )

    if (
        not urgency
        and not credentials
        and not reply_mismatch
        and not suspicious_urls
    ):

        print(
            "[+] No basic phishing indicators detected."
        )

    print()

    phishing_analysis = {
        "urgency": urgency,
        "credential_indicators": credentials,
        "reply_to_mismatch": reply_mismatch,
        "suspicious_urls": suspicious_urls
    }

    # ---------------------------------------------------------
    # BEC ANALYSIS
    # ---------------------------------------------------------

    print("=== BEC ANALYSIS ===")

    bec_result = detect_bec(
        headers,
        body
    )

    print(
        "BEC Detected:",
        bec_result["is_bec"]
    )

    print(
        "BEC Risk Score:",
        f"{bec_result['score']}/100"
    )

    print(
        "BEC Risk Level:",
        bec_result["risk_level"]
    )

    if bec_result["findings"]:

        print("BEC Indicators:")

        for finding in bec_result["findings"]:

            print(
                f"[!] {finding['category']}: "
                f"{', '.join(finding['matches'])}"
            )

    else:

        print(
            "[+] No strong BEC indicators detected."
        )

    print()

    # ---------------------------------------------------------
    # QR CODE ANALYSIS
    # ---------------------------------------------------------

    print("=== QR CODE ANALYSIS ===")

    qr_results = []

    for attachment in attachments:

        content_type = attachment.get(
            "content_type",
            ""
        )

        filename = attachment.get(
            "filename",
            "attachment"
        )

        if content_type.startswith("image/"):

            safe_filename = os.path.basename(
                filename
            )

            temp_path = os.path.join(
                "samples",
                f"_qr_temp_{safe_filename}"
            )

            try:

                with open(
                    temp_path,
                    "wb"
                ) as temp_file:

                    temp_file.write(
                        attachment["data"]
                    )

                qr_result = detect_qr_code(
                    temp_path
                )

                for result in qr_result.get(
                    "results",
                    []
                ):

                    qr_results.append({
                        "filename": filename,
                        "data": result.get("data"),
                        "type": result.get("type")
                    })

                os.remove(
                    temp_path
                )

            except Exception as e:

                print(
                    f"[!] QR analysis failed for "
                    f"{filename}: {e}"
                )

                if os.path.exists(temp_path):

                    os.remove(
                        temp_path
                    )

    qr_analysis = {
        "detected": len(qr_results) > 0,
        "results": qr_results
    }

    if qr_results:

        for result in qr_results:

            print(
                "[!] QR Code detected:",
                result["filename"]
            )

            print(
                f"    Data: {result['data']}"
            )

    else:

        print(
            "[+] No QR codes detected."
        )

    print()

    # ---------------------------------------------------------
    # VIRUSTOTAL
    # ---------------------------------------------------------

    print("=== VIRUSTOTAL ANALYSIS ===")

    vt_results = []

    urls_to_check = []

    for item in urls:

        urls_to_check.append(
            item["url"]
        )

    for item in qr_results:

        qr_data = item.get(
            "data",
            ""
        )

        if qr_data.startswith(
            ("http://", "https://")
        ):

            if qr_data not in urls_to_check:

                urls_to_check.append(
                    qr_data
                )

    for url in urls_to_check:

        print(
            f"Analyzing: {url}"
        )

        result = analyze_url(
            url
        )

        vt_results.append(
            result
        )

        if "error" in result:

            print(
                f"[!] {result['error']}"
            )

        else:

            print(
                "Malicious:",
                result.get("malicious", 0)
            )

            print(
                "Suspicious:",
                result.get("suspicious", 0)
            )

            print(
                "Harmless:",
                result.get("harmless", 0)
            )

            print(
                "Undetected:",
                result.get("undetected", 0)
            )

        print()

    if not urls_to_check:

        print(
            "[+] No URLs available for VirusTotal analysis."
        )

        print()

    # ---------------------------------------------------------
    # RISK SCORE
    # ---------------------------------------------------------

    print("=== OVERALL RISK ASSESSMENT ===")

    risk = calculate_risk(
        email_data,
        urgency,
        credentials,
        reply_mismatch,
        suspicious_urls,
        vt_results
    )

    print(
        "Risk Score:",
        f"{risk['score']}/100"
    )

    print(
        "Risk Level:",
        risk["risk_level"]
    )

    print()

    print("=== EVIDENCE ===")

    for reason in risk["reasons"]:

        print(
            f"[!] {reason}"
        )

    if not risk["reasons"]:

        print(
            "[+] No significant indicators detected."
        )

    print()

    # ---------------------------------------------------------
    # AI ANALYSIS
    # ---------------------------------------------------------

    print("=== AI PHISHING ANALYSIS ===")

    ai_result = analyze_email_with_ai(
        email_data,
        phishing_analysis,
        bec_result
    )

    if "error" in ai_result:

        print(
            f"[!] {ai_result['error']}"
        )

    else:

        print(
            "Verdict:",
            ai_result.get("verdict")
        )

        print(
            "Confidence:",
            f"{ai_result.get('confidence')}%"
        )

        print(
            "Phishing Probability:",
            f"{ai_result.get('phishing_probability')}%"
        )

        print(
            "BEC Probability:",
            f"{ai_result.get('bec_probability')}%"
        )

        print(
            "AI-Generated Probability:",
            f"{ai_result.get('ai_generated_probability')}%"
        )

        print()

        if ai_result.get(
            "reasoning"
        ):

            print("AI Reasoning:")

            for reason in ai_result["reasoning"]:

                print(
                    f"[!] {reason}"
                )

    print()

    # ---------------------------------------------------------
    # MITRE ATT&CK MAPPING
    # ---------------------------------------------------------

    print("=== MITRE ATT&CK MAPPING ===")

    mitre_results = map_mitre_attack(
        email_data,
        phishing_analysis,
        bec_result,
        qr_analysis,
        vt_results
    )

    if mitre_results:

        for mapping in mitre_results:

            technique_id = mapping.get(
                "technique_id"
            )

            technique_name = mapping.get(
                "technique_name"
            )

            tactic = mapping.get(
                "tactic"
            )

            confidence = mapping.get(
                "confidence"
            )

            if technique_id:

                print(
                    f"[+] {technique_id} - "
                    f"{technique_name}"
                )

            else:

                print(
                    f"[+] {technique_name}"
                )

            print(
                f"    Tactic: {tactic}"
            )

            print(
                f"    Confidence: {confidence}"
            )

            print(
                "    Evidence:"
            )

            for evidence in mapping.get(
                "evidence",
                []
            ):

                print(
                    f"      - {evidence}"
                )

            print()

    else:

        print(
            "[+] No MITRE ATT&CK techniques mapped."
        )

    print()

    # ---------------------------------------------------------
    # SANITIZE EMAIL DATA FOR JSON REPORT
    # ---------------------------------------------------------
    #
    # Attachment "data" contains raw bytes used by QR detection.
    # Bytes cannot be serialized by json.dump().
    #
    # Keep attachment metadata in the report, but remove the
    # binary payload after analysis is complete.
    # ---------------------------------------------------------

    report_email = {
        "headers": email_data.get(
            "headers",
            {}
        ),
        "body": email_data.get(
            "body",
            ""
        ),
        "urls": email_data.get(
            "urls",
            []
        ),
        "attachments": []
    }

    for attachment in attachments:

        report_email["attachments"].append({
            "filename": attachment.get(
                "filename"
            ),
            "content_type": attachment.get(
                "content_type"
            ),
            "size_bytes": len(
                attachment.get(
                    "data",
                    b""
                )
            )
        })

    # ---------------------------------------------------------
    # BUILD REPORT
    # ---------------------------------------------------------

    report = {
        "generated_at": datetime.now().isoformat(),

        "email": report_email,

        "phishing_analysis": phishing_analysis,

        "bec_analysis": bec_result,

        "qr_analysis": qr_analysis,

        "virustotal_analysis": vt_results,

        "risk_assessment": risk,

        "ai_analysis": ai_result,

        "mitre_attack": mitre_results
    }

    # ---------------------------------------------------------
    # SAVE REPORTS
    # ---------------------------------------------------------

    print("=== GENERATING REPORT ===")

    reports_directory = "reports"

    os.makedirs(
        reports_directory,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    json_report_path = os.path.join(
        reports_directory,
        f"report_{timestamp}.json"
    )

    html_report_path = os.path.join(
        reports_directory,
        f"report_{timestamp}.html"
    )

    with open(
        json_report_path,
        "w",
        encoding="utf-8"
    ) as report_file:

        json.dump(
            report,
            report_file,
            indent=4,
            ensure_ascii=False
        )

    generate_html_report(
        report,
        html_report_path
    )

    print(
        f"[+] JSON report saved: "
        f"{json_report_path}"
    )

    print(
        f"[+] HTML report saved: "
        f"{html_report_path}"
    )

    print()

    print("=== ANALYSIS COMPLETE ===")


if __name__ == "__main__":
    main()