import html
import os
from datetime import datetime


def generate_html_report(report, output_path):

    risk = report.get("risk_assessment", {})
    email = report.get("email", {})
    phishing = report.get("phishing_analysis", {})
    bec = report.get("bec_analysis", {})
    qr = report.get("qr_analysis", {})
    vt_results = report.get("virustotal_analysis", [])
    ai = report.get("ai_analysis", {})
    mitre_results = report.get("mitre_attack", [])

    risk_score = risk.get(
        "score",
        0
    )

    risk_level = risk.get(
        "risk_level",
        "UNKNOWN"
    )

    sender = email.get(
        "headers",
        {}
    ).get(
        "sender_email",
        "Unknown"
    )

    subject = email.get(
        "headers",
        {}
    ).get(
        "subject",
        "Unknown"
    )

    def escape(value):
        return html.escape(
            str(value)
        )

    # ---------------------------------------------------------
    # RISK LEVEL STYLE
    # ---------------------------------------------------------

    risk_styles = {
        "HIGH": (
            "#fee2e2",
            "#991b1b"
        ),
        "MEDIUM": (
            "#fef3c7",
            "#92400e"
        ),
        "LOW": (
            "#dcfce7",
            "#166534"
        )
    }

    risk_background, risk_color = risk_styles.get(
        risk_level,
        (
            "#e5e7eb",
            "#374151"
        )
    )

    # ---------------------------------------------------------
    # EVIDENCE
    # ---------------------------------------------------------

    evidence_items = risk.get(
        "reasons",
        []
    )

    evidence_html = ""

    if evidence_items:

        for item in evidence_items:

            evidence_html += (
                f"<li>{escape(item)}</li>"
            )

    else:

        evidence_html = (
            "<li>No significant indicators detected.</li>"
        )

    # ---------------------------------------------------------
    # URLS
    # ---------------------------------------------------------

    urls_html = ""

    for url in email.get(
        "urls",
        []
    ):

        urls_html += f"""
        <tr>
            <td>{escape(url.get("url"))}</td>
            <td>{escape(url.get("domain"))}</td>
            <td>{escape(url.get("scheme"))}</td>
        </tr>
        """

    if not urls_html:

        urls_html = """
        <tr>
            <td colspan="3">No URLs found.</td>
        </tr>
        """

    # ---------------------------------------------------------
    # QR
    # ---------------------------------------------------------

    qr_html = ""

    for item in qr.get(
        "results",
        []
    ):

        qr_html += f"""
        <tr>
            <td>{escape(item.get("filename"))}</td>
            <td>{escape(item.get("data"))}</td>
            <td>{escape(item.get("type"))}</td>
        </tr>
        """

    if not qr_html:

        qr_html = """
        <tr>
            <td colspan="3">No QR codes detected.</td>
        </tr>
        """

    # ---------------------------------------------------------
    # VIRUSTOTAL
    # ---------------------------------------------------------

    vt_html = ""

    for result in vt_results:

        vt_html += f"""
        <tr>
            <td>{escape(result.get("url", "Unknown"))}</td>
            <td>{escape(result.get("malicious", 0))}</td>
            <td>{escape(result.get("suspicious", 0))}</td>
            <td>{escape(result.get("harmless", 0))}</td>
            <td>{escape(result.get("undetected", 0))}</td>
        </tr>
        """

    if not vt_html:

        vt_html = """
        <tr>
            <td colspan="5">
                No VirusTotal results.
            </td>
        </tr>
        """

    # ---------------------------------------------------------
    # MITRE ATT&CK
    # ---------------------------------------------------------

    mitre_html = ""

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

                technique_display = (
                    f"<strong>{escape(technique_id)}</strong> "
                    f"{escape(technique_name)}"
                )

            else:

                technique_display = (
                    f"<strong>Context</strong> "
                    f"{escape(technique_name)}"
                )

            evidence_list = ""

            for evidence in mapping.get(
                "evidence",
                []
            ):

                evidence_list += (
                    f"<li>{escape(evidence)}</li>"
                )

            mitre_html += f"""
            <div class="mitre-card">

                <div class="mitre-header">

                    <div>
                        {technique_display}
                    </div>

                    <span class="confidence">
                        {escape(confidence)}
                    </span>

                </div>

                <p>
                    <strong>Tactic:</strong>
                    {escape(tactic)}
                </p>

                <p>
                    <strong>Evidence:</strong>
                </p>

                <ul>
                    {evidence_list}
                </ul>

            </div>
            """

    else:

        mitre_html = """
        <p>
            No MITRE ATT&CK techniques were mapped.
        </p>
        """

    # ---------------------------------------------------------
    # AI
    # ---------------------------------------------------------

    ai_html = ""

    if "error" in ai:

        ai_html = f"""
        <p class="warning">
            AI analysis unavailable:
            {escape(ai.get("error"))}
        </p>
        """

    else:

        ai_html = f"""
        <div class="grid">

            <div class="card">
                <h3>Verdict</h3>
                <p>{escape(ai.get("verdict"))}</p>
            </div>

            <div class="card">
                <h3>Confidence</h3>
                <p>{escape(ai.get("confidence"))}%</p>
            </div>

            <div class="card">
                <h3>Phishing Probability</h3>
                <p>
                    {escape(
                        ai.get(
                            "phishing_probability"
                        )
                    )}%
                </p>
            </div>

            <div class="card">
                <h3>BEC Probability</h3>
                <p>
                    {escape(
                        ai.get(
                            "bec_probability"
                        )
                    )}%
                </p>
            </div>

            <div class="card">
                <h3>AI-Generated Probability</h3>
                <p>
                    {escape(
                        ai.get(
                            "ai_generated_probability"
                        )
                    )}%
                </p>
            </div>

        </div>
        """

        reasoning = ai.get(
            "reasoning",
            []
        )

        if reasoning:

            ai_html += """
            <h3>AI Reasoning</h3>
            <ul>
            """

            for reason in reasoning:

                ai_html += (
                    f"<li>{escape(reason)}</li>"
                )

            ai_html += """
            </ul>
            """

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ---------------------------------------------------------
    # HTML DOCUMENT
    # ---------------------------------------------------------

    document = f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Phishing Email Analysis Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    color: #222;
    margin: 0;
    padding: 30px;
}}

.container {{
    max-width: 1100px;
    margin: auto;
}}

.header {{
    background: #111827;
    color: white;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 20px;
}}

.header h1 {{
    margin: 0 0 10px 0;
}}

.risk {{
    background: white;
    padding: 25px;
    border-radius: 12px;
    margin-bottom: 20px;
}}

.risk-score {{
    font-size: 42px;
    font-weight: bold;
}}

.risk-level {{
    display: inline-block;
    padding: 8px 14px;
    border-radius: 8px;
    font-weight: bold;
    background: {risk_background};
    color: {risk_color};
}}

.section {{
    background: white;
    padding: 25px;
    border-radius: 12px;
    margin-bottom: 20px;
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
}}

.card {{
    background: #f3f4f6;
    padding: 18px;
    border-radius: 10px;
}}

.card h3 {{
    margin-top: 0;
    font-size: 14px;
}}

.card p {{
    font-size: 22px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    text-align: left;
    word-break: break-word;
}}

th {{
    background: #f3f4f6;
}}

.warning {{
    background: #fff7ed;
    padding: 15px;
    border-radius: 8px;
}}

li {{
    margin-bottom: 8px;
}}

.mitre-card {{
    background: #f3f4f6;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 15px;
    border-left: 5px solid #374151;
}}

.mitre-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    font-size: 18px;
}}

.confidence {{
    background: #e5e7eb;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: bold;
}}

.footer {{
    text-align: center;
    color: #666;
    margin-top: 30px;
    font-size: 13px;
}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>AI Phishing Email Analyzer</h1>

<p>SOC Investigation Report</p>

<p>
Generated: {escape(generated_time)}
</p>

</div>


<div class="risk">

<h2>Overall Risk Assessment</h2>

<div class="risk-score">
{escape(risk_score)}/100
</div>

<p>
Risk Level:
<span class="risk-level">
{escape(risk_level)}
</span>
</p>

</div>


<div class="section">

<h2>Email Summary</h2>

<div class="grid">

<div class="card">
<h3>Sender</h3>
<p>{escape(sender)}</p>
</div>

<div class="card">
<h3>Subject</h3>
<p>{escape(subject)}</p>
</div>

<div class="card">
<h3>BEC Detected</h3>
<p>{escape(bec.get("is_bec"))}</p>
</div>

<div class="card">
<h3>QR Code Detected</h3>
<p>{escape(qr.get("detected"))}</p>
</div>

</div>

</div>


<div class="section">

<h2>Evidence</h2>

<ul>
{evidence_html}
</ul>

</div>


<div class="section">

<h2>Phishing Indicators</h2>

<div class="grid">

<div class="card">
<h3>Urgency</h3>
<p>
{escape(
    ", ".join(
        phishing.get(
            "urgency",
            []
        )
    )
)}
</p>
</div>

<div class="card">
<h3>Credential Indicators</h3>
<p>
{escape(
    ", ".join(
        phishing.get(
            "credential_indicators",
            []
        )
    )
)}
</p>
</div>

<div class="card">
<h3>Reply-To Mismatch</h3>
<p>
{escape(
    bool(
        phishing.get(
            "reply_to_mismatch"
        )
    )
)}
</p>
</div>

</div>

</div>


<div class="section">

<h2>URL Analysis</h2>

<table>

<tr>
<th>URL</th>
<th>Domain</th>
<th>Scheme</th>
</tr>

{urls_html}

</table>

</div>


<div class="section">

<h2>QR Code Analysis</h2>

<table>

<tr>
<th>Attachment</th>
<th>Decoded Data</th>
<th>Type</th>
</tr>

{qr_html}

</table>

</div>


<div class="section">

<h2>VirusTotal Analysis</h2>

<table>

<tr>
<th>URL</th>
<th>Malicious</th>
<th>Suspicious</th>
<th>Harmless</th>
<th>Undetected</th>
</tr>

{vt_html}

</table>

</div>


<div class="section">

<h2>MITRE ATT&CK Mapping</h2>

{mitre_html}

</div>


<div class="section">

<h2>AI Analysis</h2>

{ai_html}

</div>


<div class="footer">

AI Phishing Email Analyzer |
SOC Investigation Report

</div>

</div>

</body>

</html>
"""

    output_directory = os.path.dirname(
        output_path
    )

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True
        )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            document
        )