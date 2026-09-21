# AI Phishing Email Analyzer

A Python-based phishing email analysis tool that combines rule-based detection, URL reputation analysis, QR-code detection, Business Email Compromise (BEC) detection, optional LLM analysis, risk scoring, and MITRE ATT&CK mapping.

The project is designed as a small SOC-style email investigation tool for analyzing `.eml` files and producing structured JSON and HTML reports.

---

## Features

- `.eml` email parsing
- Email header analysis
- Sender and Reply-To comparison
- URL extraction
- Suspicious URL detection
- Credential-phishing indicators
- Urgency and social-engineering indicators
- Business Email Compromise (BEC) detection
- QR-code detection from image attachments
- QR-code URL extraction
- VirusTotal URL reputation analysis
- Optional OpenAI-powered email analysis
- Phishing, BEC, and AI-generated-content probability estimates
- Risk scoring
- MITRE ATT&CK technique mapping
- Structured JSON analysis
- HTML SOC-style reports
- Automated test suite

---

## Architecture

```text
                    ┌─────────────────────┐
                    │     .eml Input      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Email Parser     │
                    │ Headers / Body /    │
                    │ URLs / Attachments  │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
       │   Phishing  │  │     BEC     │  │ QR Detector │
       │    Rules    │  │  Detection  │  │             │
       └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
              │                │                │
              └────────────────┼────────────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
        ┌─────────────────┐        ┌─────────────────┐
        │   VirusTotal    │        │   OpenAI API    │
        │ Optional URL    │        │ Optional LLM    │
        │ Reputation      │        │ Analysis        │
        └────────┬────────┘        └────────┬────────┘
                 │                          │
                 └────────────┬─────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │    Risk Scoring     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ MITRE ATT&CK Mapping│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ JSON + HTML Report  │
                    └─────────────────────┘