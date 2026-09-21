# Installation Guide

## AI Phishing Email Analyzer

This guide explains how to install and run the AI Phishing Email Analyzer on Windows, Kali Linux, and other Linux systems.

## 1. Requirements

- Python 3
- Git
- Internet connection
- VirusTotal API key (optional)
- OpenAI API key (optional)

The analyzer can run without either API key.

## 2. Clone the Repository

```bash
git clone https://github.com/Rahman063/ai-phishing-detector.git
cd ai-phishing-detector
```

## 3. Windows Installation

### Check Python

```cmd
python --version
```

### Create a Virtual Environment

```cmd
python -m venv venv
```

### Activate the Virtual Environment

```cmd
venv\Scripts\activate.bat
```

### Install Dependencies

```cmd
pip install -r requirements.txt
```

## 4. Kali / Linux Installation

### Check Python

```bash
python3 --version
```

### Create a Virtual Environment

```bash
python3 -m venv venv
```

### Activate the Virtual Environment

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## 5. Configure API Keys

API keys are optional.

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
OPENAI_API_KEY=your_openai_api_key
```

VirusTotal is used for URL reputation analysis.

OpenAI is used for the optional AI-based email analysis.

## 6. Verify the Installation

### Windows

```cmd
python -m tests.test_samples
```

### Kali / Linux

```bash
python3 -m tests.test_samples
```

Expected result:

```text
RESULT: 4 passed, 0 failed
```

## 7. Run the Analyzer

The analyzer accepts `.eml` email files.

### Windows

```cmd
python main.py samples/phishing.eml
```

### Kali / Linux

```bash
python3 main.py samples/phishing.eml
```

## 8. Test the Included Samples

The repository includes sample emails for testing.

### Benign Email

```bash
python main.py samples/benign.eml
```

### Phishing Email

```bash
python main.py samples/phishing.eml
```

### BEC Email

```bash
python main.py samples/bec.eml
```

### QR Phishing Email

```bash
python main.py samples/qr_phishing.eml
```

On Kali/Linux, use `python3` instead of `python` if required.

## 9. Analyze Your Own Email

The analyzer works with `.eml` files.

### Gmail

1. Open the email in Gmail.
2. Click the three-dot menu.
3. Select **Download message**.
4. Save the `.eml` file.
5. Copy the file into the project directory.

Then run:

```bash
python main.py your_email.eml
```

Example:

```bash
python main.py suspicious_email.eml
```

The application does not require your Gmail password.

## 10. Generated Reports

Reports are generated in:

```text
reports/
```

Open the generated HTML report in a web browser to review the analysis.

Reports can contain:

- Email metadata
- Header analysis
- Phishing indicators
- URL analysis
- VirusTotal results
- BEC findings
- QR-code findings
- Risk score
- MITRE ATT&CK mappings
- AI analysis

## 11. Deactivate the Virtual Environment

### Windows

```cmd
deactivate
```

### Kali / Linux

```bash
deactivate
```

## 12. Troubleshooting

### `python` is not recognized on Windows

Try:

```cmd
py --version
```

If that works, use:

```cmd
py -m venv venv
```

Then:

```cmd
py main.py samples/phishing.eml
```

### `ModuleNotFoundError`

Make sure the virtual environment is activated and dependencies are installed:

```bash
pip install -r requirements.txt
```

### OpenAI API errors

Check that `OPENAI_API_KEY` is present and valid.

AI analysis is optional, so the rest of the analyzer can still run without it.

### VirusTotal errors

Check that `VIRUSTOTAL_API_KEY` is present and valid.

VirusTotal analysis is optional.

### QR detection does not work

Make sure the email contains an image attachment containing a readable QR code.

You can regenerate the QR test files with:

```bash
python create_qr_test.py
```

Then:

```bash
python create_qr_email.py
```
