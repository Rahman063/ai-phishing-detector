import os
import tempfile

from analyzer.email_parser import parse_email
from analyzer.phishing_rules import (
    check_urgency,
    check_credential_request,
    check_sender_reply_to,
    check_urls
)
from analyzer.bec_detector import detect_bec
from analyzer.qr_detector import detect_qr_code


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

SAMPLES_DIR = os.path.join(
    BASE_DIR,
    "samples"
)


def analyze_sample(filename):
    path = os.path.join(
        SAMPLES_DIR,
        filename
    )

    email_data = parse_email(path)

    headers = email_data["headers"]
    body = email_data["body"]
    urls = email_data["urls"]

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

    bec_result = detect_bec(
        headers,
        body
    )

    return {
        "email": email_data,
        "urgency": urgency,
        "credentials": credentials,
        "reply_mismatch": reply_mismatch,
        "suspicious_urls": suspicious_urls,
        "bec": bec_result
    }


def test_benign_email():

    result = analyze_sample(
        "benign.eml"
    )

    assert result["bec"]["is_bec"] is False

    assert len(
        result["urgency"]
    ) == 0

    assert len(
        result["credentials"]
    ) == 0

    print("[PASS] Benign email")


def test_phishing_email():

    result = analyze_sample(
        "phishing.eml"
    )

    assert len(
        result["urgency"]
    ) > 0

    assert len(
        result["credentials"]
    ) > 0

    assert len(
        result["suspicious_urls"]
    ) > 0

    assert result["bec"]["is_bec"] is False

    print("[PASS] Phishing email")


def test_bec_email():

    result = analyze_sample(
        "bec.eml"
    )

    assert result["bec"]["is_bec"] is True

    assert result["bec"]["score"] >= 60

    assert len(
        result["bec"]["findings"]
    ) > 0

    print("[PASS] BEC email")


def test_qr_email():

    path = os.path.join(
        SAMPLES_DIR,
        "qr_phishing.eml"
    )

    email_data = parse_email(path)

    attachments = email_data.get(
        "attachments",
        []
    )

    assert len(attachments) > 0

    qr_detected = False
    decoded_urls = []

    for attachment in attachments:

        content_type = attachment.get(
            "content_type",
            ""
        )

        if not content_type.startswith("image/"):
            continue

        image_data = attachment.get(
            "data"
        )

        if not image_data:
            continue

        suffix = ".png"

        if content_type == "image/jpeg":
            suffix = ".jpg"

        elif content_type == "image/webp":
            suffix = ".webp"

        temp_path = None

        try:

            with tempfile.NamedTemporaryFile(
                suffix=suffix,
                delete=False
            ) as temp_file:

                temp_file.write(image_data)
                temp_path = temp_file.name

            qr_result = detect_qr_code(
                temp_path
            )

            if qr_result.get("results"):

                qr_detected = True

                for item in qr_result["results"]:

                    data = item.get(
                        "data",
                        ""
                    )

                    if data:
                        decoded_urls.append(data)

        finally:

            if temp_path and os.path.exists(
                temp_path
            ):
                os.remove(temp_path)

    assert qr_detected is True

    assert len(decoded_urls) > 0

    assert any(
        url.startswith(
            ("http://", "https://")
        )
        for url in decoded_urls
    )

    print("[PASS] QR code detected")

    print(
        f"[PASS] QR URL decoded: "
        f"{decoded_urls[0]}"
    )


def run_tests():

    print()
    print("=" * 60)
    print("AI PHISHING DETECTOR - TEST SUITE")
    print("=" * 60)
    print()

    tests = [
        test_benign_email,
        test_phishing_email,
        test_bec_email,
        test_qr_email
    ]

    passed = 0
    failed = 0

    for test in tests:

        try:
            test()
            passed += 1

        except Exception as error:

            failed += 1

            print(
                f"[FAIL] {test.__name__}: {error}"
            )

    print()
    print("=" * 60)
    print(
        f"RESULT: {passed} passed, "
        f"{failed} failed"
    )
    print("=" * 60)
    print()

    if failed > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()