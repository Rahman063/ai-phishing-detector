from email.message import EmailMessage
from email.utils import formatdate
import mimetypes
import os


QR_IMAGE = "samples/qr_phishing_test.png"
OUTPUT_EMAIL = "samples/qr_phishing.eml"


def create_email():
    if not os.path.exists(QR_IMAGE):
        print(f"[!] QR image not found: {QR_IMAGE}")
        print("[!] Run create_qr_test.py first.")
        return

    message = EmailMessage()

    message["From"] = "Microsoft Security <security@example.com>"
    message["To"] = "user@example.com"
    message["Subject"] = "Urgent: Verify Your Account"
    message["Date"] = formatdate(localtime=False)
    message["Reply-To"] = "security-verification@example.net"

    message.set_content(
        """Your Microsoft account requires immediate verification.

Please scan the QR code below to verify your account.

Failure to verify your account may result in suspension.
"""
    )

    with open(QR_IMAGE, "rb") as image_file:
        image_data = image_file.read()

    mime_type, _ = mimetypes.guess_type(QR_IMAGE)

    if mime_type:
        maintype, subtype = mime_type.split("/", 1)
    else:
        maintype = "image"
        subtype = "png"

    message.add_attachment(
        image_data,
        maintype=maintype,
        subtype=subtype,
        filename="account_verification.png"
    )

    with open(OUTPUT_EMAIL, "wb") as email_file:
        email_file.write(bytes(message))

    print(f"[+] Test phishing email created: {OUTPUT_EMAIL}")


if __name__ == "__main__":
    create_email()