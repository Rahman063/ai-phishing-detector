from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
import re
import os


def parse_email(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body_parts = []
    urls = []
    attachments = []

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()

            # ==============================
            # TEXT CONTENT
            # ==============================

            if content_type == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

            # ==============================
            # IMAGE ATTACHMENTS
            # ==============================

            elif content_type.startswith("image/"):

                payload = part.get_payload(decode=True)

                if payload:

                    filename = part.get_filename()

                    if not filename:
                        extension = content_type.split("/")[-1]
                        filename = f"attachment.{extension}"

                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "data": payload
                    })

    else:

        try:
            body_parts.append(msg.get_content())
        except Exception:
            pass

    body = "\n".join(body_parts)

    # ==============================
    # URL EXTRACTION
    # ==============================

    url_pattern = r"https?://[^\s\"'<>]+"

    found_urls = re.findall(
        url_pattern,
        body
    )

    for url in found_urls:

        parsed = urlparse(url)

        urls.append({
            "url": url,
            "domain": parsed.netloc,
            "scheme": parsed.scheme
        })

    # ==============================
    # SENDER INFORMATION
    # ==============================

    sender_name, sender_email = parseaddr(
        msg.get("From", "")
    )

    return {
        "headers": {
            "from": msg.get("From"),
            "sender_name": sender_name,
            "sender_email": sender_email,
            "to": msg.get("To"),
            "subject": msg.get("Subject"),
            "date": msg.get("Date"),
            "reply_to": msg.get("Reply-To"),
            "return_path": msg.get("Return-Path"),
            "received": msg.get_all("Received", [])
        },

        "body": body,

        "urls": urls,

        "attachments": attachments
    }