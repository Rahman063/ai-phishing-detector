import qrcode


url = "https://example.com/login"


img = qrcode.make(url)

output_path = "samples/qr_phishing_test.png"

img.save(output_path)

print(f"QR code created: {output_path}")
print(f"Encoded URL: {url}")