import cv2


def detect_qr_code(image_path):
    """
    Detect and decode QR codes from an image.

    Returns a list of decoded QR code results.
    """

    image = cv2.imread(image_path)

    if image is None:
        return {
            "error": f"Unable to read image: {image_path}",
            "results": []
        }

    detector = cv2.QRCodeDetector()

    results = []

    # Try multi-QR detection first
    try:
        success, decoded_info, points, _ = detector.detectAndDecodeMulti(image)

        if success and decoded_info:
            for data in decoded_info:

                if data:
                    results.append({
                        "data": data,
                        "type": "QR Code"
                    })

    except Exception:
        pass

    # Fallback to single QR detection
    if not results:

        try:
            data, points, _ = detector.detectAndDecode(image)

            if data:
                results.append({
                    "data": data,
                    "type": "QR Code"
                })

        except Exception:
            pass

    return {
        "error": None,
        "results": results
    }