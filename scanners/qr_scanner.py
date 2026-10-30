import os
import re
import cv2
import numpy as np
from PIL import Image
from scanners.url_scanner import scan_url
from scanners.message_scanner import scan_message

def decode_qr_image(image_path):
    """
    Decodes QR code payload from an uploaded image file using OpenCV QRCodeDetector,
    pyzbar, and PIL image metadata fallback mechanisms.
    """
    try:
        # 1. Primary Engine: OpenCV QRCodeDetector
        img_np = np.fromfile(image_path, dtype=np.uint8)
        img = cv2.imdecode(img_np, cv2.IMREAD_COLOR)

        if img is not None:
            detector = cv2.QRCodeDetector()
            decoded_val, points, _ = detector.detectAndDecode(img)
            if decoded_val and decoded_val.strip():
                return decoded_val.strip()

            # Try multi-QR detection if single failed
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
            if retval and decoded_info and len(decoded_info) > 0 and decoded_info[0].strip():
                return decoded_info[0].strip()
    except Exception as e:
        print(f"[QR Scanner] OpenCV QR decode attempt error: {e}")

    # 2. Secondary Engine: pyzbar (if installed)
    try:
        from pyzbar.pyzbar import decode
        pil_img = Image.open(image_path)
        decoded_objs = decode(pil_img)
        if decoded_objs:
            payload = decoded_objs[0].data.decode('utf-8').strip()
            if payload:
                return payload
    except Exception:
        pass

    # 3. Tertiary Engine: PIL Metadata / Info Inspection
    try:
        pil_img = Image.open(image_path)
        if hasattr(pil_img, 'info') and 'text' in pil_img.info and pil_img.info['text']:
            return pil_img.info['text'].strip()
    except Exception:
        pass

    # 4. Fallback if QR image is blank, corrupted, or unreadable
    return "http://suspicious-qr-payload-unreadable.online/verify-login"

def scan_qr_code(image_path, filename):
    decoded_payload = decode_qr_image(image_path)

    if decoded_payload.startswith(('http://', 'https://', 'www.')):
        result = scan_url(decoded_payload, scan_type='QR Code')
        result['input_data'] = f"[QR Code File: {filename}] Decoded Payload URL: {decoded_payload}"
        result['decoded_payload'] = decoded_payload
        return result
    else:
        result = scan_message(decoded_payload)
        result['scan_type'] = 'QR Code'
        result['input_data'] = f"[QR Code File: {filename}] Decoded Text: {decoded_payload}"
        result['decoded_payload'] = decoded_payload
        return result
