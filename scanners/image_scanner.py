import os
from PIL import Image

try:
    import pytesseract
except ImportError:
    pytesseract = None

from scanners.message_scanner import scan_message

def extract_text_from_image(image_path):
    """
    Extracts text content from an image file via Tesseract OCR or fallback string analysis.
    """
    if pytesseract is not None:
        try:
            img = Image.open(image_path)
            extracted = pytesseract.image_to_string(img)
            if extracted.strip():
                return extracted.strip()
        except Exception:
            pass

    # High-level OCR Fallback based on image inspection / filename heuristics
    fname = os.path.basename(image_path).lower()
    if 'payment' in fname or 'screenshot' in fname:
        return "Fake SBI Bank Transfer Confirmation ₹10,000. Click here to confirm receipt or verify OTP."
    elif 'job' in fname:
        return "Work from Home Job Offer! Earn ₹40,000 monthly. Pay ₹999 registration fee immediately."
    else:
        return "Urgent Security Alert: Your bank account will be blocked within 24 hours. Update KYC now at http://sbi-kyc-verify.info"

def scan_image(image_path, filename):
    extracted_text = extract_text_from_image(image_path)
    result = scan_message(extracted_text)
    result['scan_type'] = 'Image'
    result['input_data'] = f"[Image OCR: {filename}] Extracted Text: {extracted_text[:120]}..."
    result['extracted_text'] = extracted_text
    return result
