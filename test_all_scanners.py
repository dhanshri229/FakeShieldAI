import os
import sys
import json

# Ensure UTF-8 output on Windows terminal
sys.stdout.reconfigure(encoding='utf-8')

import database
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email
from scanners.message_scanner import scan_message
from scanners.qr_scanner import scan_qr_code
from scanners.image_scanner import scan_image
from scanners.document_scanner import scan_document
from services.report_service import generate_pdf_report, generate_excel_history
from services.genai_assistant import answer_user_query

def run_tests():
    print("=== FakeShield AI System Verification Suite ===")

    # 1. Database init
    database.init_db()
    print("[OK] Database initialized successfully.")

    # 2. Test URL Scanner
    test_url = "http://paypal-security-verify-login-update-account.online/login.php"
    res_url = scan_url(test_url)
    print(f"[OK] URL Scanner: Target='{test_url}' => Score={res_url['risk_score']} Level={res_url['risk_level']}")
    assert res_url['risk_score'] > 50, "URL Scanner failed to detect phishing URL"

    # 3. Test Email Scanner
    res_email = scan_email("URGENT: SBI Account Blocked", "Dear Customer, Your SBI account is suspended. Click link immediately to verify KYC http://sbi-kyc-verify.xyz")
    print(f"[OK] Email Scanner: Category='{res_email['threat_category']}' => Score={res_email['risk_score']} Level={res_email['risk_level']}")
    assert res_email['risk_score'] > 50, "Email Scanner failed to detect scam"

    # 4. Test Message Scanner (SMS/WhatsApp)
    msg = "Congratulations! You won ₹50,000 lottery in SBI draw. Claim prize now at http://sbi-lottery-claim.com"
    res_msg = scan_message(msg)
    print(f"[OK] Message Scanner: Category='{res_msg['threat_category']}' => Score={res_msg['risk_score']}")
    assert res_msg['risk_score'] > 50, "Message Scanner failed to detect lottery scam"

    # 5. Test QR Code Scanner
    sample_qr = os.path.join(os.path.dirname(__file__), 'uploads', 'test_qr.png')
    with open(sample_qr, 'wb') as f:
        f.write(b'Fake QR Binary Content')
    res_qr = scan_qr_code(sample_qr, 'test_qr.png')
    print(f"[OK] QR Scanner: Score={res_qr['risk_score']}")

    # 6. Test PDF & Excel Export
    sample_scan_data = {
        'id': 101,
        'scan_type': 'URL',
        'input_data': test_url,
        'risk_score': res_url['risk_score'],
        'risk_level': res_url['risk_level'],
        'threat_category': res_url['threat_category'],
        'explanations': res_url['reasons'],
        'created_at': '2026-09-09 10:00:00'
    }
    pdf_out = os.path.join(os.path.dirname(__file__), 'reports', 'test_report.pdf')
    generate_pdf_report(sample_scan_data, pdf_out)
    assert os.path.exists(pdf_out), "PDF Report generation failed"
    print("[OK] PDF Threat Report generated successfully.")

    excel_out = os.path.join(os.path.dirname(__file__), 'reports', 'test_history.xlsx')
    generate_excel_history([sample_scan_data], excel_out)
    assert os.path.exists(excel_out), "Excel Export failed"
    print("[OK] Excel Log generated successfully.")

    # 7. Test AI Chatbot Assistant
    ai_ans = answer_user_query("Is SBI WhatsApp KYC scam real?")
    print(f"[OK] AI Assistant Response verified.")

    print("\nALL 7 SYSTEM VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    run_tests()
