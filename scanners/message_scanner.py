from ai.email_detector import predict_text_scam_risk
from ai.phishing_detector import classify_scam_category
from ai.risk_engine import calculate_final_risk_score
from ai.explanation_engine import generate_explanations_and_advice

def scan_message(message_text):
    """
    Scans SMS and WhatsApp messages for phishing & scam patterns.
    Categorizes into Banking, OTP, Job, Lottery, Investment, KYC, Delivery, or UPI scam.
    """
    ml_score, heuristics = predict_text_scam_risk(message_text)
    category = classify_scam_category(message_text)

    keyword_score = min(100, (heuristics['urgency_count'] * 30) + (heuristics['financial_count'] * 30))
    domain_score = 60 if heuristics['url_count'] > 0 else 10

    risk_result = calculate_final_risk_score(
        ml_score=ml_score,
        virustotal_score=0,
        keyword_score=keyword_score,
        domain_score=domain_score
    )

    reasons, advice = generate_explanations_and_advice(
        scan_type='Message',
        details=heuristics,
        risk_score=risk_result['risk_score'],
        category=category
    )

    return {
        'scan_type': 'Message',
        'input_data': message_text,
        'risk_score': risk_result['risk_score'],
        'risk_level': risk_result['risk_level'],
        'badge': risk_result['badge'],
        'color': risk_result['color'],
        'threat_category': category if risk_result['risk_score'] > 50 else 'Legitimate Message',
        'details': heuristics,
        'reasons': reasons,
        'advice': advice
    }
