from ai.email_detector import predict_text_scam_risk
from ai.phishing_detector import classify_scam_category
from ai.risk_engine import calculate_final_risk_score
from ai.explanation_engine import generate_explanations_and_advice

def scan_email(subject, body, sender=''):
    """
    Scans email subject, body, and sender address for phishing and scam indicators.
    """
    full_text = f"Subject: {subject}\nSender: {sender}\nBody: {body}"
    ml_score, heuristics = predict_text_scam_risk(full_text)
    category = classify_scam_category(full_text)

    keyword_score = min(100, (heuristics['urgency_count'] * 25) + (heuristics['financial_count'] * 25))
    domain_score = 70 if (heuristics['url_count'] > 0 and heuristics['phishing_count'] > 0) else 15

    risk_result = calculate_final_risk_score(
        ml_score=ml_score,
        virustotal_score=0,
        keyword_score=keyword_score,
        domain_score=domain_score
    )

    reasons, advice = generate_explanations_and_advice(
        scan_type='Email',
        details=heuristics,
        risk_score=risk_result['risk_score'],
        category=category
    )

    return {
        'scan_type': 'Email',
        'input_data': f"[{subject}] {body[:100]}...",
        'risk_score': risk_result['risk_score'],
        'risk_level': risk_result['risk_level'],
        'badge': risk_result['badge'],
        'color': risk_result['color'],
        'threat_category': category if risk_result['risk_score'] > 50 else 'Safe Email',
        'details': heuristics,
        'reasons': reasons,
        'advice': advice
    }
