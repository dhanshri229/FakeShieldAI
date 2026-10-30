import json
from ai.url_detector import predict_url_risk
from ai.risk_engine import calculate_final_risk_score
from ai.explanation_engine import generate_explanations_and_advice
from services.virustotal import check_virustotal_url
from services.url_analyzer import analyze_url_structure

def scan_url(url, scan_type='URL'):
    """
    Complete end-to-end URL scanner pipeline:
    Feature extraction -> ML Model -> Structure Analysis -> VirusTotal API -> Central Risk Engine -> XAI
    """
    url = url.strip()
    ml_score, details = predict_url_risk(url)
    struct_info = analyze_url_structure(url)
    vt_result = check_virustotal_url(url)

    # Domain risk component
    domain_score = 75 if (details['is_ip'] or details['has_at_symbol'] or details['is_shortened']) else 10
    keyword_score = min(100, details['susp_kw_count'] * 30)

    risk_result = calculate_final_risk_score(
        ml_score=ml_score,
        virustotal_score=vt_result['score'],
        keyword_score=keyword_score,
        domain_score=domain_score
    )

    category = 'Phishing Website' if risk_result['risk_score'] > 50 else ('Safe QR Target' if scan_type == 'QR Code' else 'Safe Website')
    if scan_type == 'QR Code' and risk_result['risk_score'] > 50:
        category = 'Phishing QR Code Exploit'

    reasons, advice = generate_explanations_and_advice(
        scan_type=scan_type,
        details=details,
        risk_score=risk_result['risk_score'],
        category=category,
        virustotal=vt_result,
        struct_info=struct_info
    )

    return {
        'scan_type': scan_type,
        'input_data': url,
        'risk_score': risk_result['risk_score'],
        'risk_level': risk_result['risk_level'],
        'badge': risk_result['badge'],
        'color': risk_result['color'],
        'threat_category': category,
        'details': details,
        'struct_info': struct_info,
        'virustotal': vt_result,
        'reasons': reasons,
        'advice': advice
    }
