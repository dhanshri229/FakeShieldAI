def calculate_final_risk_score(ml_score, virustotal_score=0, keyword_score=0, domain_score=0):
    """
    Fuses multiple detection vectors into a weighted Risk Score (0 - 100).
    ML Score Weight: 40%
    VirusTotal Weight: 30%
    Domain/Structure Weight: 15%
    Keyword/Pattern Weight: 15%
    """
    if virustotal_score > 0:
        total = (ml_score * 0.40) + (virustotal_score * 0.30) + (domain_score * 0.15) + (keyword_score * 0.15)
    else:
        total = (ml_score * 0.55) + (domain_score * 0.25) + (keyword_score * 0.20)

    final_score = int(round(min(100, max(0, total))))

    if final_score <= 25:
        level = 'SAFE'
        color = 'green'
        badge = '🟢 SAFE'
    elif final_score <= 50:
        level = 'LOW'
        color = 'yellow'
        badge = '🟡 LOW RISK'
    elif final_score <= 75:
        level = 'MEDIUM'
        color = 'orange'
        badge = '🟠 MEDIUM RISK'
    else:
        level = 'HIGH'
        color = 'red'
        badge = '🔴 HIGH RISK'

    return {
        'risk_score': final_score,
        'risk_level': level,
        'color': color,
        'badge': badge,
        'components': {
            'ml_score': ml_score,
            'virustotal_score': virustotal_score,
            'keyword_score': keyword_score,
            'domain_score': domain_score
        }
    }
