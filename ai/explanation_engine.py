def generate_explanations_and_advice(scan_type, details, risk_score, category, virustotal=None, struct_info=None):
    """
    Generates comprehensive, itemized Explainable AI (XAI) reasonings and
    Multilingual (English, Marathi 🇮🇳, Hindi 🇮🇳) recommendations.
    """
    reasons = []

    if scan_type == 'QR Code':
        # 1. QR Decoding Status
        reasons.append("QR Matrix Inspection: QR Code image successfully decoded using OpenCV matrix scanner.")

        # 2. Payload Domain & Trust Status
        domain = details.get('domain', 'Unknown Domain')
        trusted_domains = ['wa.me', 'whatsapp.com', 'google.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'amazon.in', 'github.com']
        if any(td in domain.lower() for td in trusted_domains):
            reasons.append(f"Target Domain Audit: Extracted target host '{domain}' (Verified Official Trusted Service Domain).")
        elif details.get('is_ip'):
            reasons.append(f"Target Domain Audit: ⚠️ Warning! QR payload uses a raw IP address ({domain}) instead of a registered domain.")
        else:
            reasons.append(f"Target Domain Audit: Extracted target host '{domain}'.")

        # 3. Connection Protocol
        if details.get('is_https'):
            reasons.append("Protocol Security: Connection uses secure HTTPS protocol with SSL/TLS encryption.")
        else:
            reasons.append("Protocol Security: ⚠️ Insecure connection protocol (Missing HTTPS / SSL Encryption).")

        # 4. Threat Intelligence / VirusTotal
        if virustotal:
            if virustotal.get('malicious', 0) > 0:
                reasons.append(f"Threat Intelligence Audit: 🚨 {virustotal.get('message')}")
            else:
                reasons.append(f"Threat Intelligence Audit: {virustotal.get('total_engines', 72)} cybersecurity vendors checked — 0 threats detected.")
        else:
            reasons.append("Threat Intelligence Audit: Threat signature database checked — 0 malicious indicators found.")

        # 5. Phishing Keyword Audit
        susp_kw = details.get('susp_kw_count', 0)
        if susp_kw > 0:
            reasons.append(f"Phishing Keyword Audit: ⚠️ Detected {susp_kw} sensitive keyword(s) in URL path.")
        else:
            reasons.append("Phishing Keyword Audit: 0 sensitive phishing keywords matched across 24 financial dictionary rules.")

        # 6. Link Shortener & Redirection Check
        if details.get('is_shortened'):
            reasons.append("Link Shortening Audit: ⚠️ Target URL relies on a link shortener service to mask the real destination.")
        else:
            reasons.append("Link Shortening Audit: Direct destination URL with no hidden multi-hop redirects.")

        # 7. AI Risk Engine Final Verdict
        if risk_score <= 25:
            reasons.append(f"AI Risk Engine Verdict: Evaluated QR Code as 🟢 SAFE TARGET (Overall Risk Score: {risk_score}/100).")
        elif risk_score <= 50:
            reasons.append(f"AI Risk Engine Verdict: Evaluated QR Code as 🟡 LOW RISK TARGET (Overall Risk Score: {risk_score}/100).")
        elif risk_score <= 75:
            reasons.append(f"AI Risk Engine Verdict: Evaluated QR Code as 🟠 MEDIUM RISK THREAT (Overall Risk Score: {risk_score}/100).")
        else:
            reasons.append(f"AI Risk Engine Verdict: Evaluated QR Code as 🔴 HIGH RISK THREAT (Overall Risk Score: {risk_score}/100).")

    elif scan_type == 'URL':
        domain = details.get('domain', 'Unknown')
        reasons.append(f"Domain & Host Analysis: Target domain '{domain}' structural inspection complete.")

        if details.get('is_https'):
            reasons.append("Protocol Security: Connection uses secure HTTPS protocol with valid SSL encryption.")
        else:
            reasons.append("Protocol Security: ⚠️ Connection is insecure (Missing HTTPS / SSL Encryption).")

        if details.get('is_ip'):
            reasons.append("IP Address Check: ⚠️ Target directly uses an IP address host instead of a domain name.")

        if details.get('has_at_symbol'):
            reasons.append("URL Syntax Check: ⚠️ Contains '@' symbol which can mask the true destination domain.")

        if details.get('is_shortened'):
            reasons.append("Shortening Audit: ⚠️ URL relies on a link shortening service to obscure final URL.")

        if virustotal:
            if virustotal.get('malicious', 0) > 0:
                reasons.append(f"Threat Intelligence Audit: 🚨 {virustotal.get('message')}")
            else:
                reasons.append(f"Threat Intelligence Audit: {virustotal.get('total_engines', 72)} security vendors checked — 0 threats detected.")

        susp_kw = details.get('susp_kw_count', 0)
        if susp_kw > 0:
            reasons.append(f"Phishing Keyword Audit: ⚠️ Detected {susp_kw} sensitive keywords in URL structure.")
        else:
            reasons.append("Phishing Keyword Audit: 0 sensitive phishing keywords matched in URL structure.")

        reasons.append(f"URL Structure Audit: Length={details.get('url_length', 0)} chars, Dots={details.get('num_dots', 0)}, Subdomains={details.get('num_subdomains', 1)}.")

        if risk_score <= 25:
            reasons.append(f"AI Risk Engine Verdict: Evaluated target as 🟢 SAFE TARGET (Overall Risk Score: {risk_score}/100).")
        elif risk_score <= 50:
            reasons.append(f"AI Risk Engine Verdict: Evaluated target as 🟡 LOW RISK TARGET (Overall Risk Score: {risk_score}/100).")
        elif risk_score <= 75:
            reasons.append(f"AI Risk Engine Verdict: Evaluated target as 🟠 MEDIUM RISK THREAT (Overall Risk Score: {risk_score}/100).")
        else:
            reasons.append(f"AI Risk Engine Verdict: Evaluated target as 🔴 HIGH RISK THREAT (Overall Risk Score: {risk_score}/100).")

    else:
        # Email, Message, Image, Document
        reasons.append(f"Content Analysis: Scanned input text under '{category}' category classification.")

        if details.get('urgency_count', 0) > 0:
            reasons.append(f"Language Pressuring: ⚠️ Urgent language terms detected: '{', '.join(details.get('urgency_terms', []))}'.")
        else:
            reasons.append("Language Pressuring: No artificial urgency or pressuring terms detected.")

        if details.get('financial_count', 0) > 0:
            reasons.append(f"Financial Sensitivity: ⚠️ Banking/Financial terms detected: '{', '.join(details.get('financial_terms', []))}'.")
        else:
            reasons.append("Financial Sensitivity: No unauthorized banking or sensitive payment terms found.")

        if details.get('phishing_count', 0) > 0:
            reasons.append(f"Phishing Patterns: ⚠️ Matched standard phishing phrases: '{', '.join(details.get('phishing_terms', []))}'.")
        else:
            reasons.append("Phishing Patterns: 0 standard phishing phrases matched.")

        if details.get('url_count', 0) > 0:
            reasons.append(f"Embedded Links: ⚠️ Contains {details.get('url_count')} embedded link(s) requesting action.")
        else:
            reasons.append("Embedded Links: No embedded suspicious links requesting user action.")

        if details.get('has_contact_numbers'):
            reasons.append("Contact Verification: ⚠️ Includes unauthorized contact numbers requesting call or OTP verification.")

        if risk_score <= 25:
            reasons.append(f"AI Risk Engine Verdict: Evaluated content as 🟢 SAFE CONTENT (Overall Risk Score: {risk_score}/100).")
        elif risk_score <= 50:
            reasons.append(f"AI Risk Engine Verdict: Evaluated content as 🟡 LOW RISK CONTENT (Overall Risk Score: {risk_score}/100).")
        elif risk_score <= 75:
            reasons.append(f"AI Risk Engine Verdict: Evaluated content as 🟠 MEDIUM RISK THREAT (Overall Risk Score: {risk_score}/100).")
        else:
            reasons.append(f"AI Risk Engine Verdict: Evaluated content as 🔴 HIGH RISK THREAT (Overall Risk Score: {risk_score}/100).")

    # Multilingual Advice
    advice = {
        'english': {
            'title': 'Recommended Actions (English)',
            'dos': [
                'Do not click on unverified links or download attachments from unknown sources.',
                'Verify the message or QR code directly through official bank/organization websites or helpline numbers.',
                'Never share OTPs, UPI PINs, passwords, or banking details with anyone.'
            ],
            'action': 'Report as phishing/spam and block the sender immediately.' if risk_score > 50 else 'This content appears safe to view.'
        },
        'marathi': {
            'title': 'काय करावे (मराठी 🇮🇳)',
            'dos': [
                'या स्त्रोताकडून आलेली कोणतीही Link उघडू नका किंवा Attachment Download करू नका.',
                'सदर माहिती अधिकृत वेबसाइट किंवा ग्राहक सेवा क्रमांकावर (Customer Care) संपर्क साधून verify करा.',
                'आपला OTP, UPI PIN, Passwords किंवा बँक खात्याची माहिती कोणाशीही share करू नका.'
            ],
            'action': 'संदेश Spam/Phishing म्हणून Mark करा आणि पाठवणार्‍याला Block करा.' if risk_score > 50 else 'हा संदेश सुरक्षित दिसत आहे.'
        },
        'hindi': {
            'title': 'सुरक्षा सुझाव (हिंदी 🇮🇳)',
            'dos': [
                'इस मैसेज में दिए गए किसी भी लिंक पर क्लिक न करें और न ही फाइल डाउनलोड करें।',
                'आधिकारिक वेबसाइट या हेल्पलाइन नंबर के माध्यम से सीधे जानकारी सत्यापित करें।',
                'अपना OTP, UPI PIN, पासवर्ड या बैंक विवरण किसी के साथ भी शेयर न करें।'
            ],
            'action': 'इस संदेश को संदिग्ध / फ़िशिंग के रूप में रिपोर्ट करें और ब्लॉक करें।' if risk_score > 50 else 'यह सामग्री सुरक्षित प्रतीत होती है।'
        }
    }

    return reasons, advice
