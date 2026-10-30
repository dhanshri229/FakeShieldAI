import re

CATEGORY_PATTERNS = {
    'Banking Scam': [r'sbi', r'hdfc', r'icici', r'bank', r'account', r'debit card', r'credit card', r'netbanking', r'pin'],
    'OTP Scam': [r'otp', r'one time password', r'verification code', r'share code', r'do not share'],
    'KYC Scam': [r'kyc', r'pan card', r'aadhaar', r'document update', r'account blocked', r'suspended'],
    'Lottery Scam': [r'lottery', r'won', r'prize', r'reward', r'₹50', r'₹100', r'₹500', r'winner', r'lucky draw'],
    'Job Scam': [r'work from home', r'part time job', r'job offer', r'daily income', r'processing fee', r'hiring'],
    'UPI Scam': [r'gpay', r'phonepe', r'paytm', r'upi', r'cashback', r'send money to receive', r'qr payment'],
    'Delivery Scam': [r'courier', r'package', r'amazon', r'flipkart', r'bluedart', r'address update', r'delivery failed'],
    'Investment Scam': [r'crypto', r'double money', r'guaranteed return', r'bitcoin', r'trading bot', r'forex']
}

def classify_scam_category(text):
    text_lower = text.lower()
    matched_scores = {}

    for cat, patterns in CATEGORY_PATTERNS.items():
        score = sum(1 for p in patterns if re.search(p, text_lower))
        if score > 0:
            matched_scores[cat] = score

    if matched_scores:
        best_category = max(matched_scores, key=matched_scores.get)
        return best_category
    
    if any(k in text_lower for k in ['http://', 'https://', 'www.', '.com', '.xyz', '.online']):
        return 'Phishing Website'
    
    return 'General Suspicious Text'
