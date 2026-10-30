import os
import pickle
import re

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')

URGENCY_KEYWORDS = ['urgent', 'immediately', 'suspended', 'blocked', '24 hours', 'action required', 'critical', 'deactivated', 'expire', 'asap']
FINANCIAL_KEYWORDS = ['bank', 'account', 'otp', 'credit card', 'refund', 'lottery', 'prize', 'claim', 'kyc', 'cashback', 'transfer', 'processing fee', 'loan', 'upi', 'gpay', 'phonepe']
PHISHING_PHRASES = [
    'congratulations', 'won', 'click here', 'verify your account', 'update details',
    'security alert', 'unauthorized transaction', 'work from home', 'income tax refund',
    'free gift', 'limited time offer'
]

def extract_text_heuristics(text):
    text_lower = text.lower()
    urgency_found = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
    financial_found = [kw for kw in FINANCIAL_KEYWORDS if kw in text_lower]
    phishing_found = [phrase for phrase in PHISHING_PHRASES if phrase in text_lower]
    urls_found = re.findall(r'https?://[^\s]+|www\.[^\s]+', text)
    numbers_found = re.findall(r'\b\d{5,}\b', text)

    return {
        'urgency_count': len(urgency_found),
        'urgency_terms': urgency_found,
        'financial_count': len(financial_found),
        'financial_terms': financial_found,
        'phishing_count': len(phishing_found),
        'phishing_terms': phishing_found,
        'url_count': len(urls_found),
        'urls': urls_found,
        'has_contact_numbers': len(numbers_found) > 0
    }

def predict_text_scam_risk(text):
    """Predicts scam risk percentage (0-100) using ML TF-IDF model and text heuristics."""
    heuristics = extract_text_heuristics(text)
    model_path = os.path.join(MODELS_DIR, 'email_model.pkl')
    vectorizer_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')

    ml_score = 0
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        with open(model_path, 'rb') as f:
            clf = pickle.load(f)
        with open(vectorizer_path, 'rb') as f:
            vectorizer = pickle.load(f)

        vec = vectorizer.transform([text])
        prob = clf.predict_proba(vec)[0][1]
        ml_score = int(round(prob * 100))

    # Combine ML score with Heuristics boost if strong indicator present
    heuristic_boost = 0
    if heuristics['urgency_count'] > 0 and heuristics['financial_count'] > 0:
        heuristic_boost += 25
    if heuristics['url_count'] > 0 and heuristics['phishing_count'] > 0:
        heuristic_boost += 25

    final_score = min(100, max(ml_score, heuristic_boost))
    return final_score, heuristics
