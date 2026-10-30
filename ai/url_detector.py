import os
import re
import pickle
import urllib.parse
import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'account', 'banking', 'secure', 'confirm', 'pay',
    'support', 'security', 'service', 'free', 'bonus', 'claim', 'gift', 'award',
    'winner', 'lottery', 'wallet', 'refund', 'official', 'billing', 'password', 'token'
]

SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'v.gd'
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.info', '.site', '.online', '.club', '.work', '.click', '.tk', '.ml', '.ga', '.cf', '.gq']

def extract_url_features(url):
    """
    Extracts 14 structural and behavioral features from a target URL string.
    Returns feature array for ML model prediction.
    """
    parsed = urllib.parse.urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path

    url_length = len(url)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_spec_chars = len(re.findall(r'[@_?&=%#+~]', url))
    num_digits = len(re.findall(r'\d', url))
    is_https = 1 if url.lower().startswith('https://') else 0
    is_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0

    susp_kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    has_at_symbol = 1 if '@' in url else 0

    is_shortened = 1 if any(short in domain.lower() for short in SHORTENING_SERVICES) else 0

    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 1

    # Domain Age Simulation / Heuristics based on TLD / IP / Shortener
    if is_ip or is_shortened or any(tld in domain.lower() for tld in SUSPICIOUS_TLDS):
        domain_age_days = np.random.randint(1, 60)
    else:
        domain_age_days = np.random.randint(400, 3500)

    has_ssl = 1 if is_https else 0
    redirect_count = 3 if (is_shortened or 'redirect' in url.lower()) else (1 if susp_kw_count > 1 else 0)

    features = [
        url_length, num_dots, num_hyphens, num_spec_chars, num_digits,
        is_https, is_ip, susp_kw_count, has_at_symbol, is_shortened,
        num_subdomains, domain_age_days, has_ssl, redirect_count
    ]

    return np.array([features]), {
        'url_length': url_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_spec_chars': num_spec_chars,
        'num_digits': num_digits,
        'is_https': bool(is_https),
        'is_ip': bool(is_ip),
        'susp_kw_count': susp_kw_count,
        'has_at_symbol': bool(has_at_symbol),
        'is_shortened': bool(is_shortened),
        'num_subdomains': num_subdomains,
        'domain_age_days': domain_age_days,
        'has_ssl': bool(has_ssl),
        'redirect_count': redirect_count,
        'domain': domain
    }

def predict_url_risk(url):
    """Loads ML model and predicts URL phishing probability (0-100)."""
    features_vec, details = extract_url_features(url)
    model_path = os.path.join(MODELS_DIR, 'url_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')

    if os.path.exists(model_path) and os.path.exists(scaler_path):
        with open(model_path, 'rb') as f:
            clf = pickle.load(f)
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)

        features_scaled = scaler.transform(features_vec)
        prob = clf.predict_proba(features_scaled)[0][1]
        score = int(round(prob * 100))
    else:
        # Heuristic fallback if model not loaded
        score = 80 if (details['is_ip'] or details['has_at_symbol'] or details['susp_kw_count'] > 2) else 15

    return score, details
