import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

def generate_url_dataset():
    """Generates synthetic dataset representing 14 URL features & labels (0 = Safe, 1 = Phishing)."""
    np.random.seed(42)
    n_samples = 1500

    # Features:
    # 0: url_length
    # 1: num_dots
    # 2: num_hyphens
    # 3: num_spec_chars
    # 4: num_digits
    # 5: is_https (1=yes, 0=no)
    # 6: is_ip (1=yes, 0=no)
    # 7: suspicious_keywords (count)
    # 8: has_at_symbol (1=yes, 0=no)
    # 9: is_shortened (1=yes, 0=no)
    # 10: num_subdomains
    # 11: domain_age_days (0 to 5000)
    # 12: has_valid_ssl (1=yes, 0=no)
    # 13: redirect_count

    X = []
    y = []

    # Safe URLs (y = 0)
    for _ in range(n_samples // 2):
        url_len = np.random.randint(15, 45)
        dots = np.random.randint(1, 3)
        hyphens = np.random.randint(0, 2)
        spec = np.random.randint(0, 4)
        digits = np.random.randint(0, 5)
        is_https = 1 if np.random.rand() > 0.1 else 0
        is_ip = 0
        susp_kw = 0
        has_at = 0
        shortened = 1 if np.random.rand() < 0.05 else 0
        subdomains = np.random.randint(1, 3)
        dom_age = np.random.randint(365, 4000)
        ssl = 1 if is_https == 1 else 0
        redirects = np.random.randint(0, 2)

        X.append([url_len, dots, hyphens, spec, digits, is_https, is_ip, susp_kw, has_at, shortened, subdomains, dom_age, ssl, redirects])
        y.append(0)

    # Phishing / Malicious URLs (y = 1)
    for _ in range(n_samples // 2):
        url_len = np.random.randint(55, 180)
        dots = np.random.randint(3, 8)
        hyphens = np.random.randint(2, 7)
        spec = np.random.randint(4, 15)
        digits = np.random.randint(5, 25)
        is_https = 1 if np.random.rand() > 0.6 else 0
        is_ip = 1 if np.random.rand() > 0.7 else 0
        susp_kw = np.random.randint(1, 5)
        has_at = 1 if np.random.rand() > 0.7 else 0
        shortened = 1 if np.random.rand() > 0.4 else 0
        subdomains = np.random.randint(3, 6)
        dom_age = np.random.randint(1, 90)  # Very young domain
        ssl = 1 if np.random.rand() > 0.6 else 0
        redirects = np.random.randint(2, 6)

        X.append([url_len, dots, hyphens, spec, digits, is_https, is_ip, susp_kw, has_at, shortened, subdomains, dom_age, ssl, redirects])
        y.append(1)

    return np.array(X), np.array(y)

def train_url_model():
    print("--- Training URL ML Model (Random Forest) ---")
    X, y = generate_url_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"URL Model Accuracy: {acc*100:.2f}%")
    print(f"Precision: {prec:.4f} | Recall: {rec:.4f} | F1 Score: {f1:.4f}")

    with open(os.path.join(MODELS_DIR, 'url_model.pkl'), 'wb') as f:
        pickle.dump(clf, f)
    with open(os.path.join(MODELS_DIR, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    print("Saved url_model.pkl and scaler.pkl successfully.\n")

def generate_text_dataset():
    """Generates synthetic scam and legitimate text dataset for Email/SMS scam training."""
    scam_texts = [
        "Congratulations! You won ₹50,000 lottery. Click here immediately to claim prize.",
        "Your SBI bank account is suspended due to missing KYC. Update details now at http://sbi-kyc-update.com",
        "Urgent: Your Amazon order delivery failed. Verify credit card details at http://amz-tracking-verify.xyz",
        "Dear customer, your electricity bill is unpaid. Connection will be disconnected tonight. Call 9876543210 or pay at http://mseb-bill-online.info",
        "Earn ₹5,000 per day working online from home! No experience required. WhatsApp us now.",
        "Your Netflix subscription payment failed. Update credit card immediately to avoid cancellation: http://netflix-payment-fix.top",
        "ALERT: Someone logged into your HDFC netbanking from new device. Click link to block unauthorized transaction.",
        "Congratulations! Selected for work from home job offer. Income ₹40,000/month. Pay initial processing fee of ₹999 to confirm seat.",
        "Instant personal loan approved up to ₹5,000,000 with 0% interest! No documents required. Click link to transfer funds.",
        "Dear User, your WhatsApp account will be deactivated in 24 hours. Send OTP received on your phone to verify.",
        "Your GPay / PhonePe ₹2,000 cashback reward is pending. Click link to receive money in your account directly.",
        "Tax Refund Notice: Income Tax Department has approved ₹14,500 refund. Fill bank details to process payment.",
        "URGENT NOTICE: Security breach detected in your email account. Click here to reset password immediately.",
        "You have 1 unread message from SBI support. Login to verify your debit card PIN.",
        "Claim your free iPhone 15 Pro Max today! Complete 2 minute survey to get instant shipping."
    ]

    safe_texts = [
        "Hi, please find attached the monthly project progress report for your review.",
        "Reminder: The team sync meeting is scheduled for tomorrow at 10:00 AM on Zoom.",
        "Your order #4029-8921 has been shipped via BlueDart. Track delivery in the app.",
        "Dear Student, your semester exam timetable has been released on the official university portal.",
        "Thanks for your payment of ₹1,200 towards electricity bill. Receipt number: 9812401.",
        "Hey! Are we still meeting for lunch today at the cafeteria?",
        "Your flight ticket booking to Mumbai is confirmed. PNR: ABC1234.",
        "Please review the pull request on GitHub when you have a moment.",
        "Hi mom, I reached home safely. Will call you later in the evening.",
        "Your monthly bank account statement for August 2026 is attached as a password protected PDF.",
        "Here is the draft agenda for the upcoming cybersecurity seminar next week.",
        "Thank you for visiting our store. We hope you enjoyed your shopping experience.",
        "The project deliverables have been successfully uploaded to Google Drive.",
        "Happy Birthday! Wishing you a fantastic day and great year ahead.",
        "Please verify your email address by clicking the verification link sent during registration."
    ]

    # Duplicate & introduce variation to create larger dataset
    texts = []
    labels = []

    for t in scam_texts:
        for _ in range(30):
            texts.append(t)
            labels.append(1)

    for t in safe_texts:
        for _ in range(30):
            texts.append(t)
            labels.append(0)

    return texts, labels

def train_email_model():
    print("--- Training Email/Message NLP Scam Model (TF-IDF + Logistic Regression) ---")
    texts, labels = generate_text_dataset()

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1,2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = LogisticRegression(C=1.0)
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"Email/Message Model Accuracy: {acc*100:.2f}%")
    print(f"Precision: {prec:.4f} | Recall: {rec:.4f} | F1 Score: {f1:.4f}")

    with open(os.path.join(MODELS_DIR, 'email_model.pkl'), 'wb') as f:
        pickle.dump(clf, f)
    with open(os.path.join(MODELS_DIR, 'vectorizer.pkl'), 'wb') as f:
        pickle.dump(vectorizer, f)
    print("Saved email_model.pkl and vectorizer.pkl successfully.\n")

if __name__ == '__main__':
    train_url_model()
    train_email_model()
    print("All ML models trained and saved to models/ directory successfully!")
