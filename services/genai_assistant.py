import re

CYBER_KNOWLEDGE = {
    'phishing': "Phishing is a cyber attack where attackers disguise themselves as trustworthy entities via emails, messages, or websites to steal sensitive credentials, credit card details, or money.",
    'sbi': "SBI bank scams usually involve urgent SMS/calls asking to update KYC or PAN card. SBI never sends SMS with unofficial links ending in .xyz or asking for your netbanking password.",
    'otp': "One-Time Passwords (OTPs) are security keys meant only for you. Never share an OTP with anyone on phone, WhatsApp, or unverified websites under any circumstance.",
    'qr': "QR code scams (Quishing) trick victims into scanning QR codes that open malicious login portals or authorize instant money deductions via UPI apps.",
    'upi': "UPI safety rule: You ONLY enter your UPI PIN to SEND money, NEVER to receive money! If a buyer asks you to scan a QR or enter your PIN to receive money, it is 100% a scam.",
    'job': "Fake job offer scams request advance processing fees, registration charges, or security deposits. Legitimate companies never charge fees for hiring.",
    'virustotal': "VirusTotal aggregates data from over 70 cybersecurity vendors and antivirus engines to inspect URLs, IPs, and files for malicious signatures."
}

def answer_user_query(query):
    query_lower = query.lower()

    for key, answer in CYBER_KNOWLEDGE.items():
        if key in query_lower:
            return f"🛡️ **FakeShield Security Assistant**:\n\n{answer}\n\n**Recommendation**: Always scan unverified links or messages using our dedicated FakeShield AI scanner tabs before interacting!"

    if 'safe' in query_lower or 'check' in query_lower or 'link' in query_lower:
        return "🛡️ **FakeShield Security Assistant**:\n\nTo check if a link, email, or message is safe, paste the content directly into our **URL Scanner**, **Email Scanner**, or **SMS Scanner**. Our AI Risk Engine will analyze it using machine learning, VirusTotal threat intelligence, and structural feature extraction."

    return (
        "🛡️ **FakeShield Security Assistant**:\n\n"
        "I am your AI Cyber Threat Protection Assistant. You can ask me about:\n"
        "1. How to identify phishing websites and scam emails\n"
        "2. SBI, HDFC, and Banking KYC scams\n"
        "3. QR code & UPI payment security rules\n"
        "4. Work-from-home job & lottery scam prevention\n\n"
        "How can I assist your security today?"
    )
