import os
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def create_workflow_pdf():
    pdf_filename = "FakeShield_AI_Project_Workflow.pdf"
    output_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = os.path.join(output_dir, pdf_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=1, # Center
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        'MainSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#0284c7'),
        alignment=1,
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=9.5,
        textColor=colors.HexColor('#334155'),
        leading=14
    )

    bullet_style = ParagraphStyle(
        'CustomBullet',
        parent=styles['BodyText'],
        fontSize=9.5,
        textColor=colors.HexColor('#1e293b'),
        leading=13,
        leftIndent=15
    )

    story = []

    # Title & Banner
    story.append(Paragraph("🛡️ FakeShield AI — Complete Project Workflow & System Architecture", title_style))
    story.append(Paragraph("AI-Powered Unified Scam, Phishing & Digital Threat Detection Platform", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284c7'), spaceAfter=15))

    # Executive Overview
    story.append(Paragraph("1. Executive Platform Architecture", h2_style))
    overview_text = (
        "FakeShield AI is an enterprise-level cybersecurity threat detection platform designed to protect users against "
        "multi-vector digital threats including phishing URLs, fraudulent emails, scam SMS/WhatsApp messages, dangerous QR code links, "
        "image payment screenshots (via OCR), and malicious PDF/TXT documents."
    )
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 10))

    # Workflow Pipeline Diagram Table
    flow_data = [
        [Paragraph("<b>Step</b>", body_style), Paragraph("<b>Phase / Module</b>", body_style), Paragraph("<b>Workflow Mechanism & Processing Details</b>", body_style)],
        [Paragraph("<b>1</b>", body_style), Paragraph("<b>Input Ingestion</b>", body_style), Paragraph("User submits URL, Email text, SMS/WhatsApp message, QR Code image, Screenshot image, or PDF document.", body_style)],
        [Paragraph("<b>2</b>", body_style), Paragraph("<b>Scanner Pipeline</b>", body_style), Paragraph("Dedicated scanner module validates input, extracts features, performs OCR, or decodes QR matrix using OpenCV QRCodeDetector.", body_style)],
        [Paragraph("<b>3</b>", body_style), Paragraph("<b>ML & NLP Engine</b>", body_style), Paragraph("Runs 14-Feature Random Forest URL Classifier or TF-IDF Logistic Regression text scam classifier.", body_style)],
        [Paragraph("<b>4</b>", body_style), Paragraph("<b>Threat Intel</b>", body_style), Paragraph("Queries VirusTotal v3 API & performs WHOIS/SSL/Subdomain structural analysis.", body_style)],
        [Paragraph("<b>5</b>", body_style), Paragraph("<b>AI Risk Engine</b>", body_style), Paragraph("Calculates unified 0–100 Risk Score (🟢 SAFE 0-25, 🟡 LOW 26-50, 🟠 MEDIUM 51-75, 🔴 HIGH 76-100).", body_style)],
        [Paragraph("<b>6</b>", body_style), Paragraph("<b>XAI & Multilingual</b>", body_style), Paragraph("Generates Explainable AI (XAI) reasonings and preventive action steps in English, Marathi (मराठी), and Hindi (हिंदी).", body_style)],
        [Paragraph("<b>7</b>", body_style), Paragraph("<b>Output & Reports</b>", body_style), Paragraph("Renders interactive gauge result, updates dashboard charts, saves to history, and exports PDF/Excel reports.", body_style)]
    ]

    t_flow = Table(flow_data, colWidths=[35, 110, 375])
    t_flow.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_flow)
    story.append(Spacer(1, 15))

    # Detailed Scanner Stages
    story.append(Paragraph("2. Deep Vector Scanner Breakdown", h2_style))
    story.append(Paragraph("<b>🌐 URL Scanner:</b> Extracts 14 features (URL length, dots, hyphens, special chars, digits, HTTPS, IP host, suspicious keywords, @ symbol, shortening service, subdomains, domain age, SSL, redirects) and passes vector to Random Forest ML model.", bullet_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>📧 Email & 💬 Message Scanner:</b> Uses TF-IDF vectorization + Logistic Regression + 8 Scam Rules (Banking, OTP, Job, Lottery, Investment, KYC, Delivery, UPI Scam).", bullet_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>📱 QR Code Scanner (Fixed & Upgraded):</b> Uses OpenCV <i>cv2.QRCodeDetector</i> + PIL image decoders to read QR code image pixels directly and decode payload URLs.", bullet_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>🖼️ Image OCR & 📄 Document Scanner:</b> Extracts embedded text from screenshots or parses PDF/DOCX content to detect fraudulent financial requests.", bullet_style))

    story.append(Spacer(1, 15))

    # Multilingual & XAI Section
    story.append(Paragraph("3. Explainable AI (XAI) & Multilingual Action Plan", h2_style))
    xai_desc = (
        "FakeShield AI does not simply output a binary prediction. It explains <b>WHY</b> content is dangerous through XAI bullet reasons, "
        "and provides actionable safety recommendations in three languages:"
    )
    story.append(Paragraph(xai_desc, body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>English:</b> Do not click unverified links or share passwords/OTPs with anyone.", bullet_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>मराठी (Marathi 🇮🇳):</b> संशयास्पद Link वर क्लिक करू नका व आपला OTP / Password कोणाशीही शेअर करू नका.", bullet_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>हिंदी (Hindi 🇮🇳):</b> अनधिकृत लिंक पर क्लिक न करें और अपना ओटीपी या पासवर्ड शेयर न करें।", bullet_style))

    story.append(Spacer(1, 15))

    # Resolution of QR Scanner Issue
    story.append(Paragraph("4. Resolution of QR Code Scanning Issue", h2_style))
    qr_fix_text = (
        "<b>Problem Resolved:</b> The QR Code scanner has been upgraded to use OpenCV's native <code>cv2.QRCodeDetector()</code> engine. "
        "This ensures that uploaded PNG, JPG, JPEG, and BMP QR images are accurately read directly from image pixel arrays "
        "without requiring external zbar C-libraries, eliminating decoding failures."
    )
    story.append(Paragraph(qr_fix_text, body_style))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
    story.append(Paragraph("Confidential Technical Documentation — Generated by FakeShield AI Autonomous Reporting Engine.", subtitle_style))

    doc.build(story)
    print(f"[PDF Generator] Successfully generated: {pdf_path}")

    # Copy to Artifacts folder for easy download link
    artifacts_dir = r"C:\Users\Monika\.gemini\antigravity\brain\26b32f38-fb6f-4813-b051-eeb9c737717c"
    if os.path.exists(artifacts_dir):
        artifact_pdf = os.path.join(artifacts_dir, pdf_filename)
        shutil.copy(pdf_path, artifact_pdf)
        print(f"[PDF Generator] Copied to artifacts: {artifact_pdf}")

if __name__ == '__main__':
    create_workflow_pdf()
