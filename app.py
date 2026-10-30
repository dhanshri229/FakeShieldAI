import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash

from config import Config
from database import (
    init_db, create_user, get_user_by_username, get_user_by_id,
    get_all_users, delete_user, save_scan, get_scan_by_id,
    get_all_scans, get_scan_stats, save_feedback
)
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email
from scanners.message_scanner import scan_message
from scanners.qr_scanner import scan_qr_code
from scanners.image_scanner import scan_image
from scanners.document_scanner import scan_document
from services.report_service import generate_pdf_report, generate_excel_history
from services.genai_assistant import answer_user_query
from train_models import train_url_model, train_email_model

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Database on Startup
init_db()

def get_current_user():
    if 'user_id' in session:
        return get_user_by_id(session['user_id'])
    return None

# Context Processor for Templates
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())

# --- AUTHENTICATION ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome back, {user['username']}! Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password. Please try again.", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user_id = create_user(username, email, password)
        if user_id:
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("Username or Email already exists.", "danger")

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

# --- CORE PAGES ---
@app.route('/')
def index():
    stats = get_scan_stats()
    return render_template('index.html', stats=stats)

@app.route('/dashboard')
def dashboard():
    stats = get_scan_stats()
    recent_scans = get_all_scans(limit=8)
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)

@app.route('/profile')
def profile():
    user = get_current_user()
    if not user:
        flash("Please login to view your profile.", "warning")
        return redirect(url_for('login'))
    user_scans = get_all_scans(limit=50)
    user_scans = [s for s in user_scans if s['user_id'] == user['id']]
    return render_template('profile.html', user=user, user_scans=user_scans)

# --- SCANNER ROUTES ---
@app.route('/scan/url', methods=['GET', 'POST'])
def scan_url_route():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash("Please enter a valid URL to scan.", "warning")
            return redirect(url_for('scan_url_route'))

        res = scan_url(url)
        user_id = session.get('user_id')
        scan_id = save_scan(
            user_id=user_id,
            scan_type=res['scan_type'],
            input_data=res['input_data'],
            risk_score=res['risk_score'],
            risk_level=res['risk_level'],
            threat_category=res['threat_category'],
            explanation_json=json.dumps(res['reasons']),
            recommendation_json=json.dumps(res['advice'])
        )
        return redirect(url_for('result', scan_id=scan_id))

    return render_template('url_scanner.html')

@app.route('/scan/email', methods=['GET', 'POST'])
def scan_email_route():
    if request.method == 'POST':
        subject = request.form.get('subject', '')
        sender = request.form.get('sender', '')
        body = request.form.get('body', '').strip()

        if not body:
            flash("Please enter email body content to scan.", "warning")
            return redirect(url_for('scan_email_route'))

        res = scan_email(subject, body, sender)
        user_id = session.get('user_id')
        scan_id = save_scan(
            user_id=user_id,
            scan_type=res['scan_type'],
            input_data=res['input_data'],
            risk_score=res['risk_score'],
            risk_level=res['risk_level'],
            threat_category=res['threat_category'],
            explanation_json=json.dumps(res['reasons']),
            recommendation_json=json.dumps(res['advice'])
        )
        return redirect(url_for('result', scan_id=scan_id))

    return render_template('email_scanner.html')

@app.route('/scan/message', methods=['GET', 'POST'])
def scan_message_route():
    if request.method == 'POST':
        message_text = request.form.get('message', '').strip()
        if not message_text:
            flash("Please paste a message to scan.", "warning")
            return redirect(url_for('scan_message_route'))

        res = scan_message(message_text)
        user_id = session.get('user_id')
        scan_id = save_scan(
            user_id=user_id,
            scan_type=res['scan_type'],
            input_data=res['input_data'],
            risk_score=res['risk_score'],
            risk_level=res['risk_level'],
            threat_category=res['threat_category'],
            explanation_json=json.dumps(res['reasons']),
            recommendation_json=json.dumps(res['advice'])
        )
        return redirect(url_for('result', scan_id=scan_id))

    return render_template('message_scanner.html')

@app.route('/scan/qr', methods=['GET', 'POST'])
def scan_qr_route():
    if request.method == 'POST':
        if 'qr_file' not in request.files:
            flash("No file uploaded.", "warning")
            return redirect(url_for('scan_qr_route'))
        file = request.files['qr_file']
        if file.filename == '':
            flash("No file selected.", "warning")
            return redirect(url_for('scan_qr_route'))

        fname = secure_filename(file.filename)
        filepath = os.path.join(Config.UPLOAD_FOLDER, fname)
        file.save(filepath)

        res = scan_qr_code(filepath, fname)
        user_id = session.get('user_id')
        scan_id = save_scan(
            user_id=user_id,
            scan_type=res['scan_type'],
            input_data=res['input_data'],
            risk_score=res['risk_score'],
            risk_level=res['risk_level'],
            threat_category=res['threat_category'],
            explanation_json=json.dumps(res['reasons']),
            recommendation_json=json.dumps(res['advice'])
        )
        return redirect(url_for('result', scan_id=scan_id))

    return render_template('qr_scanner.html')

@app.route('/scan/image', methods=['GET', 'POST'])
def scan_image_route():
    if request.method == 'POST':
        if 'image_file' not in request.files:
            flash("No image file uploaded.", "warning")
            return redirect(url_for('scan_image_route'))
        file = request.files['image_file']
        if file.filename == '':
            flash("No image selected.", "warning")
            return redirect(url_for('scan_image_route'))

        fname = secure_filename(file.filename)
        filepath = os.path.join(Config.UPLOAD_FOLDER, fname)
        file.save(filepath)

        res = scan_image(filepath, fname)
        user_id = session.get('user_id')
        scan_id = save_scan(
            user_id=user_id,
            scan_type=res['scan_type'],
            input_data=res['input_data'],
            risk_score=res['risk_score'],
            risk_level=res['risk_level'],
            threat_category=res['threat_category'],
            explanation_json=json.dumps(res['reasons']),
            recommendation_json=json.dumps(res['advice'])
        )
        return redirect(url_for('result', scan_id=scan_id))

    return render_template('image_scanner.html')

@app.route('/scan/document', methods=['GET', 'POST'])
def scan_document_route():
    if request.method == 'POST':
        if 'doc_file' not in request.files:
            flash("No document uploaded.", "warning")
            return redirect(url_for('scan_document_route'))
        file = request.files['doc_file']
        if file.filename == '':
            flash("No file selected.", "warning")
            return redirect(url_for('scan_document_route'))

        fname = secure_filename(file.filename)
        filepath = os.path.join(Config.UPLOAD_FOLDER, fname)
        file.save(filepath)

        res = scan_document(filepath, fname)
        user_id = session.get('user_id')
        scan_id = save_scan(
            user_id=user_id,
            scan_type=res['scan_type'],
            input_data=res['input_data'],
            risk_score=res['risk_score'],
            risk_level=res['risk_level'],
            threat_category=res['threat_category'],
            explanation_json=json.dumps(res['reasons']),
            recommendation_json=json.dumps(res['advice'])
        )
        return redirect(url_for('result', scan_id=scan_id))

    return render_template('document_scanner.html')

# --- RESULTS & HISTORY ---
@app.route('/result/<int:scan_id>')
def result(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("Scan record not found.", "danger")
        return redirect(url_for('dashboard'))

    explanations = []
    if scan['explanation_json']:
        try:
            explanations = json.loads(scan['explanation_json'])
        except Exception:
            explanations = [scan['explanation_json']]

    advice = {}
    if scan['recommendation_json']:
        try:
            advice = json.loads(scan['recommendation_json'])
        except Exception:
            pass

    return render_template('result.html', scan=scan, explanations=explanations, advice=advice)

@app.route('/history')
def history():
    scan_type = request.args.get('type')
    search = request.args.get('q')
    scans = get_all_scans(limit=100, scan_type=scan_type, search=search)
    return render_template('history.html', scans=scans, current_type=scan_type, search_query=search)

# --- EXPORTS & FEEDBACK ---
@app.route('/export/pdf/<int:scan_id>')
def export_pdf(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("Scan record not found.", "danger")
        return redirect(url_for('history'))

    pdf_filename = f"FakeShield_Report_Scan_{scan_id}.pdf"
    pdf_path = os.path.join(Config.REPORTS_FOLDER, pdf_filename)
    
    scan_dict = dict(scan)
    scan_dict['explanations'] = scan_dict.get('explanation_json', '[]')
    
    generate_pdf_report(scan_dict, pdf_path)
    return send_file(pdf_path, as_attachment=True)

@app.route('/export/excel')
def export_excel():
    scans = get_all_scans(limit=500)
    excel_path = os.path.join(Config.REPORTS_FOLDER, 'FakeShield_Scan_History.xlsx')
    scans_dicts = [dict(s) for s in scans]
    generate_excel_history(scans_dicts, excel_path)
    return send_file(excel_path, as_attachment=True)

@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    data = request.get_json() or {}
    scan_id = data.get('scan_id')
    is_correct = data.get('is_correct', True)
    notes = data.get('notes', '')

    if scan_id:
        user_id = session.get('user_id')
        save_feedback(scan_id, user_id, is_correct, notes)
        return jsonify({'status': 'success', 'message': 'Feedback submitted successfully.'})
    return jsonify({'status': 'error', 'message': 'Invalid scan ID'}), 400

# --- GENAI CHATBOT ASSISTANT ---
@app.route('/genai')
def genai_page():
    return render_template('genai.html')

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json() or {}
    message = data.get('message', '').strip()
    if message:
        response = answer_user_query(message)
        return jsonify({'status': 'success', 'response': response})
    return jsonify({'status': 'error', 'response': 'Please provide a security question.'})

# --- ADMIN PANEL ---
@app.route('/admin')
def admin_panel():
    if session.get('role') != 'admin':
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('dashboard'))

    stats = get_scan_stats()
    users = get_all_users()
    all_scans = get_all_scans(limit=20)
    return render_template('admin.html', stats=stats, users=users, scans=all_scans)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    delete_user(user_id)
    flash(f"User #{user_id} deleted.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/retrain', methods=['POST'])
def admin_retrain_models():
    if session.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    train_url_model()
    train_email_model()
    flash("ML Models retrained and updated successfully!", "success")
    return redirect(url_for('admin_panel'))

# --- REST API ENDPOINTS (FOR CHROME EXTENSION & MOBILE APP) ---
@app.route('/api/v1/scan/url', methods=['POST'])
def api_scan_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    res = scan_url(url)
    save_scan(None, res['scan_type'], res['input_data'], res['risk_score'], res['risk_level'], res['threat_category'])
    return jsonify(res)

@app.route('/api/v1/scan/email', methods=['POST'])
def api_scan_email():
    data = request.get_json() or {}
    body = data.get('body', '').strip()
    subject = data.get('subject', '')
    sender = data.get('sender', '')
    if not body:
        return jsonify({'error': 'Email body content is required'}), 400
    res = scan_email(subject, body, sender)
    save_scan(None, res['scan_type'], res['input_data'], res['risk_score'], res['risk_level'], res['threat_category'])
    return jsonify(res)

@app.route('/api/v1/scan/message', methods=['POST'])
def api_scan_message():
    data = request.get_json() or {}
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Message content is required'}), 400
    res = scan_message(message)
    save_scan(None, res['scan_type'], res['input_data'], res['risk_score'], res['risk_level'], res['threat_category'])
    return jsonify(res)

if __name__ == '__main__':
    print("Starting FakeShield AI Server on http://127.0.0.1:5000 ...")
    app.run(debug=True, host='0.0.0.0', port=5000)
