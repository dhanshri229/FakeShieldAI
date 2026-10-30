import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    Config.init_app()
    conn = get_db()
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Scan History Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        scan_type TEXT NOT NULL,
        input_data TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        explanation_json TEXT,
        recommendation_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Feedback Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        user_id INTEGER,
        is_correct INTEGER NOT NULL,
        user_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scan_history (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Seed Default Admin User if missing
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        admin_pass = generate_password_hash('admin123')
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            ('admin', 'admin@fakeshield.ai', admin_pass, 'admin')
        )
        print("[Database] Default Admin created: username='admin', password='admin123'")

    conn.commit()
    conn.close()

# User Helpers
def create_user(username, email, password, role='user'):
    conn = get_db()
    cursor = conn.cursor()
    pwd_hash = generate_password_hash(password)
    try:
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (username, email, pwd_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_user_by_username(username):
    conn = get_db()
    user = conn.cursor().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db()
    user = conn.cursor().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def get_all_users():
    conn = get_db()
    users = conn.cursor().execute('SELECT id, username, email, role, created_at FROM users ORDER BY id DESC').fetchall()
    conn.close()
    return users

def delete_user(user_id):
    conn = get_db()
    conn.cursor().execute('DELETE FROM users WHERE id = ? AND role != "admin"', (user_id,))
    conn.commit()
    conn.close()

# Scan Helpers
def save_scan(user_id, scan_type, input_data, risk_score, risk_level, threat_category, explanation_json='', recommendation_json=''):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO scan_history 
           (user_id, scan_type, input_data, risk_score, risk_level, threat_category, explanation_json, recommendation_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (user_id, scan_type, input_data, risk_score, risk_level, threat_category, str(explanation_json), str(recommendation_json))
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_scan_by_id(scan_id):
    conn = get_db()
    scan = conn.cursor().execute('''
        SELECT s.*, u.username 
        FROM scan_history s 
        LEFT JOIN users u ON s.user_id = u.id 
        WHERE s.id = ?
    ''', (scan_id,)).fetchone()
    conn.close()
    return scan

def get_all_scans(limit=100, scan_type=None, search=None):
    conn = get_db()
    query = '''
        SELECT s.*, u.username 
        FROM scan_history s 
        LEFT JOIN users u ON s.user_id = u.id 
        WHERE 1=1
    '''
    params = []
    if scan_type and scan_type != 'all':
        query += ' AND s.scan_type = ?'
        params.append(scan_type)
    if search:
        query += ' AND (s.input_data LIKE ? OR s.threat_category LIKE ? OR s.risk_level LIKE ?)'
        pattern = f'%{search}%'
        params.extend([pattern, pattern, pattern])

    query += ' ORDER BY s.id DESC LIMIT ?'
    params.append(limit)

    scans = conn.cursor().execute(query, params).fetchall()
    conn.close()
    return scans

def get_scan_stats():
    conn = get_db()
    cursor = conn.cursor()

    total_scans = cursor.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]
    safe_scans = cursor.execute('SELECT COUNT(*) FROM scan_history WHERE risk_level = "SAFE"').fetchone()[0]
    threat_scans = cursor.execute('SELECT COUNT(*) FROM scan_history WHERE risk_level IN ("HIGH", "MEDIUM")').fetchone()[0]
    avg_risk = cursor.execute('SELECT AVG(risk_score) FROM scan_history').fetchone()[0] or 0

    # Category breakdown
    categories = cursor.execute('''
        SELECT threat_category, COUNT(*) as count 
        FROM scan_history 
        GROUP BY threat_category 
        ORDER BY count DESC 
        LIMIT 6
    ''').fetchall()

    # Scanner type breakdown
    types = cursor.execute('''
        SELECT scan_type, COUNT(*) as count 
        FROM scan_history 
        GROUP BY scan_type
    ''').fetchall()

    # Risk level breakdown
    levels = cursor.execute('''
        SELECT risk_level, COUNT(*) as count 
        FROM scan_history 
        GROUP BY risk_level
    ''').fetchall()

    conn.close()
    return {
        'total_scans': total_scans,
        'safe_scans': safe_scans,
        'threat_scans': threat_scans,
        'avg_risk': round(avg_risk, 1),
        'categories': [dict(c) for c in categories],
        'types': [dict(t) for t in types],
        'levels': [dict(l) for l in levels]
    }

def save_feedback(scan_id, user_id, is_correct, notes=''):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO user_feedback (scan_id, user_id, is_correct, user_notes) VALUES (?, ?, ?, ?)',
        (scan_id, user_id, 1 if is_correct else 0, notes)
    )
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
