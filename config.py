import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fakeshield-ai-super-secret-cyber-key-2026'
    DATABASE = os.path.join(BASE_DIR, 'fakeshield.db')
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
    MODELS_FOLDER = os.path.join(BASE_DIR, 'models')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'txt', 'doc', 'docx'}
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY') or ''

    # Ensure required runtime directories exist
    @staticmethod
    def init_app(app=None):
        for folder in [Config.UPLOAD_FOLDER, Config.REPORTS_FOLDER, Config.MODELS_FOLDER]:
            if not os.path.exists(folder):
                os.makedirs(folder, exist_ok=True)
