import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'phishguard.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
