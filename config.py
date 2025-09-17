import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '3ffc0347c4cee16ff7c621486cdfd431d911a69bb1b08446'
    
    # Ensure instance directory exists for database
    instance_path = os.path.join(basedir, 'instance')
    os.makedirs(instance_path, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(instance_path, "database.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Mail configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'ahmedburhan4834@gmail.com'
    MAIL_PASSWORD = 'cnzwlrvuqvskella'
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'img', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Create upload folder if it doesn't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Google OAuth configuration
    GOOGLE_CLIENT_ID = '965417814447-elnpvhohd2pgm4mq9pcce5afboau4sk5.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
    REDIRECT_URI = os.environ.get('REDIRECT_URI') or 'http://127.0.0.1:5000/login/google/authorize'
    
    # config.py - Add these session configuration settings
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Create static/resumes directory for PDF downloads
    resumes_dir = os.path.join(basedir, 'static', 'resumes')
    os.makedirs(resumes_dir, exist_ok=True)