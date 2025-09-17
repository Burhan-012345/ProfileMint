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
    REDIRECT_URI = os.environ.get('REDIRECT_URI') or 'https://mine01.pythonanywhere.com/login/google/authorize'

    # Session configuration
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    # Create static/resumes directory for PDF downloads
    resumes_dir = os.path.join(basedir, 'static', 'resumes')
    os.makedirs(resumes_dir, exist_ok=True)

  # In config.py, update the init_app method
@staticmethod
def init_app(app):
    # For PythonAnywhere deployment
    if 'pythonanywhere' in os.environ.get('HOME', ''):
        # Set PythonAnywhere specific paths
        app.config['UPLOAD_FOLDER'] = '/home/mine01/ProfileMint/static/img/uploads'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/mine01/ProfileMint/instance/database.db'
        
        # Create directories if they don't exist
        directories = [
            app.config['UPLOAD_FOLDER'],
            '/home/mine01/ProfileMint/instance',
            '/home/mine01/ProfileMint/static/resumes'
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                print(f"Created directory: {directory}")
    
    # For local development, ensure directories exist
    else:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Create static/resumes directory if it doesn't exist
        resumes_dir = os.path.join(basedir, 'static', 'resumes')
        if not os.path.exists(resumes_dir):
            os.makedirs(resumes_dir, exist_ok=True)
