import os
import io
import pyotp
import uuid
from flask_mail import Mail
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
import secrets
import random
import string
import sqlite3
import urllib.parse
from pathlib import Path
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta  # Add timedelta import
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
# Remove pdfkit import
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import json
from authlib.integrations.flask_client import OAuth
from weasyprint import HTML, CSS 
from flask_wtf.csrf import generate_csrf, CSRFError

# Import configuration
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize OAuth first
mail = Mail(app)
oauth = OAuth(app)
# After initializing CSRF protection
csrf = CSRFProtect(app)

# Add the login_required decorator definition here
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        
        # Verify user actually exists in database
        user = User.query.get(session['user_id'])
        if not user:
            flash('Your session is invalid. Please log in again.', 'danger')
            session.clear()
            return redirect(url_for('login'))
            
        # Refresh session to keep it alive
        session.modified = True
        return f(*args, **kwargs)
    return decorated_function

def two_factor_verified(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.two_factor_enabled and not session.get('2fa_verified'):
                # 2FA is enabled but not verified in this session
                session['2fa_user_id'] = user.id
                session['2fa_required'] = True
                flash('Two-factor authentication verification required.', 'info')
                return redirect(url_for('verify_2fa_login'))
        return f(*args, **kwargs)
    return decorated_function

# Add this to handle AJAX CSRF protection
@csrf.exempt
@app.after_request
def set_csrf_cookie(response):
    if response.status_code == 200:
        response.set_cookie('csrf_token', generate_csrf())
    return response

# Add a custom error handler for CSRF errors
@app.errorhandler(400)
def handle_csrf_error(e):
    if 'CSRF token' in str(e.description):
        return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 400
    return e

# In app.py, update the Google OAuth registration:
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
        'redirect_uri': app.config['REDIRECT_URI']  # Use configurable redirect URI
    },
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# In app.py, update the User class
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(200), nullable=True)
    subscription_type = db.Column(db.String(20), default='free')
    two_factor_backup_codes = db.Column(db.Text, nullable=True)  # Store as JSON array
    
    # Integration fields - only Google remains
    google_connected = db.Column(db.Boolean, default=False)
    
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    two_factor_backup_codes = db.Column(db.Text, nullable=True)
    
    # Premium subscription fields
    is_premium = db.Column(db.Boolean, default=False)
    subscription_status = db.Column(db.String(20), default='inactive')  # active, canceled, expired
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    
    resumes = db.relationship('Resume', backref='user', lazy=True)

class Resume(db.Model):
    __tablename__ = 'resumes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    template = db.Column(db.String(50), default='template1')
    data = db.Column(db.Text)  # JSON data stored as text
    photo = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=False)

    @property
    def data_dict(self):
        """Parse the JSON data from the database"""
        try:
            return json.loads(self.data) if self.data else {}
        except json.JSONDecodeError:
            return {}

class MagicLink(db.Model):
    __tablename__ = 'magic_links'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('magic_links', lazy=True))

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # For tracking suspicious activity
    flagged = db.Column(db.Boolean, default=False)
    reason = db.Column(db.String(200), nullable=True)
    
    @property
    def data_dict(self):
        try:
            return json.loads(self.data) if self.data else {}
        except json.JSONDecodeError:
            return {}

class OTP(db.Model):
    __tablename__ = 'otps'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Add a new model for API keys
class APIKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False)
    prefix = db.Column(db.String(8), nullable=False)
    permissions = db.Column(db.String(20), default='read')  # read, write, admin
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('api_keys', lazy=True))

# Add a new model for webhooks
class Webhook(db.Model):
    __tablename__ = 'webhooks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    secret = db.Column(db.String(32), nullable=False)
    events = db.Column(db.Text, default='[]')  # JSON array of events
    is_active = db.Column(db.Boolean, default=True)
    last_triggered = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('webhooks', lazy=True))

# Add a new model for tracking sessions
class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Get all active sessions for the user"""
    try:
        user = User.query.get(session['user_id'])
        sessions = UserSession.query.filter_by(user_id=user.id, is_active=True).order_by(UserSession.last_activity.desc()).all()
        
        sessions_data = []
        for user_session in sessions:
            is_current = user_session.session_id == session.get('session_id')
            
            sessions_data.append({
                'id': user_session.id,
                'ip_address': user_session.ip_address,
                'user_agent': user_session.user_agent,
                'location': user_session.location,
                'last_activity': user_session.last_activity.isoformat(),
                'created_at': user_session.created_at.isoformat(),
                'is_current': is_current
            })
        
        return jsonify({'success': True, 'sessions': sessions_data})
    except Exception as e:
        app.logger.error(f"Sessions fetch error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def revoke_session(session_id):
    """Revoke a specific session"""
    try:
        user = User.query.get(session['user_id'])
        user_session = UserSession.query.get(session_id)
        
        if not user_session or user_session.user_id != user.id:
            return jsonify({'success': False, 'error': 'Session not found'}), 404
        
        # Don't allow revoking the current session through this endpoint
        if user_session.session_id == session.get('session_id'):
            return jsonify({'success': False, 'error': 'Cannot revoke current session'}), 400
        
        user_session.is_active = False
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Session revoked successfully'})
    except Exception as e:
        app.logger.error(f"Session revocation error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/update-settings', methods=['POST'])
@login_required
def update_session_settings():
    """Update session-related settings"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        # Store session preferences (you'd need to add these fields to User model)
        # For now, we'll just acknowledge the request
        
        return jsonify({'success': True, 'message': 'Session settings updated'})
    except Exception as e:
        app.logger.error(f"Session settings update error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Webhook routes
@app.route('/api/webhooks', methods=['GET'])
@login_required
def get_webhooks():
    """Get all webhooks for the current user"""
    try:
        user = User.query.get(session['user_id'])
        webhooks = Webhook.query.filter_by(user_id=user.id).order_by(Webhook.created_at.desc()).all()
        
        webhooks_data = []
        for webhook in webhooks:
            webhooks_data.append({
                'id': webhook.id,
                'name': webhook.name,
                'url': webhook.url,
                'events': json.loads(webhook.events),
                'is_active': webhook.is_active,
                'last_triggered': webhook.last_triggered.isoformat() if webhook.last_triggered else None,
                'created_at': webhook.created_at.isoformat()
            })
        
        return jsonify({'success': True, 'webhooks': webhooks_data})
    except Exception as e:
        app.logger.error(f"Webhooks fetch error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/webhooks', methods=['POST'])
@login_required
def create_webhook():
    """Create a new webhook"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        name = data.get('name')
        url = data.get('url')
        events = data.get('events', [])
        
        if not name or not url:
            return jsonify({'success': False, 'error': 'Name and URL are required'}), 400
        
        # Validate URL
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return jsonify({'success': False, 'error': 'Invalid URL'}), 400
        except:
            return jsonify({'success': False, 'error': 'Invalid URL'}), 400
        
        # Generate webhook secret
        secret = secrets.token_urlsafe(16)
        
        # Create webhook
        webhook = Webhook(
            user_id=user.id,
            name=name,
            url=url,
            secret=secret,
            events=json.dumps(events)
        )
        
        db.session.add(webhook)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'webhook': {
                'id': webhook.id,
                'name': webhook.name,
                'url': webhook.url,
                'events': json.loads(webhook.events),
                'secret': secret,  # Only returned once
                'created_at': webhook.created_at.isoformat()
            },
            'message': 'Webhook created successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Webhook creation error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/webhooks/<int:webhook_id>', methods=['PUT'])
@login_required
def update_webhook(webhook_id):
    """Update a webhook"""
    try:
        user = User.query.get(session['user_id'])
        webhook = Webhook.query.get(webhook_id)
        
        if not webhook or webhook.user_id != user.id:
            return jsonify({'success': False, 'error': 'Webhook not found'}), 404
        
        data = request.get_json()
        
        if 'name' in data:
            webhook.name = data['name']
        if 'url' in data:
            # Validate URL
            try:
                result = urllib.parse.urlparse(data['url'])
                if not all([result.scheme, result.netloc]):
                    return jsonify({'success': False, 'error': 'Invalid URL'}), 400
                webhook.url = data['url']
            except:
                return jsonify({'success': False, 'error': 'Invalid URL'}), 400
        if 'events' in data:
            webhook.events = json.dumps(data['events'])
        if 'is_active' in data:
            webhook.is_active = data['is_active']
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Webhook updated successfully'})
    except Exception as e:
        app.logger.error(f"Webhook update error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@login_required
def delete_webhook(webhook_id):
    """Delete a webhook"""
    try:
        user = User.query.get(session['user_id'])
        webhook = Webhook.query.get(webhook_id)
        
        if not webhook or webhook.user_id != user.id:
            return jsonify({'success': False, 'error': 'Webhook not found'}), 404
        
        db.session.delete(webhook)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Webhook deleted successfully'})
    except Exception as e:
        app.logger.error(f"Webhook deletion error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# API Key routes
@app.route('/api/api-keys', methods=['GET'])
@login_required
def get_api_keys():
    """Get all API keys for the current user"""
    try:
        user = User.query.get(session['user_id'])
        api_keys = APIKey.query.filter_by(user_id=user.id).order_by(APIKey.created_at.desc()).all()
        
        keys_data = []
        for key in api_keys:
            keys_data.append({
                'id': key.id,
                'name': key.name,
                'prefix': key.prefix,
                'permissions': key.permissions,
                'expires_at': key.expires_at.isoformat() if key.expires_at else None,
                'last_used': key.last_used.isoformat() if key.last_used else None,
                'created_at': key.created_at.isoformat(),
                'is_active': key.is_active
            })
        
        return jsonify({'success': True, 'api_keys': keys_data})
    except Exception as e:
        app.logger.error(f"API keys fetch error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        name = data.get('name')
        permissions = data.get('permissions', 'read')
        expiry_days = data.get('expiry_days', 30)
        
        if not name:
            return jsonify({'success': False, 'error': 'API key name is required'}), 400
        
        # Generate a secure API key
        key_secret = secrets.token_urlsafe(32)
        key_prefix = secrets.token_urlsafe(4).upper()
        full_key = f"pm_{key_prefix}_{key_secret}"
        
        # Calculate expiration date
        expires_at = datetime.utcnow() + timedelta(days=expiry_days) if expiry_days > 0 else None
        
        # Create API key record
        api_key = APIKey(
            user_id=user.id,
            name=name,
            key=generate_password_hash(key_secret),
            prefix=key_prefix,
            permissions=permissions,
            expires_at=expires_at
        )
        
        db.session.add(api_key)
        db.session.commit()
        
        # Return the full key (only shown once)
        return jsonify({
            'success': True,
            'api_key': {
                'id': api_key.id,
                'name': api_key.name,
                'full_key': full_key,
                'prefix': api_key.prefix,
                'permissions': api_key.permissions,
                'expires_at': api_key.expires_at.isoformat() if api_key.expires_at else None,
                'created_at': api_key.created_at.isoformat()
            },
            'message': 'API key created successfully. Store it securely as it will not be shown again.'
        })
        
    except Exception as e:
        app.logger.error(f"API key creation error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def revoke_api_key(key_id):
    """Revoke an API key"""
    try:
        user = User.query.get(session['user_id'])
        api_key = APIKey.query.get(key_id)
        
        if not api_key or api_key.user_id != user.id:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
        
        api_key.is_active = False
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'API key revoked successfully'})
    except Exception as e:
        app.logger.error(f"API key revocation error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/api-keys/stats')
@login_required 
def api_key_stats():
    """Get API usage statistics"""
    try:
        user = User.query.get(session['user_id'])
        
        # Calculate basic stats (you'd integrate with your analytics system)
        today = datetime.utcnow().date()
        
        # Mock data - replace with actual analytics
        requests_today = random.randint(1000, 2000)
        error_rate = round(random.uniform(0.5, 2.0), 1)
        
        return jsonify({
            'success': True,
            'stats': {
                'requests_today': requests_today,
                'error_rate': error_rate,
                'active_keys': len([k for k in user.api_keys if k.is_active])
            }
        })
    except Exception as e:
        app.logger.error(f"API stats error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        
        # Verify user actually exists in database
        user = User.query.get(session['user_id'])
        if not user:
            flash('Your session is invalid. Please log in again.', 'danger')
            session.clear()
            return redirect(url_for('login'))
            
        # Refresh session to keep it alive
        session.modified = True
        return f(*args, **kwargs)
    return decorated_function
    
def ensure_db_directory():
    """Ensure the database directory exists"""
    try:
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        db_dir = os.path.dirname(db_path)
        
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            print(f"Created database directory: {db_dir}")
        
        # Also ensure the upload directories exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Create static/resumes directory if it doesn't exist
        resumes_dir = 'static/resumes'
        if not os.path.exists(resumes_dir):
            os.makedirs(resumes_dir, exist_ok=True)
            
        print("All directories verified successfully")
        
    except Exception as e:
        print(f"Error creating directories: {e}")
        # Fallback to current directory if there's an issue
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        app.config['UPLOAD_FOLDER'] = 'uploads'
    
    # Also ensure the upload directories exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists('static/resumes'):
        os.makedirs('static/resumes')

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_USERNAME'], to_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def image_to_base64(image_path):
    """Convert image to base64 string for embedding in HTML"""
    try:
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            # Determine the image type from the file extension
            file_extension = image_path.split('.')[-1].lower()
            if file_extension == 'jpg':
                file_extension = 'jpeg'
            return f"data:image/{file_extension};base64,{encoded_string}"
    except Exception as e:
        print(f"Error converting image to base64: {e}")
        return None
    
@app.before_request
def check_subscription_status():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            # Handle canceled subscriptions immediately
            if user.subscription_status == 'canceled' and user.is_premium:
                user.is_premium = False
                # Set subscription end to now if it's in the future
                if user.subscription_end and user.subscription_end > datetime.utcnow():
                    user.subscription_end = datetime.utcnow()
                db.session.commit()
                flash('Your premium subscription has been canceled. Premium features are no longer available.', 'warning')
            
            # Handle expired subscriptions
            elif user.subscription_status == 'active' and user.subscription_end and user.subscription_end < datetime.utcnow():
                user.is_premium = False
                user.subscription_status = 'expired'
                db.session.commit()
                flash('Your premium subscription has expired. Please renew to continue accessing premium features.', 'warning')
            
            # Handle cases where subscription status doesn't match premium status
            elif user.subscription_status != 'active' and user.is_premium:
                user.is_premium = False
                db.session.commit()
                flash('Your premium subscription status has been updated.', 'info')
                
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}
    
@app.context_processor
def utility_processor():
    def is_premium_template(template_name):
        """Check if a template is premium-only"""
        # Handle both template naming formats
        if template_name.isdigit():
            template_num = int(template_name)
        else:
            # Extract number from template_X format
            if template_name.startswith('template_'):
                try:
                    template_num = int(template_name.split('_')[1])
                except (IndexError, ValueError):
                    return False
            else:
                return False
        
        # Premium templates are 7-12
        premium_templates = [7, 8, 9, 10, 11, 12]
        return template_num in premium_templates
    
    return dict(is_premium_template=is_premium_template)

@app.before_request
def check_session():
    if 'user_id' in session:
        print(f"Session user_id: {session['user_id']}")
        print(f"Session keys: {list(session.keys())}")
    
# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/request-magic-link', methods=['POST'])
def request_magic_link():
    """Request a magic link for passwordless login"""
    try:
        email = request.form.get('email')
        
        if not email:
            flash('Please provide an email address.', 'danger')
            return redirect(url_for('login'))
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate a unique token
            token = str(uuid.uuid4())
            
            # Set expiration (15 minutes from now)
            expires_at = datetime.utcnow() + timedelta(minutes=15)
            
            # Create magic link record
            magic_link = MagicLink(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            )
            
            # Invalidate any existing magic links for this user
            MagicLink.query.filter_by(user_id=user.id, used=False).update({'used': True})
            
            db.session.add(magic_link)
            db.session.commit()
            
            # Send email with magic link
            magic_link_url = url_for('login_with_magic_link', token=token, _external=True)
            
            email_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Your ProfileMint Login Link</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333333;
                        margin: 0;
                        padding: 0;
                        background-color: #f7f9fc;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #ffffff;
                        border-radius: 8px;
                        overflow: hidden;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }}
                    .header {{
                        background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
                        padding: 30px 20px;
                        text-align: center;
                        color: white;
                    }}
                    .content {{
                        padding: 30px;
                    }}
                    .button {{
                        display: inline-block;
                        background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
                        color: white;
                        padding: 12px 25px;
                        text-decoration: none;
                        border-radius: 4px;
                        font-weight: bold;
                        margin: 20px 0;
                    }}
                    .footer {{
                        background-color: #f5f5f5;
                        padding: 20px;
                        text-align: center;
                        font-size: 12px;
                        color: #666666;
                    }}
                    .expiry {{
                        color: #e53935;
                        font-weight: bold;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Your Secure Login Link</h2>
                    </div>
                    
                    <div class="content">
                        <p>Hi {user.name},</p>
                        <p>You requested a magic link to login to your ProfileMint account. Click the button below to securely login:</p>
                        
                        <center>
                            <a href="{magic_link_url}" class="button">Login to ProfileMint</a>
                        </center>
                        
                        <p>This link will expire in <span class="expiry">15 minutes</span> for security reasons.</p>
                        
                        <p>If you didn't request this login link, please ignore this email or contact our support team if you have concerns.</p>
                        
                        <p>Best regards,<br>The ProfileMint Team</p>
                    </div>
                    
                    <div class="footer">
                        <p>&copy; 2023 ProfileMint. All rights reserved.</p>
                        <p>This is an automated message, please do not reply to this email.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            if send_email(email, 'Your ProfileMint Login Link', email_body):
                flash('Magic link sent to your email! Check your inbox.', 'success')
            else:
                flash('Failed to send magic link. Please try again.', 'danger')
        else:
            # For security, don't reveal whether email exists
            flash('If an account exists with this email, a magic link has been sent.', 'info')
        
        return redirect(url_for('login'))
        
    except Exception as e:
        app.logger.error(f"Magic link request error: {str(e)}")
        flash('Failed to send magic link. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/login/magic-link/<token>')
def login_with_magic_link(token):
    """Login using a magic link"""
    try:
        magic_link = MagicLink.query.filter_by(token=token, used=False).first()
        
        if not magic_link:
            flash('Invalid or expired login link.', 'danger')
            return redirect(url_for('login'))
        
        if magic_link.expires_at < datetime.utcnow():
            flash('Login link has expired.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.get(magic_link.user_id)
        
        if not user:
            flash('Invalid user account.', 'danger')
            return redirect(url_for('login'))
        
        # Mark magic link as used
        magic_link.used = True
        
        # Check if 2FA is enabled
        if user.two_factor_enabled:
            session['2fa_user_id'] = user.id
            session['2fa_required'] = True
            session.pop('user_id', None)
            flash('Please verify your two-factor authentication code.', 'info')
            return redirect(url_for('verify_2fa_login'))
        
        # Regular login without 2FA
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.name
        session['2fa_verified'] = True
        
        # Record successful login
        record_login_attempt(user.email, True)
        
        db.session.commit()
        
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"Magic link login error: {str(e)}")
        flash('Failed to login with magic link. Please try again.', 'danger')
        return redirect(url_for('login'))

def record_login_attempt(email, success, ip_address=None, user_agent=None):
    """Record a login attempt for security monitoring"""
    if not ip_address:
        ip_address = request.remote_addr
    if not user_agent:
        user_agent = request.headers.get('User-Agent')
    
    login_attempt = LoginAttempt(
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success
    )
    
    # Check for suspicious patterns
    if not success:
        # Check for multiple failed attempts from same IP
        recent_failures = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.created_at > datetime.utcnow() - timedelta(hours=1)
        ).count()
        
        if recent_failures >= 5:
            login_attempt.flagged = True
            login_attempt.reason = "Multiple failed login attempts"
    
    db.session.add(login_attempt)
    db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.password and check_password_hash(user.password, password):
            if not user.verified:
                flash('Please verify your email address before logging in.', 'danger')
                return redirect(url_for('login'))
            
            # Check if 2FA is enabled
            if user.two_factor_enabled:
                # Store user ID in session for 2FA verification
                session['2fa_user_id'] = user.id
                session['2fa_required'] = True
                session.pop('user_id', None)  # Remove regular session
                session.pop('user_email', None)
                session.pop('user_name', None)
                
                flash('Please verify your two-factor authentication code.', 'info')
                return redirect(url_for('verify_2fa_login'))
            
            # Regular login without 2FA
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            session['2fa_verified'] = True  # Mark as verified for this session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

@app.route('/verify-2fa-login', methods=['GET', 'POST'])
def verify_2fa_login():
    """2FA verification page for login"""
    # Check if 2FA is required for this login attempt
    if '2fa_user_id' not in session or not session.get('2fa_required'):
        return redirect(url_for('login'))
    
    user_id = session['2fa_user_id']
    user = User.query.get(user_id)
    
    if not user:
        session.pop('2fa_user_id', None)
        session.pop('2fa_required', None)
        flash('Invalid session. Please login again.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        
        if not code or len(code) != 6:
            flash('Please enter a valid 6-digit code.', 'danger')
            return render_template('verify_2fa.html')
        
        # Verify the code
        totp = pyotp.TOTP(user.two_factor_secret)
        
        if totp.verify(code, valid_window=1):
            # Successful 2FA verification
            session.pop('2fa_user_id', None)
            session.pop('2fa_required', None)
            
            # Set regular session
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            session['2fa_verified'] = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('verify_2fa.html', user=user)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    print(f"Redirect URI: {redirect_uri}")
    print(f"Client ID: {app.config['GOOGLE_CLIENT_ID']}")
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def authorize_google():
    try:
        token = google.authorize_access_token()
        if not token:
            flash('Failed to get access token from Google', 'danger')
            return redirect(url_for('login'))
        
        # Get user info using the token
        resp = google.get('userinfo', token=token)
        if resp.status_code != 200:
            flash(f"Google API error: {resp.status_code}", 'danger')
            return redirect(url_for('login'))
        
        user_info = resp.json()
        
        # Check if user already exists
        user = User.query.filter_by(google_id=user_info['id']).first()
        
        if not user:
            # Check if user exists with email but no Google ID
            user = User.query.filter_by(email=user_info['email']).first()
            if user:
                user.google_id = user_info['id']
            else:
                # Create new user
                user = User(
                    name=user_info['name'],
                    email=user_info['email'],
                    google_id=user_info['id'],
                    password=None,
                    verified=True  # Google users are automatically verified
                )
                db.session.add(user)
        
        db.session.commit()
        
        # Check if 2FA is enabled
        if user.two_factor_enabled:
            session['2fa_user_id'] = user.id
            session['2fa_required'] = True
            flash('Please verify your two-factor authentication code.', 'info')
            return redirect(url_for('verify_2fa_login'))
        
        # Set session variables securely
        session.permanent = True  # Make session persistent
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.name
        session['logged_in'] = True
        session['2fa_verified'] = True
        
        # Commit session changes
        session.modified = True
        
        flash('Login with Google successful!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"Google OAuth error: {str(e)}")
        flash('Failed to login with Google. Please try again.', 'danger')
        return redirect(url_for('login'))
        
# Add this route to test file operations
@app.route('/test-io')
def test_io():
    try:
        # Test database access
        user_count = User.query.count()
        print(f"Users in database: {user_count}")
        
        # Test file upload directory
        test_file = os.path.join(app.config['UPLOAD_FOLDER'], 'test.txt')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        
        return jsonify({'status': 'success', 'users': user_count})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
    
@app.route('/integrations')
@login_required
def integrations():
    user = User.query.get(session['user_id'])
    return render_template('integrations.html', user=user)

@app.route('/connect-google')
@login_required
def connect_google():
    # Redirect to Google OAuth for connection only
    redirect_uri = url_for('authorize_google_integration', _external=True)  # Changed endpoint name
    return google.authorize_redirect(redirect_uri)

@app.route('/connect/google/integration-authorize')
@login_required
def authorize_google_integration():
    try:
        token = google.authorize_access_token()
        if not token:
            flash('Failed to get access token from Google', 'danger')
            return redirect(url_for('integrations'))
        
        user_info = google.get('userinfo').json()
        if 'error' in user_info:
            flash(f"Google API error: {user_info['error']}", 'danger')
            return redirect(url_for('integrations'))
        
        # Get the current user
        user = User.query.get(session['user_id'])
        
        # Update the user's Google connection status
        user.google_connected = True
        # Also store the google_id if it's not already set
        if not user.google_id:
            user.google_id = user_info['id']
        
        db.session.commit()
        
        flash('Google account connected successfully!', 'success')
        return redirect(url_for('settings'))
        
    except Exception as e:
        app.logger.error(f"Google OAuth integration error: {str(e)}")
        flash('Failed to connect Google account. Please try again.', 'danger')
        return redirect(url_for('settings'))

@app.route('/disconnect-integration/<integration_type>', methods=['POST'])
@login_required
def disconnect_integration(integration_type):
    user = User.query.get(session['user_id'])
    
    try:
        if integration_type == 'google':
            user.google_connected = False
            # Don't set google_id to None - keep it for reconnection
            db.session.commit()
            flash('Google integration disconnected successfully!', 'success')
        else:
            flash('Invalid integration type.', 'danger')
    except Exception as e:
        app.logger.error(f"Error disconnecting integration: {str(e)}")
        db.session.rollback()
        flash('Error disconnecting integration. Please try again.', 'danger')
    
    return redirect(url_for('settings'))
    
# Add this function to create styled email templates
def create_otp_email_template(name, otp_code, purpose="registration"):
    if purpose == "registration":
        title = "Welcome to ProfileMint!"
        header = f"Welcome to ProfileMint, {name}!"
        message = "Thank you for registering. Use the OTP below to verify your email address:"
        button_text = "Verify Account"
    else:  # password reset
        title = "ProfileMint - Password Reset OTP"
        header = "Password Reset Request"
        message = "You requested to reset your password. Use the OTP below to verify your identity:"
        button_text = "Reset Password"
    
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333333;
            margin: 0;
            padding: 0;
            background-color: #f7f9fc;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            padding: 30px 20px;
            text-align: center;
            color: white;
        }}
        .logo {{
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #4db6ac;
        }}
        .content {{
            padding: 30px;
        }}
        .otp-container {{
            background-color: #f1f8ff;
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            text-align: center;
            border-left: 4px solid #4db6ac;
        }}
        .otp-code {{
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 5px;
            color: #1a237e;
            margin: 15px 0;
        }}
        .footer {{
            background-color: #f5f5f5;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #666666;
        }}
        .button {{
            display: inline-block;
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            margin: 15px 0;
        }}
        .expiry {{
            color: #e53935;
            font-weight: bold;
        }}
        .support {{
            color: #1a237e;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ProfileMint</div>
            <h2>{header}</h2>
        </div>
        
        <div class="content">
            <p>Hi {name},</p>
            <p>{message}</p>
            
            <div class="otp-container">
                <p>Your verification code is:</p>
                <div class="otp-code">{otp_code}</div>
                <p>Enter this code in the verification page to complete the process.</p>
            </div>
            
            <p>This code will expire in <span class="expiry">10 minutes</span> for security reasons.</p>
            <p>If you didn't request this, please ignore this email or contact our <span class="support">support team</span> if you have concerns.</p>
            
            <p>Best regards,<br>The ProfileMint Team</p>
        </div>
        
        <div class="footer">
            <p>&copy; 2023 ProfileMint. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""

# Add this function to create a welcome email template
def create_welcome_email_template(name):
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to ProfileMint!</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333333;
            margin: 0;
            padding: 0;
            background-color: #f7f9fc;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            padding: 30px 20px;
            text-align: center;
            color: white;
        }}
        .logo {{
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #4db6ac;
        }}
        .content {{
            padding: 30px;
        }}
        .feature {{
            display: flex;
            align-items: center;
            margin: 15px 0;
        }}
        .feature-icon {{
            background-color: #4db6ac;
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
            flex-shrink: 0;
        }}
        .button {{
            display: inline-block;
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .footer {{
            background-color: #f5f5f5;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #666666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ProfileMint</div>
            <h2>Welcome to ProfileMint, {name}!</h2>
        </div>
        
        <div class="content">
            <p>Congratulations! Your account has been successfully verified and created.</p>
            <p>Now you can start creating professional resumes with our easy-to-use platform.</p>
            
            <div class="feature">
                <div class="feature-icon">✓</div>
                <div>Create beautiful, professional resumes in minutes</div>
            </div>
            <div class="feature">
                <div class="feature-icon">✓</div>
                <div>Choose from multiple designer templates</div>
            </div>
            <div class="feature">
                <div class="feature-icon">✓</div>
                <div>Download as PDF or share online</div>
            </div>
            
            <center>
                <a href="#" class="button">Create Your First Resume</a>
            </center>
            
            <p>If you have any questions, feel free to reach out to our support team.</p>
            
            <p>Best regards,<br>The ProfileMint Team</p>
        </div>
        
        <div class="footer">
            <p>&copy; 2023 ProfileMint. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if not name or not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered.', 'danger')
            return render_template('register.html')
        
        # Create new user (not verified yet)
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            verified=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate and send OTP
        otp_code = generate_otp()
        otp_record = OTP(user_id=new_user.id, otp=otp_code)
        db.session.add(otp_record)
        db.session.commit()
        
        # Send email with styled template
        email_body = create_otp_email_template(name, otp_code, "registration")
        if send_email(email, 'Verify Your ProfileMint Account', email_body):
            flash('Registration successful! Please check your email for the verification code.', 'success')
            session['temp_user_id'] = new_user.id
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send verification email. Please try again.', 'danger')
            # Clean up the user record if email fails
            db.session.delete(new_user)
            db.session.commit()
    
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user_id' not in session:
        flash('Please register first.', 'danger')
        return redirect(url_for('register'))
    
    user_id = session['temp_user_id']
    user = User.query.get(user_id)
    
    if not user:
        flash('Invalid session. Please register again.', 'danger')
        session.pop('temp_user_id', None)
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp')
        
        # Find the most recent OTP for this user
        otp_record = OTP.query.filter_by(user_id=user_id, used=False).order_by(OTP.created_at.desc()).first()
        
        if otp_record and otp_record.otp == otp_code:
            # Check if OTP is not expired (10 minutes)
            time_diff = datetime.utcnow() - otp_record.created_at
            if time_diff.total_seconds() <= 600:  # 10 minutes
                # Mark OTP as used and verify user
                otp_record.used = True
                user.verified = True
                db.session.commit()
                
                # Send welcome email
                welcome_email = create_welcome_email_template(user.name)
                send_email(user.email, 'Welcome to ProfileMint!', welcome_email)
                
                session.pop('temp_user_id', None)
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('OTP has expired. Please request a new one.', 'danger')
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('verify_otp.html', email=user.email)

@app.route('/resend-otp')
def resend_otp():
    if 'temp_user_id' not in session:
        flash('Please register first.', 'danger')
        return redirect(url_for('register'))
    
    user_id = session['temp_user_id']
    user = User.query.get(user_id)
    
    if not user:
        flash('Invalid session. Please register again.', 'danger')
        session.pop('temp_user_id', None)
        return redirect(url_for('register'))
    
    # Generate new OTP
    otp_code = generate_otp()
    otp_record = OTP(user_id=user.id, otp=otp_code)
    db.session.add(otp_record)
    db.session.commit()
    
    # Resend email with styled template
    email_body = create_otp_email_template(user.name, otp_code, "registration")
    if send_email(user.email, 'Your New Verification Code', email_body):
        flash('New verification code sent to your email.', 'success')
    else:
        flash('Failed to send verification email. Please try again.', 'danger')
    
    return redirect(url_for('verify_otp'))

@app.route('/pricing')
@login_required
def pricing():
    user = User.query.get(session['user_id'])
    return render_template('pricing.html', user=user)

@app.route('/create-mock-order', methods=['POST'])
@login_required
def create_mock_order():
    """Create a mock order for testing"""
    try:
        return jsonify({
            'order_id': f'mock_order_{datetime.now().strftime("%Y%m%d%H%M%S")}',
            'amount': 29900,
            'currency': 'INR',
            'success': True
        })
    except Exception as e:
        app.logger.error(f"Mock order creation error: {str(e)}")
        return jsonify({'error': 'Failed to create order'}), 500

SUBSCRIPTION_PLANS = {
    'free_trial': {
        'name': '1 Day Free Trial',
        'price_inr': 0,
        'price_usd': 0,
        'duration_days': 1,
        'features': ['All premium features', '1 day access', 'Cancel anytime']
    },
    'weekly': {
        'name': '1 Week Premium',
        'price_inr': 99,
        'price_usd': 1.99,
        'duration_days': 7,
        'features': ['All premium templates', 'Unlimited downloads', 'Priority support']
    },
    'monthly': {
        'name': '1 Month Premium',
        'price_inr': 299,
        'price_usd': 5.99,
        'duration_days': 30,
        'features': ['All premium templates', 'Unlimited downloads', 'Priority support']
    },
    'semiannual': {
        'name': '6 Months Premium',
        'price_inr': 1499,
        'price_usd': 24.99,
        'duration_days': 180,
        'features': ['All premium templates', 'Unlimited downloads', 'Priority support', '40% discount']
    },
    'annual': {
        'name': '1 Year Premium',
        'price_inr': 2499,
        'price_usd': 39.99,
        'duration_days': 365,
        'features': ['All premium templates', 'Unlimited downloads', 'Priority support', '60% discount']
    }
}

@app.route('/verify-mock-payment/<plan_type>', methods=['POST'])
@login_required
def verify_mock_payment(plan_type):
    """Mock payment verification for different subscription plans"""
    try:
        if plan_type not in SUBSCRIPTION_PLANS:
            return jsonify({'success': False, 'error': 'Invalid plan type'}), 400
        
        plan = SUBSCRIPTION_PLANS[plan_type]
        
        # Update user subscription status
        user = User.query.get(session['user_id'])
        user.is_premium = True
        user.subscription_status = 'active'
        user.subscription_start = datetime.utcnow()
        
        if plan_type == 'free_trial':
            # For free trial, set end date to 1 day from now
            user.subscription_end = datetime.utcnow() + timedelta(days=1)
            user.subscription_status = 'trial'
        else:
            user.subscription_end = datetime.utcnow() + timedelta(days=plan['duration_days'])
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'{plan["name"]} activated successfully!',
            'plan': plan['name']
        })
    except Exception as e:
        app.logger.error(f"Mock payment verification error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/cancel-subscription', methods=['GET', 'POST'])
@login_required
def cancel_subscription():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        try:

            user.is_premium = False
            user.subscription_status = 'canceled'
            user.subscription_end = datetime.utcnow()
            db.session.commit()
            
            flash('Your subscription has been canceled successfully. Premium features are no longer available.', 'success')
            return redirect(url_for('account'))
        except Exception as e:
            app.logger.error(f"Subscription cancellation error: {str(e)}")
            db.session.rollback()
            flash('Failed to cancel subscription. Please try again.', 'danger')
    
    return render_template('cancel_subscription.html', user=user)

@app.route('/api/cancel-subscription', methods=['POST'])
@login_required
def api_cancel_subscription():
    try:
        user = User.query.get(session['user_id'])
        
        if not user.is_premium:
            return jsonify({'success': False, 'error': 'No active subscription found'})
        
        # Update user subscription status - immediately revoke access
        user.is_premium = False
        user.subscription_status = 'canceled'
        user.subscription_end = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Subscription canceled successfully. Premium features are no longer available.'})
    except Exception as e:
        app.logger.error(f"API Subscription cancellation error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})
        
@app.route('/sync-subscription-status')
@login_required
def sync_subscription_status():
    """Force synchronization of subscription status"""
    user = User.query.get(session['user_id'])
    original_status = {
        'is_premium': user.is_premium,
        'subscription_status': user.subscription_status
    }
    
    # Re-run the subscription status check
    if user.subscription_status == 'canceled' and user.is_premium:
        user.is_premium = False
        if user.subscription_end and user.subscription_end > datetime.utcnow():
            user.subscription_end = datetime.utcnow()
    
    elif user.subscription_status == 'active' and user.subscription_end and user.subscription_end < datetime.utcnow():
        user.is_premium = False
        user.subscription_status = 'expired'
    
    elif user.subscription_status != 'active' and user.is_premium:
        user.is_premium = False
    
    db.session.commit()
    
    # Check if status changed
    status_changed = (
        original_status['is_premium'] != user.is_premium or
        original_status['subscription_status'] != user.subscription_status
    )
    
    if status_changed:
        flash('Subscription status has been synchronized.', 'success')
    else:
        flash('Subscription status is already up to date.', 'info')
    
    return redirect(url_for('account'))

@app.route('/dashboard')
@login_required
@two_factor_verified
def dashboard():
    user = User.query.get(session['user_id'])
    resumes = Resume.query.filter_by(user_id=user.id).order_by(Resume.updated_at.desc()).all()
    resume_count = len(resumes)
    return render_template('dashboard.html', user=user, resumes=resumes, resume_count=resume_count)

# Apply @two_factor_verified to other protected routes as needed
@app.route('/my-resumes')
@login_required
@two_factor_verified
def my_resumes():
    user = User.query.get(session['user_id'])
    resumes = Resume.query.filter_by(user_id=user.id).order_by(Resume.updated_at.desc()).all()
    return render_template('my_resumes.html', user=user, resumes=resumes)

@app.route('/create-resume', methods=['GET', 'POST'])
@login_required
def create_resume():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        title = request.form.get('title')
        template = request.form.get('template', 'template1')
        
        # Check if user is trying to use a premium template without access
        if is_premium_template(template) and not can_access_template(user, template):
            flash('This template is only available for premium users. Upgrade your account to access premium templates.', 'danger')
            return redirect(url_for('pricing'))
        
        if not title:
            flash('Please enter a title for your resume.', 'danger')
            return render_template('create_resume.html', 
                                 user=user,
                                 available_templates=get_available_templates(user))
        
        # Create a new resume with basic structure
        resume_data = {
            "personal_info": {
                "name": request.form.get('name', ''),
                "email": request.form.get('email', ''),
                "phone": request.form.get('phone', ''),
                "address": request.form.get('address', ''),
                "linkedin": request.form.get('linkedin', ''),
                "website": request.form.get('website', '')
            },
            "summary": request.form.get('summary', ''),
            "experience": [],
            "education": [],
            "skills": [],
            "projects": [],
            "languages": [],
            "certifications": []
        }
        
        # Handle photo upload during creation
        photo_filename = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user.id}_{int(datetime.utcnow().timestamp())}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                photo_filename = filename
        
        # Process experience data
        exp_count = int(request.form.get('exp_count', 0))
        for i in range(exp_count):
            if f'exp_company_{i+1}' in request.form:
                experience = {
                    'company': request.form[f'exp_company_{i+1}'],
                    'position': request.form[f'exp_position_{i+1}'],
                    'start_date': request.form.get(f'exp_start_{i+1}', ''),
                    'end_date': request.form.get(f'exp_end_{i+1}', ''),
                    'current': f'exp_current_{i+1}' in request.form,
                    'description': request.form.get(f'exp_description_{i+1}', '')
                }
                resume_data['experience'].append(experience)
        
        # Process education data
        edu_count = int(request.form.get('edu_count', 0))
        for i in range(edu_count):
            if f'edu_institution_{i+1}' in request.form:
                education = {
                    'institution': request.form[f'edu_institution_{i+1}'],
                    'degree': request.form[f'edu_degree_{i+1}'],
                    'field': request.form.get(f'edu_field_{i+1}', ''),
                    'start_date': request.form.get(f'edu_start_{i+1}', ''),
                    'end_date': request.form.get(f'edu_end_{i+1}', ''),
                    'current': f'edu_current_{i+1}' in request.form,
                    'description': request.form.get(f'edu_description_{i+1}', '')
                }
                resume_data['education'].append(education)
        
        # Process skills
        if 'skills' in request.form and request.form['skills']:
            skills = request.form['skills'].split(',')
            resume_data['skills'] = [skill.strip() for skill in skills if skill.strip()]
        
        new_resume = Resume(
            user_id=session['user_id'],
            title=title,
            template=template,
            data=json.dumps(resume_data),
            photo=photo_filename
        )
        
        db.session.add(new_resume)
        db.session.commit()
        
        flash('Resume created successfully!', 'success')
        return redirect(url_for('my_resumes'))
    
    return render_template('create_resume.html', 
                         user=user,
                         available_templates=get_available_templates(user))


@app.route('/edit-resume/<int:resume_id>', methods=['GET', 'POST'])
@login_required
def edit_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    user = User.query.get(session['user_id'])
    
    # Check if the resume belongs to the current user
    if resume.user_id != session['user_id']:
        flash('You do not have permission to edit this resume.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Parse the resume data properly
    try:
        resume_data = json.loads(resume.data) if resume.data else {}
    except json.JSONDecodeError:
        resume_data = {
            "personal_info": {
                "name": "", "email": "", "phone": "", "address": "",
                "linkedin": "", "website": ""
            },
            "summary": "",
            "experience": [],
            "education": [],
            "skills": [],
            "projects": [],
            "languages": [],
            "certifications": []
        }
    
    # Check if user is trying to access a premium template without access
    if is_premium_template(resume.template) and not can_access_template(user, resume.template):
        flash('This template is only available for premium users. Upgrade your account to access premium templates.', 'danger')
        return redirect(url_for('pricing'))
    
    if request.method == 'POST':
        # Handle photo upload
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{resume_id}_{int(datetime.utcnow().timestamp())}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Delete old photo if it exists
                if resume.photo:
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                
                resume.photo = filename
        
        # Update resume title
        if 'title' in request.form:
            resume.title = request.form['title']
        
        # Update resume data
        resume_data = {
            "personal_info": {
                "name": request.form.get('name', ''),
                "email": request.form.get('email', ''),
                "phone": request.form.get('phone', ''),
                "address": request.form.get('address', ''),
                "linkedin": request.form.get('linkedin', ''),
                "website": request.form.get('website', '')
            },
            "summary": request.form.get('summary', ''),
            "experience": [],
            "education": [],
            "skills": [],
            "projects": [],
            "languages": [],
            "certifications": []
        }
        
        # Handle experience
        exp_count = int(request.form.get('exp_count', 0))
        for i in range(1, exp_count + 1):
            if f'exp_company_{i}' in request.form:
                experience = {
                    'company': request.form[f'exp_company_{i}'],
                    'position': request.form[f'exp_position_{i}'],
                    'start_date': request.form.get(f'exp_start_{i}', ''),
                    'end_date': request.form.get(f'exp_end_{i}', ''),
                    'current': f'exp_current_{i}' in request.form,
                    'description': request.form.get(f'exp_description_{i}', '')
                }
                resume_data['experience'].append(experience)
        
        # Handle education
        edu_count = int(request.form.get('edu_count', 0))
        for i in range(1, edu_count + 1):
            if f'edu_institution_{i}' in request.form:
                education = {
                    'institution': request.form[f'edu_institution_{i}'],
                    'degree': request.form[f'edu_degree_{i}'],
                    'field': request.form.get(f'edu_field_{i}', ''),
                    'start_date': request.form.get(f'edu_start_{i}', ''),
                    'end_date': request.form.get(f'edu_end_{i}', ''),
                    'current': f'edu_current_{i}' in request.form,
                    'description': request.form.get(f'edu_description_{i}', '')
                }
                resume_data['education'].append(education)
        
        # Handle skills
        if 'skills' in request.form:
            skills = request.form['skills'].split(',')
            resume_data['skills'] = [skill.strip() for skill in skills if skill.strip()]
        
        # Update template if changed
        if 'template' in request.form:
            new_template = request.form['template']
            # Check if user is trying to switch to a premium template without access
            if is_premium_template(new_template) and not can_access_template(user, new_template):
                flash('This template is only available for premium users. Upgrade your account to access premium templates.', 'danger')
                return redirect(url_for('pricing'))
            resume.template = new_template
        
        # Save updated data
        resume.data = json.dumps(resume_data)
        resume.updated_at = datetime.utcnow()
        db.session.commit()
        
        flash('Resume updated successfully!', 'success')
        return redirect(url_for('my_resumes'))
    
    # For GET request, populate the form with existing data
    resume_data = resume.data_dict
    photo_url = url_for('uploaded_file', filename=resume.photo) if resume.photo else None
    
    return render_template('edit_resume.html', 
                         resume=resume, 
                         resume_data=resume_data,
                         photo_url=photo_url,
                         user=user,
                         available_templates=get_available_templates(user))


@app.route('/view-resume/<int:resume_id>')
def view_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if user owns the resume or if it's public
    if 'user_id' not in session or resume.user_id != session['user_id']:
        if not resume.is_public:
            flash('You do not have permission to view this resume.', 'danger')
            return redirect(url_for('index'))
        # For public resumes, use the share view
        return redirect(url_for('share_resume', resume_id=resume_id))
    
    user = User.query.get(session['user_id'])
    
    # Check if user is trying to access a premium template without access
    if is_premium_template(resume.template) and not can_access_template(user, resume.template):
        flash('This template is only available for premium users with an active subscription.', 'danger')
        return redirect(url_for('pricing'))
    
    # Convert photo to base64 if it exists
    photo_data = None
    if resume.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
        photo_data = image_to_base64(photo_path)
    
    # Parse the resume data
    try:
        resume_data = json.loads(resume.data) if resume.data else {}
    except json.JSONDecodeError:
        resume_data = {}
    
    # Determine template name
    if resume.template.isdigit():
        template_name = f"resume_templates/template_{resume.template}.html"
    else:
        template_name = f"resume_templates/{resume.template}.html"
    
    return render_template(template_name, 
                         resume=resume, 
                         resume_data=resume_data,
                         base64_photo=photo_data)

# Add this route after the existing routes
@app.route('/api/set-resume-visibility/<int:resume_id>', methods=['POST'])
@login_required
def set_resume_visibility(resume_id):
    """Set whether a resume is publicly accessible"""
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if the resume belongs to the current user
    if resume.user_id != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    resume.is_public = data.get('is_public', False)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/share-resume/<int:resume_id>')
def share_resume(resume_id):
    """Publicly accessible resume view for sharing"""
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if resume is public or user owns it
    if not resume.is_public and ('user_id' not in session or resume.user_id != session['user_id']):
        flash('This resume is not publicly accessible.', 'danger')
        return redirect(url_for('index'))
    
    # Convert photo to base64 if it exists
    photo_data = None
    if resume.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
        photo_data = image_to_base64(photo_path)
    
    # Parse the resume data
    try:
        resume_data = json.loads(resume.data) if resume.data else {}
    except json.JSONDecodeError:
        resume_data = {}
    
    # Determine template name
    if resume.template.isdigit():
        template_name = f"resume_templates/template_{resume.template}.html"
    else:
        template_name = f"resume_templates/{resume.template}.html"
    
    return render_template('edit_resume.html', 
                     resume=resume, 
                     resume_data=resume_data,
                     photo_url=photo_url,
                     user=user,  # Change this line
                     available_templates=get_available_templates(user))
                         
@app.route('/debug-resume/<int:resume_id>')
@login_required
def debug_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    if resume.user_id != session['user_id']:
        return "Unauthorized", 403
    
    return jsonify({
        'resume_data': resume.data_dict,
        'raw_data': resume.data,
        'template': resume.template
    })

@app.route('/preview-resume/<int:resume_id>')
@login_required
def preview_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if the resume belongs to the current user
    if resume.user_id != session['user_id']:
        flash('You do not have permission to view this resume.', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get(session['user_id'])
    
    # Check if user is trying to access a premium template without access
    if is_premium_template(resume.template) and not can_access_template(user, resume.template):
        flash('This template is only available for premium users with an active subscription.', 'danger')
        return redirect(url_for('pricing'))
    
    # Convert photo to base64 if it exists
    photo_data = None
    if resume.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
        photo_data = image_to_base64(photo_path)
    
    # Parse the resume data
    try:
        resume_data = json.loads(resume.data) if resume.data else {}
    except json.JSONDecodeError:
        resume_data = {}
    
    # Determine template name
    if resume.template.isdigit():
        template_name = f"resume_templates/template_{resume.template}.html"
    else:
        template_name = f"resume_templates/{resume.template}.html"
    
    return render_template(template_name, 
                         resume=resume, 
                         resume_data=resume_data,
                         base64_photo=photo_data)

@app.route('/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    user = User.query.get(session['user_id'])
    if 'avatar' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['avatar']
    if file and allowed_file(file.filename):
        # Get file extension
        file_ext = os.path.splitext(file.filename)[1]
        # Create secure filename with user ID and proper extension
        filename = secure_filename(f"user_{user.id}_avatar{file_ext}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Delete old avatar if it exists
        if user.profile_picture:
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
            if os.path.exists(old_path):
                os.remove(old_path)

        user.profile_picture = filename
        db.session.commit()
        flash('Avatar uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Please upload an image.', 'danger')

    return redirect(url_for('profile'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        # Return a default avatar or 404 if the file doesn't exist
        return send_from_directory('static', 'img/default-avatar.png')
        
@app.route('/download-resume/<int:resume_id>', methods=['GET', 'POST'])
@login_required
def download_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if the resume belongs to the current user
    if resume.user_id != session['user_id']:
        flash('You do not have permission to download this resume.', 'danger')
        return redirect(url_for('dashboard'))
    
    # For POST requests, generate and return the PDF
    if request.method == 'POST':
        try:
            return generate_download(resume_id, 'pdf')
        except Exception as e:
            app.logger.error(f"Download error: {str(e)}")
            flash('Failed to generate download. Please try again.', 'danger')
            return redirect(url_for('view_resume', resume_id=resume_id))
    
    # For GET requests, show the download options page
    return render_template('download_options.html', resume=resume)

def generate_download(resume_id, format_type):
    resume = Resume.query.get_or_404(resume_id)
    user = User.query.get(session['user_id'])
    
    # Check if the resume belongs to the current user
    if resume.user_id != session['user_id']:
        flash('You do not have permission to download this resume.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Parse resume data
    try:
        resume_data = json.loads(resume.data) if resume.data else {}
    except json.JSONDecodeError:
        resume_data = {}
    
    # Generate filename
    filename = f"{resume.title.replace(' ', '_')}_resume"
    
    # Only PDF format is supported now
    if format_type == 'pdf':
        # Convert photo to base64 if it exists for PDF
        photo_data = None
        if resume.photo:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
            photo_data = image_to_base64(photo_path)
        
        # Render the resume HTML for PDF
        try:
            if resume.template.isdigit():
                template_name = f"resume_templates/template_{resume.template}.html"
            else:
                template_name = f"resume_templates/{resume.template}.html"
                
            html_content = render_template(template_name, 
                                 resume=resume, 
                                 resume_data=resume_data,
                                 base64_photo=photo_data,
                                 for_pdf=True)
            
            # Generate PDF using WeasyPrint
            pdf = HTML(string=html_content).write_pdf()
            
            # Create a BytesIO object to hold the PDF in memory
            pdf_buffer = BytesIO()
            pdf_buffer.write(pdf)
            pdf_buffer.seek(0)
            
            # Send file for download directly from memory
            response = send_file(
                pdf_buffer, 
                as_attachment=True, 
                download_name=f"{filename}.pdf",
                mimetype='application/pdf'
            )
            
        except Exception as e:
            app.logger.error(f"PDF generation error: {str(e)}")
            flash('Failed to generate PDF. Please try again.', 'danger')
            return redirect(url_for('view_resume', resume_id=resume_id))
            
    else:
        flash('Invalid format selected.', 'danger')
        return redirect(url_for('view_resume', resume_id=resume_id))
    
    return response
    
@app.route('/delete-resume/<int:resume_id>')
@login_required
def delete_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if the resume belongs to the current user
    if resume.user_id != session['user_id']:
        flash('You do not have permission to delete this resume.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Delete associated photo if it exists
    if resume.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
        if os.path.exists(photo_path):
            os.remove(photo_path)
    
    db.session.delete(resume)
    db.session.commit()
    
    flash('Resume deleted successfully!', 'success')
    return redirect(url_for('my_resumes'))

def can_access_template(user, template_name):
    """Check if user can access the given template"""
    if not is_premium_template(template_name):
        return True
    return user.is_premium and user.subscription_status == 'active'

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        name = request.form.get('name')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Update name
        if name and name != user.name:
            user.name = name
            session['user_name'] = name
        
        # Update password if provided
        if current_password and new_password:
            if not user.password or check_password_hash(user.password, current_password):
                if new_password == confirm_password:
                    user.password = generate_password_hash(new_password)
                    flash('Password updated successfully!', 'success')
                else:
                    flash('New passwords do not match.', 'danger')
            else:
                flash('Current password is incorrect.', 'danger')
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{user.id}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Delete old profile picture if it exists
                if user.profile_picture:
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                
                user.profile_picture = filename
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# Add this route after the profile route
@app.route('/account')
@login_required
def account():
    user = User.query.get(session['user_id'])
    return render_template('account.html', user=user)

# Add this route after the account route
@app.route('/settings')
@login_required
def settings():
    user = User.query.get(session['user_id'])
    return render_template('settings.html', user=user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate OTP
            otp_code = generate_otp()
            otp_record = OTP(user_id=user.id, otp=otp_code)
            db.session.add(otp_record)
            db.session.commit()
            
            # Send email with styled template
            email_body = create_otp_email_template(user.name, otp_code, "password_reset")
            if send_email(email, 'Password Reset Request', email_body):
                session['reset_user_id'] = user.id
                flash('Password reset instructions sent to your email.', 'success')
                return redirect(url_for('reset_password'))
            else:
                flash('Failed to send reset email. Please try again.', 'danger')
        else:
            flash('No account found with that email address.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user_id' not in session:
        flash('Please request a password reset first.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user_id = session['reset_user_id']
    user = User.query.get(user_id)
    
    if not user:
        flash('Invalid session. Please request a new password reset.', 'danger')
        session.pop('reset_user_id', None)
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Find the most recent OTP for this user
        otp_record = OTP.query.filter_by(user_id=user_id, used=False).order_by(OTP.created_at.desc()).first()
        
        if otp_record and otp_record.otp == otp_code:
            # Check if OTP is not expired (10 minutes)
            time_diff = datetime.utcnow() - otp_record.created_at
            if time_diff.total_seconds() <= 600:  # 10 minutes
                if new_password == confirm_password:
                    # Update password
                    user.password = generate_password_hash(new_password)
                    otp_record.used = True
                    db.session.commit()
                    
                    session.pop('reset_user_id', None)
                    flash('Password reset successfully! You can now log in.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Passwords do not match.', 'danger')
            else:
                flash('OTP has expired. Please request a new one.', 'danger')
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('reset_password.html', email=user.email)

@app.route('/logout')
def logout():
    # Clear all session variables
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))
    
@app.route('/generate-api-key', methods=['POST'])
@login_required
def generate_api_key():
    """Generate a new API key for the user"""
    try:
        user = User.query.get(session['user_id'])
        
        # Generate a secure API key
        api_key = secrets.token_urlsafe(32)

        return jsonify({
            'success': True,
            'api_key': api_key,
            'message': 'API key generated successfully. Store it securely as it will not be shown again.'
        })
        
    except Exception as e:
        app.logger.error(f"API key generation error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to generate API key'}), 500

@app.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Initialize 2FA setup by generating a secret"""
    try:
        user = User.query.get(session['user_id'])
        
        # Generate a new secret
        user.two_factor_secret = pyotp.random_base32()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]
        user.two_factor_backup_codes = json.dumps(backup_codes)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'secret': user.two_factor_secret,
            'backup_codes': backup_codes
        })
        
    except Exception as e:
        app.logger.error(f"2FA enable error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to enable 2FA'}), 500

@app.route('/generate-2fa-qr')
@login_required
def generate_2fa_qr():
    """Generate QR code for 2FA setup"""
    try:
        user = User.query.get(session['user_id'])
        
        if not user.two_factor_secret:
            return jsonify({'success': False, 'error': 'No 2FA secret found'}), 400
        
        # Generate provisioning URI
        totp = pyotp.TOTP(user.two_factor_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="ProfileMint"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return jsonify({
            'success': True,
            'qr_code': f"data:image/png;base64,{qr_code_base64}",
            'provisioning_uri': provisioning_uri
        })
        
    except Exception as e:
        app.logger.error(f"QR generation error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to generate QR code'}), 500
        
@app.route('/generate-backup-codes')
@login_required
def generate_backup_codes():
    """Generate new 2FA backup codes"""
    try:
        user = User.query.get(session['user_id'])
        
        # Generate 10 backup codes (8-character alphanumeric)
        backup_codes = [''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=8)) 
                       for _ in range(10)]
        
        user.two_factor_backup_codes = json.dumps(backup_codes)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'backup_codes': backup_codes,
            'message': 'New backup codes generated successfully'
        })
    except Exception as e:
        app.logger.error(f"Backup code generation error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
        
@app.route('/verify-backup-code', methods=['POST'])
@login_required
def verify_backup_code():
    """Verify 2FA backup code"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        backup_code = data.get('backup_code', '').strip().upper()
        
        if not user.two_factor_backup_codes:
            return jsonify({'success': False, 'error': 'No backup codes available'}), 400
        
        try:
            backup_codes = json.loads(user.two_factor_backup_codes)
        except json.JSONDecodeError:
            return jsonify({'success': False, 'error': 'Invalid backup codes format'}), 400
        
        if backup_code in backup_codes:
            # Remove the used backup code
            backup_codes.remove(backup_code)
            user.two_factor_backup_codes = json.dumps(backup_codes)
            db.session.commit()
            
            # Set session flag to indicate 2FA verification passed
            session['2fa_verified'] = True
            return jsonify({'success': True, 'message': 'Backup code accepted'})
        else:
            return jsonify({'success': False, 'error': 'Invalid backup code'}), 400
            
    except Exception as e:
        app.logger.error(f"Backup code verification error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/verify-2fa', methods=['POST'])
@login_required
def verify_2fa_code():
    """Verify the 2FA code and enable 2FA"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        code = data.get('code')
        
        if not user.two_factor_secret:
            return jsonify({'success': False, 'error': 'No 2FA secret found'}), 400
        
        if not code or len(code) != 6:
            return jsonify({'success': False, 'error': 'Invalid code format'}), 400
        
        # Verify the code
        totp = pyotp.TOTP(user.two_factor_secret)
        
        if totp.verify(code, valid_window=1):  # Allow 30-second window
            # Enable 2FA
            user.two_factor_enabled = True
            db.session.commit()
            
            return jsonify({'success': True, 'message': '2FA enabled successfully!'})
        else:
            return jsonify({'success': False, 'error': 'Invalid verification code'}), 400
            
    except Exception as e:
        app.logger.error(f"2FA verification error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to verify 2FA code'}), 500

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa_backend():
    """Disable 2FA for the user"""
    try:
        user = User.query.get(session['user_id'])
        
        user.two_factor_enabled = False
        user.two_factor_secret = None
        user.two_factor_backup_codes = None
        db.session.commit()
        
        return jsonify({'success': True, 'message': '2FA disabled successfully'})
        
    except Exception as e:
        app.logger.error(f"2FA disable error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to disable 2FA'}), 500
    
# Add these routes after your existing 2FA routes

@app.route('/api/regenerate-backup-codes', methods=['POST'])
@login_required
def regenerate_backup_codes():
    """Generate new 2FA backup codes and invalidate old ones"""
    try:
        user = User.query.get(session['user_id'])
        
        if not user.two_factor_enabled:
            return jsonify({'success': False, 'error': '2FA is not enabled'}), 400
        
        # Generate 10 new backup codes (8-character alphanumeric)
        backup_codes = [''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=8)) 
                       for _ in range(10)]
        
        user.two_factor_backup_codes = json.dumps(backup_codes)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'backup_codes': backup_codes,
            'message': 'New backup codes generated successfully. Old codes are no longer valid.'
        })
    except Exception as e:
        app.logger.error(f"Backup code regeneration error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/download-backup-codes')
@login_required
def download_backup_codes():
    """Download backup codes as a text file"""
    try:
        user = User.query.get(session['user_id'])
        
        if not user.two_factor_enabled or not user.two_factor_backup_codes:
            flash('No backup codes available', 'danger')
            return redirect(url_for('settings'))
        
        backup_codes = json.loads(user.two_factor_backup_codes)
        codes_text = "ProfileMint 2FA Backup Codes\n"
        codes_text += "============================\n\n"
        codes_text += "Store these codes in a secure place. Each code can be used once.\n\n"
        
        for i, code in enumerate(backup_codes, 1):
            codes_text += f"{i}. {code}\n"
        
        codes_text += "\nGenerated on: " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Create in-memory file
        buffer = BytesIO()
        buffer.write(codes_text.encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name='profilemint_backup_codes.txt',
            mimetype='text/plain'
        )
        
    except Exception as e:
        app.logger.error(f"Backup code download error: {str(e)}")
        flash('Failed to download backup codes', 'danger')
        return redirect(url_for('settings'))

@app.route('/api/update-2fa-settings', methods=['POST'])
@login_required
def update_2fa_settings():
    """Update 2FA-related settings"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        # Update login alerts preference
        if 'login_alerts' in data:
            # Store in user preferences - you might need to add a preferences field to User model
            pass
        
        # Update device remembering preference
        if 'remember_devices' in data:
            # Store in user preferences
            pass
            
        # Update IP allowlist
        if 'ip_whitelist' in data:
            # Store in user preferences
            pass
        
        db.session.commit()
        return jsonify({'success': True, 'message': '2FA settings updated successfully'})
        
    except Exception as e:
        app.logger.error(f"2FA settings update error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Permanently delete user account and all associated data"""
    try:
        user = User.query.get(session['user_id'])
        
        # Delete all user's resumes and associated files
        resumes = Resume.query.filter_by(user_id=user.id).all()
        for resume in resumes:
            # Delete resume photo if it exists
            if resume.photo:
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.photo)
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            db.session.delete(resume)
        
        # Delete user's OTP records
        otp_records = OTP.query.filter_by(user_id=user.id).all()
        for otp in otp_records:
            db.session.delete(otp)
        
        # Delete user's profile picture if it exists
        if user.profile_picture:
            profile_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
            if os.path.exists(profile_path):
                os.remove(profile_path)
        
        # Delete the user account
        db.session.delete(user)
        db.session.commit()
        
        # Clear session
        session.clear()
        
        return jsonify({
            'success': True,
            'message': 'Your account has been permanently deleted.'
        })
        
    except Exception as e:
        app.logger.error(f"Account deletion error: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Failed to delete account. Please try again.'
        }), 500
    
# In app.py, update the can_access_template function
def can_access_template(user, template_name):
    """Check if user can access the given template"""
    if not is_premium_template(template_name):
        return True
    return user.is_premium and user.subscription_status == 'active'

@app.route('/contact-support')
def contact_support():
    return render_template('contact_support.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
@app.route('/about')
def about():
    return render_template('about.html')

# API endpoints for AJAX operations
@app.route('/api/add-experience/<int:resume_id>', methods=['POST'])
@login_required
def api_add_experience(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    if resume.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    experience_data = request.json
    resume_data = resume.data_dict
    
    resume_data['experience'].append(experience_data)
    resume.data = json.dumps(resume_data)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/remove-experience/<int:resume_id>/<int:index>', methods=['POST'])
@login_required
def api_remove_experience(resume_id, index):
    resume = Resume.query.get_or_404(resume_id)
    
    if resume.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    resume_data = resume.data_dict
    
    if 0 <= index < len(resume_data['experience']):
        resume_data['experience'].pop(index)
        resume.data = json.dumps(resume_data)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid index'}), 400

@app.route('/api/integrations', methods=['GET'])
@login_required
def get_integrations():
    """Get all integrations for the user"""
    try:
        user = User.query.get(session['user_id'])
        
        # For now, we'll return static data about integrations
        # In a real app, you'd have an Integration model
        
        integrations = [
            {
                'id': 'google',
                'name': 'Google',
                'connected': bool(user.google_id),
                'icon': 'fab fa-google',
                'color': 'text-danger',
                'description': 'Connect for authentication & calendar sync'
            },
            {
                'id': 'linkedin',
                'name': 'LinkedIn',
                'connected': False,  # You'd track this in your database
                'icon': 'fab fa-linkedin',
                'color': 'text-primary',
                'description': 'Import your LinkedIn profile data'
            },
            {
                'id': 'dropbox',
                'name': 'Dropbox',
                'connected': False,
                'icon': 'fab fa-dropbox',
                'color': 'text-primary',
                'description': 'Save resumes to your Dropbox'
            },
            {
                'id': 'slack',
                'name': 'Slack',
                'connected': False,
                'icon': 'fab fa-slack',
                'color': 'text-warning',
                'description': 'Get notifications in Slack'
            }
        ]
        
        return jsonify({'success': True, 'integrations': integrations})
    except Exception as e:
        app.logger.error(f"Integrations fetch error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/integrations/<integration_id>', methods=['POST'])
@login_required
def connect_integration(integration_id):
    """Connect an integration"""
    try:
        user = User.query.get(session['user_id'])
        
        # Handle different integration types
        if integration_id == 'google':
            # Redirect to Google OAuth
            redirect_uri = url_for('authorize_google_integration', _external=True)
            return jsonify({'success': True, 'redirect_url': '/connect-google'})
        else:
            # For other integrations, you'd have similar OAuth flows
            return jsonify({'success': False, 'error': 'Integration not available'}), 400
            
    except Exception as e:
        app.logger.error(f"Integration connection error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/integrations/<integration_id>', methods=['DELETE'])
@login_required
def api_disconnect_integration(integration_id):
    user = User.query.get(session['user_id'])
    try:
        if integration_id == 'google':
            user.google_connected = False
            db.session.commit()
            return jsonify({'success': True, 'message': 'Google integration disconnected successfully!'})
        else:
            return jsonify({'success': False, 'error': 'Invalid integration type'}), 400
    except Exception as e:
        app.logger.error(f"Error disconnecting integration: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Error disconnecting integration'}), 500


@app.route('/api/integrations/stats')
@login_required
def integration_stats():
    """Get integration usage statistics"""
    try:
        user = User.query.get(session['user_id'])
        
        # Mock data - replace with actual analytics
        return jsonify({
            'success': True,
            'stats': {
                'most_used': 'google',
                'health_status': 'operational',
                'total_integrations': len([i for i in get_integrations() if i['connected']])
            }
        })
    except Exception as e:
        app.logger.error(f"Integration stats error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Initialize the database
with app.app_context():
    ensure_db_directory()
    db.create_all()

def is_premium_template(template_name):
    """Check if a template is premium-only"""
    # Handle both template naming formats
    if template_name.isdigit():
        template_num = int(template_name)
    else:
        # Extract number from template_X format
        if template_name.startswith('template_'):
            try:
                template_num = int(template_name.split('_')[1])
            except (IndexError, ValueError):
                return False
        else:
            return False
    
    # Premium templates are 7-12
    premium_templates = [7, 8, 9, 10, 11, 12]
    return template_num in premium_templates

def get_available_templates(user):
    """Get available templates based on user subscription status"""
    basic_templates = ['template_1', 'template_2', 'template_3', 'template_4', 'template_5', 'template_6']
    
    if user.is_premium and user.subscription_status == 'active':
        
        return basic_templates + ['template_7', 'template_8', 'template_9', 'template_10', 'template_11', 'template_12']
    else:

        return basic_templates

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)