"""
CryptoLogin Web App Example - Flask
Simple web application demonstrating CryptoLogin integration
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
from cryptologin.core.user_manager_v2 import UserManagerV2
from cryptologin.client.crypto_client import CryptoClient
import hmac
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For Flask sessions

# Initialize CryptoLogin
storage = SQLiteStorageV2(db_path="webapp.db", auto_migrate=True)
user_manager = UserManagerV2(storage=storage, session_duration_hours=24)
crypto_client = CryptoClient()

def compute_hmac(user_id: str, challenge: str) -> str:
    """Compute HMAC-SHA256 signature"""
    return hmac.new(
        user_id.encode('utf-8'),
        challenge.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    master_secret = request.form.get('master_secret')
    if not master_secret or len(master_secret) < 32:
        flash('Master secret must be at least 32 characters', 'error')
        return redirect(url_for('index'))
    
    try:
        # Derive user_id
        user_id = crypto_client.derive_user_id(master_secret)
        # Register user
        user_manager.register_user_v2(user_id, {
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        })
        flash('✅ Registration successful! Please login.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'❌ Registration failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    """Login a user"""
    master_secret = request.form.get('master_secret')
    if not master_secret or len(master_secret) < 32:
        flash('Master secret must be at least 32 characters', 'error')
        return redirect(url_for('index'))
    
    try:
        # Derive user_id
        user_id = crypto_client.derive_user_id(master_secret)
        # Get challenge
        challenge = user_manager.initiate_login_v2(user_id)
        # Compute HMAC
        hmac_signature = compute_hmac(user_id, challenge)
        # Verify login
        auth_session = user_manager.complete_login_v2(user_id, hmac_signature)
        
        # ✅ CORRECTION: UserManagerV2 keys sessions by user_id, not session_id
        session['user_id'] = user_id
        session['expires_at'] = auth_session.expires_at.isoformat()
        
        flash('✅ Login successful!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'❌ Login failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Protected dashboard"""
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('index'))
    
    # Validate session
    try:
        # ✅ CORRECTION: validate_session expects user_id, not session_id
        is_valid = user_manager.validate_session(session['user_id'])
        if not is_valid:
            session.clear()
            flash('Session expired', 'warning')
            return redirect(url_for('index'))
    except Exception:
        session.clear()
        flash('Invalid session', 'error')
        return redirect(url_for('index'))
        
    return render_template('dashboard.html', user_id=session['user_id'])

@app.route('/logout')
def logout():
    """Logout user"""
    # ✅ CORRECTION: Check for user_id and pass it to logout()
    if 'user_id' in session:
        try:
            user_manager.logout(session['user_id'])
        except Exception:
            pass  # Ignore if already expired/removed
        session.clear()
        flash('👋 Logged out successfully', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=3000)