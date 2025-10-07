#!/usr/bin/env python3
"""
FAS (Forward Authentication Service) Mock Server for Testing
Simulates a complete FAS authentication flow with JWT tokens
"""

import os
import jwt
import time
import logging
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect

# Configuration
FAS_SECRET = os.getenv('FAS_SECRET', 'supersecretfaskey123456789')
FAS_PORT = int(os.getenv('FAS_PORT', 8081))
TOKEN_EXPIRATION = int(os.getenv('TOKEN_EXPIRATION', 300))  # 5 minutes
RADIUS_HOST = os.getenv('RADIUS_HOST', 'radius')
RADIUS_SECRET = os.getenv('RADIUS_SECRET', 'testing123')

# Initialize Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = FAS_SECRET

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory session storage (for testing)
active_sessions = {}
token_blacklist = set()

# =============================================================================
# HTML TEMPLATES
# =============================================================================

LOGIN_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FAS Login - CoovaChilli</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            width: 90%;
        }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; font-size: 14px; }
        .info strong { display: block; margin-bottom: 5px; color: #1976d2; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: bold; }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Hotspot Login</h1>

        <div class="info">
            <strong>Session Information:</strong>
            Client MAC: {{ client_mac }}<br>
            Client IP: {{ client_ip }}<br>
            NAS ID: {{ nas_id }}
        </div>

        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/auth">
            <input type="hidden" name="token" value="{{ token }}">
            <input type="hidden" name="client_mac" value="{{ client_mac }}">
            <input type="hidden" name="client_ip" value="{{ client_ip }}">
            <input type="hidden" name="nas_id" value="{{ nas_id }}">

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

SUCCESS_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Successful</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 90%;
            text-align: center;
        }
        .success-icon { font-size: 80px; color: #38ef7d; margin-bottom: 20px; }
        h1 { color: #333; margin-bottom: 20px; }
        .info { background: #e8f5e9; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: left; }
        .info div { padding: 8px 0; border-bottom: 1px solid #c8e6c9; }
        .info div:last-child { border-bottom: none; }
        .info strong { color: #2e7d32; }
        button {
            margin-top: 20px;
            padding: 14px 30px;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Authentication Successful!</h1>
        <p>You are now connected to the network.</p>

        <div class="info">
            <div><strong>Username:</strong> {{ username }}</div>
            <div><strong>Session ID:</strong> {{ session_id }}</div>
            <div><strong>IP Address:</strong> {{ client_ip }}</div>
            <div><strong>Session Timeout:</strong> {{ timeout }} seconds</div>
        </div>

        <button onclick="window.close()">Close</button>
    </div>

    <script>
        // Redirect to CoovaChilli callback
        setTimeout(function() {
            window.location.href = '{{ callback_url }}';
        }, 2000);
    </script>
</body>
</html>
"""

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def generate_token(client_mac, client_ip, nas_id):
    """Generate JWT token for FAS authentication"""
    payload = {
        'client_mac': client_mac,
        'client_ip': client_ip,
        'nas_id': nas_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRATION),
        'jti': hashlib.sha256(f"{client_mac}{time.time()}".encode()).hexdigest()[:16]
    }

    token = jwt.encode(payload, FAS_SECRET, algorithm='HS256')
    logger.info(f"Generated token for MAC={client_mac}, IP={client_ip}")
    return token

def validate_token(token):
    """Validate JWT token"""
    if token in token_blacklist:
        logger.warning(f"Token in blacklist: {token[:20]}...")
        return None

    try:
        payload = jwt.decode(token, FAS_SECRET, algorithms=['HS256'])
        logger.info(f"Token validated for MAC={payload.get('client_mac')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return None

def create_session(username, client_mac, client_ip, nas_id):
    """Create authentication session"""
    session_id = hashlib.sha256(f"{username}{client_mac}{time.time()}".encode()).hexdigest()[:24]

    session_data = {
        'session_id': session_id,
        'username': username,
        'client_mac': client_mac,
        'client_ip': client_ip,
        'nas_id': nas_id,
        'created_at': datetime.utcnow().isoformat(),
        'timeout': 3600,
        'bandwidth_down': 10000,  # kbps
        'bandwidth_up': 5000      # kbps
    }

    active_sessions[session_id] = session_data
    logger.info(f"Created session {session_id} for user={username}, MAC={client_mac}")

    return session_data

# =============================================================================
# ROUTES
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'FAS Mock Server',
        'timestamp': datetime.utcnow().isoformat(),
        'active_sessions': len(active_sessions)
    })

@app.route('/login', methods=['GET'])
def login_page():
    """Display login page"""
    # Extract parameters from query string
    token = request.args.get('token', '')
    client_mac = request.args.get('client_mac', request.args.get('mac', 'unknown'))
    client_ip = request.args.get('client_ip', request.args.get('ip', 'unknown'))
    nas_id = request.args.get('nas_id', request.args.get('nasid', 'unknown'))
    error = request.args.get('error', '')

    # If no token provided, generate one
    if not token and client_mac != 'unknown':
        token = generate_token(client_mac, client_ip, nas_id)

    return render_template_string(
        LOGIN_PAGE_TEMPLATE,
        token=token,
        client_mac=client_mac,
        client_ip=client_ip,
        nas_id=nas_id,
        error=error
    )

@app.route('/auth', methods=['POST'])
def authenticate():
    """Process authentication"""
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('token')
    client_mac = request.form.get('client_mac', 'unknown')
    client_ip = request.form.get('client_ip', 'unknown')
    nas_id = request.form.get('nas_id', 'unknown')

    logger.info(f"Auth attempt: user={username}, MAC={client_mac}, IP={client_ip}")

    # Validate token
    if token:
        token_data = validate_token(token)
        if not token_data:
            return redirect(f"/login?error=Invalid or expired token&client_mac={client_mac}&client_ip={client_ip}&nas_id={nas_id}")

    # Simple authentication (for testing - accept testuser/testpass or any user*/user*pass)
    if (username == 'testuser' and password == 'testpass') or \
       (username.startswith('user') and password == f'{username}pass') or \
       (username.startswith('vlan') and password == 'testpass'):

        # Create session
        session_data = create_session(username, client_mac, client_ip, nas_id)

        # Generate callback URL to CoovaChilli
        callback_url = f"http://{nas_id}:3990/api/v1/fas/auth?token={token}&session_id={session_data['session_id']}&username={username}"

        return render_template_string(
            SUCCESS_PAGE_TEMPLATE,
            username=username,
            session_id=session_data['session_id'],
            client_ip=client_ip,
            timeout=session_data['timeout'],
            callback_url=callback_url
        )
    else:
        return redirect(f"/login?error=Invalid credentials&client_mac={client_mac}&client_ip={client_ip}&nas_id={nas_id}&token={token}")

@app.route('/api/validate', methods=['POST'])
def validate_token_api():
    """API endpoint to validate token"""
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'valid': False, 'error': 'Token required'}), 400

    token_data = validate_token(token)

    if token_data:
        return jsonify({
            'valid': True,
            'client_mac': token_data.get('client_mac'),
            'client_ip': token_data.get('client_ip'),
            'nas_id': token_data.get('nas_id'),
            'expires_at': token_data.get('exp')
        })
    else:
        return jsonify({'valid': False, 'error': 'Invalid or expired token'}), 401

@app.route('/api/callback', methods=['POST', 'GET'])
def callback():
    """Callback endpoint from CoovaChilli"""
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args.to_dict()

    session_id = data.get('session_id')
    token = data.get('token')

    logger.info(f"Callback received: session_id={session_id}")

    if session_id and session_id in active_sessions:
        session_data = active_sessions[session_id]

        # Mark token as used
        if token:
            token_blacklist.add(token)

        return jsonify({
            'authenticated': True,
            'session': session_data
        })
    else:
        return jsonify({'authenticated': False, 'error': 'Invalid session'}), 401

@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    """Get all active sessions (for debugging)"""
    return jsonify({
        'sessions': list(active_sessions.values()),
        'count': len(active_sessions)
    })

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    """Delete session (logout)"""
    if session_id in active_sessions:
        del active_sessions[session_id]
        logger.info(f"Session {session_id} deleted")
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    logger.info(f"Starting FAS Mock Server on port {FAS_PORT}")
    logger.info(f"Token expiration: {TOKEN_EXPIRATION} seconds")

    app.run(host='0.0.0.0', port=FAS_PORT, debug=True)
