# CryptoLogin Web App Example

Simple Flask web application demonstrating CryptoLogin integration.

## Prerequisites

```bash
pip install -r requirements.txt
```

## Setup

### 1. Run the application:

```bash
python app.py
```

### 2. Open your browser:

```
http://localhost:5000
```

## Features

- ✅ User registration with master secret
- ✅ Login with HMAC-based authentication
- ✅ Session management with Flask sessions
- ✅ Protected routes
- ✅ Logout functionality

## Security Notes

- The master secret is never stored on the server
- All cryptographic operations happen client-side
- Sessions are stored securely in Flask sessions
- CSRF protection enabled
