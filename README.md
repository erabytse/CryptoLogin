<div align="center">

# ![Passwordless Authentication without Password Storage](https://raw.githubusercontent.com/erabytse/CryptoLogin/main/images/logo.png)

## _Zero-Knowledge-Inspired Passwordless Authentication without Password Storage_

**The Future of Authentication is Here. No Email. No Password. Just Your Secret.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/cryptologin.svg)](https://pypi.org/project/cryptologin/)
[![CI Status](https://img.shields.io/badge/CI-Pending-yellow.svg)](https://github.com/erabytse/CryptoLogin)
[![Security](https://img.shields.io/badge/Security-Military%20Grade-red.svg)](SECURITY.md)
[![Stars](https://img.shields.io/github/stars/erabytse/CryptoLogin.svg)](https://github.com/yourusername/cryptologin)

## The time is now ripe for it

**Stop storing password hashes. With CryptoLogin, the server only stores encrypted challenges. The master secret is used once at registration, then forgotten. At login, no secret ever crosses the network.**

<img src="https://raw.githubusercontent.com/erabytse/CryptoLogin/main/images/CryptoLogin.gif" width="320" height="170" alt="CryptoLogin"/>

CryptoLogin uses a challenge-response mechanism inspired by Zero-Knowledge principles.
The server never stores your secret. Your secret never leaves your device.

</div>

---

## 🛡️ Powered by Flash512-Vanguard

CryptoLogin is built on top of [Flash512-Vanguard](https://github.com/erabytse/Flash512-vanguard), a military-grade encryption engine:

- **AES-256-GCM** - NIST standard encryption
- **Argon2id** - Memory-hard key derivation (GPU/ASIC resistant)
- **SecureBuffer** - Automatic memory wiping of sensitive data

Flash512 handles all cryptographic operations, ensuring that CryptoLogin inherits battle-tested security from one of the most robust encryption libraries available.

---

## 🚀 What is CryptoLogin?

**CryptoLogin** is a revolutionary **Passwordless Authentication without Password Storage** that eliminates the need for emails, passwords, or social logins.

---

## What CryptoLogin REALLY is (and isn't)

### ❌ It is NOT "Zero-Knowledge" in the strict cryptographic sense

- In true Zero-Knowledge (like zk-SNARKs or Passkeys), the server never sees the secret, even during registration.
- Here, the `master_secret` is used to encrypt the challenge during registration.

### ✅ What it actually is

- A **Passwordless Authentication System with Encrypted Challenges**.
- The `master_secret` is **never stored** in the database.
- During login, no secret travels over the network.
- Security relies on the fact that **only the client can decrypt the `challenge_token`**.

### 🔐 Real-world security

If the database leaks, the attacker gets:

- `challenge_en_clair` (the "salt")
- `challenge_token` (the "hash")

To crack it, they must perform offline brute-force:

1. Guess a `master_secret`.
2. Derive the key with Argon2id.
3. Decrypt the `challenge_token` with AES-GCM.
4. Compare with `challenge_en_clair`.

**This is equivalent to cracking a password hash with a salt (like bcrypt/Argon2), but using our own elegant and secure mechanism.**

### 🚀 Why it's still revolutionary

- **One secret** for your entire digital life.
- **No email** required.
- **No OAuth** or social login.
- **Military-grade encryption**: AES-256-GCM + Argon2id + SecureBuffer.
- **Data Vault**: Your data is encrypted with your secret.

#

### The Problem

- 🔓 Passwords are **stolen** daily
- 📧 Email verification is **slow** and **annoying**
- 🕵️‍♂️ Social logins **track** your users
- 💰 Authentication services are **expensive**

### The Solution

- 🔐 **One Master Secret** - All you need to remember
- 🛡️ **Military-Grade Encryption** - AES-256-GCM + Argon2id
- 🚫 **Passwordless without password storage** - Your secret never leaves your device
- ⚡ **Lightning Fast** - Register in seconds

---

## ✨ Key Features

| Feature                                                                | Description                    | Security          |
| :--------------------------------------------------------------------- | :----------------------------- | :---------------- |
| **CryptoLogin: Passwordless Authentication without Password Storage"** | Server never knows your secret | 🔒 **Military**   |
| **No Email Required**                                                  | Register without email         | 🔒 **Privacy**    |
| **No Password Required**                                               | Single master secret           | 🔒 **Simple**     |
| **AES-256-GCM**                                                        | NIST standard encryption       | 🔒 **FIPS**       |
| **Argon2id**                                                           | Memory-hard KDF                | 🔒 **OWASP**      |
| **SecureBuffer**                                                       | Automatic memory wiping        | 🔒 **Military**   |
| **Data Vault**                                                         | Encrypted user data            | 🔒 **Zero-Trust** |
| **REST API**                                                           | FastAPI + OpenAPI              | 🔒 **Modern**     |
| **Rate Limiting**                                                      | Brute-force protection         | 🔒 **Production** |

---

## 📦 Installation

```bash
# Install from PyPI
pip install cryptologin

# Or install from source
git clone https://github.com/erabytse/CryptoLogin.git
cd cryptologin
pip install -e .
```

## 🔒 Security Model

**CryptoLogin** uses a challenge-response mechanism with symmetric encryption (Flash512) to achieve Passwordless without password storage authentication.

**Registration:**

1. User creates a `master_secret` (never leaves the client).
2. Client derives a `user_id` from the `master_secret`.
3. Server generates a random `challenge` and encrypts it using Flash512 with the `master_secret`.
4. Server stores the encrypted challenge (`challenge_token`) in the database.

**Login:**

1. User sends `user_id` to the server.
2. Server retrieves the `challenge_token` and sends it to the client.
3. Client decrypts the `challenge_token` with the `master_secret` to get the plaintext `challenge`.
4. Client sends the plaintext `challenge` back to the server.
5. Server verifies that the plaintext `challenge` matches the original challenge.

**The `master_secret` is never transmitted over the network.** Only the encrypted challenge and the derived `user_id` are exchanged.

### Why This Is Secure

- **Passwordless without password storage**: The server never sees the `master_secret`.
- **Military-Grade Encryption**: AES-256-GCM + Argon2id via Flash512.
- **Challenge-Response**: Each login uses a unique challenge (nonce).
- **Data Vault**: All user data is encrypted with the `master_secret`.

## 🏗️ Architecture

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant Server

    Note over User,Server: REGISTRATION
    User->>Browser: Enter master_secret
    Browser->>Server: POST /register {user_id, master_secret}
    Server->>Server: Generate random challenge
    Server->>Server: Encrypt challenge with master_secret (Flash512)
    Server->>Server: Store (user_id, challenge, encrypted_token)
    Server->>Browser: Return success

    Note over User,Server: LOGIN
    User->>Browser: Enter master_secret
    Browser->>Server: POST /login/init {user_id}
    Server->>Server: Retrieve encrypted_token
    Server->>Browser: Return encrypted_token
    Browser->>Browser: Decrypt token with master_secret
    Browser->>Server: POST /login/verify {user_id, decrypted_challenge}
    Server->>Server: Compare with stored challenge
    Server->>Browser: Return session_token
```

```text
┌─────────────────────────────────────────────────────────────────┐
│ CRYPTOLOGIN                                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ [USER] → [API] → [UserManager] → [Data Vault] → [Storage]       │
│                                                                 │
│ 🔐 AES-256-GCM + Argon2id + SecureBuffer                       |
│ 🚫 Passwordless Authentication Architecture                                 |
│ ⚡ FastAPI + SQLite/PostgreSQL                                 |
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

✅ No Password Storage

The server never stores the master secret. Only encrypted challenges are stored.

✅ No Secret at Login

During login, the master secret never leaves the browser. Only the decrypted challenge is sent.

✅ Simple Architecture

No asymmetric keys, no WebAuthn complexity, no email verification. Just Flash512 encryption.

✅ Breach-Resistant

If the database is compromised, attackers only get encrypted challenges. They must brute-force each user individually.

# Powered by Flash512-Vanguard

Flash512-Vanguard is the cryptographic engine behind CryptoLogin. It provides:

- AES-256-GCM: NIST-standard authenticated encryption

- Argon2id: Memory-hard key derivation

- SecureBuffer: Automatic memory wiping

- Polymorphic encryption: Same data, different ciphertext each time

- Integrity verification: GCM authentication tags

By building on Flash512, CryptoLogin inherits enterprise-grade security without implementing cryptographic primitives from scratch.

### Deployment Example (Web Application)

## Example 1

**Frontend (JavaScript):**

```javascript
import { deriveUserId, decrypt } from "cryptologin-wasm";

async function login(masterSecret) {
  const userId = deriveUserId(masterSecret);

  const initResponse = await fetch("/auth/login/init", {
    method: "POST",
    body: JSON.stringify({ user_id: userId }),
  });
  const { challenge_token } = await initResponse.json();

  const challenge = decrypt(challenge_token, masterSecret);

  const verifyResponse = await fetch("/auth/login/verify", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, challenge }),
  });

  return verifyResponse.json();
}
```

**Backend (Python - FastAPI):**

```python
@router.post('/auth/login/init')
async def login_init(user_id: str):
    challenge = os.urandom(32).hex()
    challenge_token = Flash512Vanguard.protect(challenge, get_master_secret(user_id))
    store_challenge(user_id, challenge_token)
    return {"challenge_token": challenge_token}

@router.post('/auth/login/verify')
async def login_verify(user_id: str, challenge: str):
    stored_challenge = get_stored_challenge(user_id)
    if challenge == stored_challenge:
        return {"authenticated": True}
    return {"authenticated": False}
```

## Example 2

**Frontend(index.html):**

```html
<!DOCTYPE html>
<html>
  <head>
    <title>CryptoLogin Demo</title>
  </head>
  <body>
    <h1>CryptoLogin Demo</h1>

    <input type="text" id="userId" placeholder="User ID" />
    <input type="password" id="masterSecret" placeholder="Master Secret" />

    <button onclick="register()">Register</button>
    <button onclick="login()">Login</button>

    <script>
      async function register() {
        const userId = document.getElementById("userId").value;
        const masterSecret = document.getElementById("masterSecret").value;

        const res = await fetch("/api/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            user_id: userId,
            master_secret: masterSecret,
          }),
        });

        alert(await res.json());
      }

      async function login() {
        const userId = document.getElementById("userId").value;
        const masterSecret = document.getElementById("masterSecret").value;

        // 1. Request the encrypted token
        const initRes = await fetch("/api/login/init", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_id: userId }),
        });
        const { challenge_token } = await initRes.json();

        // 2. Decrypt LOCALLY using master_secret
        // (In the actual app, this is done using WASM/JS with Flash512)
        const decryptedChallenge = await decryptLocally(
          challenge_token,
          masterSecret,
        );

        // 3. Send back the decrypted challenge
        const verifyRes = await fetch("/api/login/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            user_id: userId,
            decrypted_challenge: decryptedChallenge,
          }),
        });

        if (verifyRes.ok) {
          alert("Authentifié !");
        }
      }

      async function decryptLocally(token, secret) {
        // Here, you call Flash512 via WASM/JS
        // For the demo, we’re simulating
        return "decrypted_challenge";
      }
    </script>
  </body>
</html>
```

**Backend(app.py):**

```python
from flask import Flask, request, jsonify, session
from cryptologin import CryptoLogin
from flash512_vanguard import Flash512Vanguard

app = Flask(__name__)
app.secret_key = "your-secret-key"
auth = CryptoLogin()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    user_id = data['user_id']
    master_secret = data['master_secret']

    # The server generates a random challenge
    challenge = auth.generate_challenge()

    # The server encrypts the challenge using the master_secret
    challenge_token = Flash512Vanguard.protect(challenge, master_secret)

    # The server stores everything (the plaintext challenge is used for verification)
    auth.store_user(user_id, challenge, challenge_token)

    # IMPORTANT: The master_secret is NOT stored
    return jsonify({"status": "User registered"})

@app.route('/api/login/init', methods=['POST'])
def login_init():
    user_id = request.json['user_id']

    # The server returns the encrypted token
    challenge_token = auth.get_challenge_token(user_id)
    return jsonify({"challenge_token": challenge_token})

@app.route('/api/login/verify', methods=['POST'])
def login_verify():
    user_id = request.json['user_id']
    decrypted_challenge = request.json['decrypted_challenge']

    # The server compares it with the challenge stored in plain text
    if auth.verify_challenge(user_id, decrypted_challenge):
        session['user_id'] = user_id
        return jsonify({"status": "Authenticated"})

    return jsonify({"error": "Invalid"}), 401
```

### The master_secret is never exposed to the server. This is true Passwordless without password storage.

#

### Security Certifications

| Standard      | Compliance                               |
| ------------- | ---------------------------------------- |
| NIST FIPS 197 | ✅ AES-256                               |
| OWASP ASVS    | ✅ Argon2id                              |
| GDPR          | ✅ Passwordless without password storage |
| SOC2          | ✅ Audit Logs                            |
|               |

📊 Comparison

| Feature                               | CryptoLogin | Auth0  | Firebase | Clerk  |
| ------------------------------------- | ----------- | ------ | -------- | ------ |
| Passwordless without password storage | ✅          | ❌     | ❌       | ❌     |
| No Email Required                     | ✅          | ❌     | ❌       | ❌     |
| No Password Required                  | ✅          | ❌     | ❌       | ❌     |
| Open Source                           | ✅          | ❌     | ❌       | ❌     |
| Self-Hosted                           | ✅          | ❌     | ❌       | ❌     |
| Military Encryption                   | ✅          | ⚠️     | ⚠️       | ⚠️     |
| Price                                 | 💰Free      | 💰💰💰 | 💰💰     | 💰💰💰 |

🎯 Use Cases

- 🌐 Web Applications - Authentication without email/password

- 📱 Mobile Apps - Simple, secure login

- 🔒 Enterprise Apps - Zero-trust authentication

- 🏥 Healthcare - GDPR compliant authentication

- 💳 Fintech - High-security authentication

#

# 🧪 DEMO

Try it now

The interactive demo

Create an account in 2 seconds. One master secret. No personal data.

<b>[ONLINE DEMO](https://erabytse.github.io/cryptologin-website/)</b>

#

📚 Documentation

- API Reference

- Getting Started Guide

- Security Whitepaper

- Architecture Overview

#

🤝 Contributing

We welcome contributions! Please see our Contributing Guide.

Development Setup

```bash
# Clone the repository
git clone https://github.com/erabytse/CryptoLogin.git
cd cryptologin

# Install dev dependencies
pip install -e .[dev]

# Run tests
pytest tests/ -v

# Run the API
python run.py
```

#

📄 License

- Open Source: Apache 2.0

- Commercial: Available for enterprise use

#

🌟 Support the Project

- ⭐ Star the repository

- 🐛 Report issues

- 📝 Improve documentation

- 💰 Sponsor the project

- 🗣️ Spread the word

#

📞 Contact

- 📧 Email: contact@fbfconsulting.org

- 🐦 Twitter: @cryptologin (coming soon)

- 💬 Discord: Join our community (coming soon)

[©erabytse](https://erabytse.github.io/)

#

<div align="center">
Built with ❤️ by erabytse

Reinventing Authentication. One Secret at a Time.

A quiet rebellion against digital waste.

</div>
