<div align="center">

# ![Server-Side Secret-Free](https://raw.githubusercontent.com/erabytse/CryptoLogin/main/images/logo.png)

[![PyPI version](https://img.shields.io/pypi/v/cryptologin.svg)](https://pypi.org/project/cryptologin/)
[![Python](https://img.shields.io/pypi/pyversions/cryptologin.svg)](https://pypi.org/project/cryptologin/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!--[![Tests](https://github.com/erabytse/CryptoLogin/actions/workflows/test.yml/badge.svg)](https://github.com/erabytse/CryptoLogin/actions)-->

**Zero-storage authentication for Python applications.** The server knows absolutely nothing about your users.

</div>

---

## Overview

CryptoLogin is a passwordless authentication system built on a radical principle: **the server should never know anything that the user doesn't explicitly share**.

**Key properties:**

- 🔐 **Zero-knowledge inspired**: The `master_secret` never leaves the client
- 🛡️ **Breach-resistant**: If the database is leaked, there's nothing to exploit
- ⚡ **Fast**: HMAC-SHA256 verification (~1ms per login)
- 🔌 **Simple**: 3 API endpoints, 2 SDKs (Python + JavaScript)
- 📦 **Battle-tested primitives**: Built on standard `hashlib`, `hmac`, and Web Crypto API

---

## Security Model

### What the server stores

```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,      -- 64-char hex, derived from master_secret
    user_data TEXT,                -- Optional JSON metadata
    created_at TEXT,
    updated_at TEXT,
    last_activity_at TEXT,
    challenge TEXT                 -- Temporary, for active login sessions
);
```

**No passwords. No emails. No secrets.**

**_Authentication flow_**

```test
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │ 1. Derive user_id from master_secret    │
     │    (PBKDF2-SHA512, 100k iterations)     │
     │                                         │
     │ 2. POST /auth/login/init {user_id}      │
     │ ──────────────────────────────────────► │
     │                                         │ 3. Generate challenge
     │    4. Return challenge                  │
     │ ◄────────────────────────────────────── │
     │                                         │
     │ 5. Compute HMAC(challenge, user_id)     │
     │                                         │
     │ 6. POST /auth/login/verify              │
     │    {user_id, hmac}                      │
     │ ──────────────────────────────────────► │
     │                                         │ 7. Verify HMAC
     │    8. Return session                    │
     │ ◄────────────────────────────────────── │
     │                                         │
     ✅ Authenticated                          ✅ Session created
```

### Cryptographic primitives

| Component      | Algorithm                            | Purpose                           |
| -------------- | ------------------------------------ | --------------------------------- |
| Key derivation | PBKDF2-HMAC-SHA512 (100k iterations) | Derive user_id from master_secret |
| Authentication | HMAC-SHA256                          | Prove knowledge of master_secret  |
| Comparison     | Constant-time (hmac.compare_digest)  | Prevent timing attacks            |

**No custom cryptography. All primitives are from Python's standard library.**

---

### Installation

```bash
pip install cryptologin

# With server dependencies (FastAPI, Uvicorn)
pip install 'cryptologin[server]'

# With CLI formatting (Rich)
pip install 'cryptologin[cli]'

# Everything
pip install 'cryptologin[all]'
```

---

### Quick Start

**Initialize a project**

```bash
cryptologin init
cryptologin run --port 8000
```

### Server (Python API)

```python
from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
from cryptologin.core.user_manager_v2 import UserManagerV2

# Initialize
storage = SQLiteStorageV2(db_path="auth.db", auto_migrate=True)
user_manager = UserManagerV2(storage=storage)

# Register (user_id derived client-side from master_secret)
user_manager.register_user_v2(user_id, user_data={"name": "Alice"})

# Login flow
challenge = user_manager.initiate_login_v2(user_id)
# Client computes: hmac = HMAC-SHA256(challenge, user_id)
session = user_manager.complete_login_v2(user_id, hmac)
```

### Client (JavaScript)

```bash
npm install cryptologin-client
```

```javascript
import { createClient } from "cryptologin-client";

const client = createClient({
  baseURL: "https://api.yourapp.com/v1",
  timeout: 30000,
});

// Register - SDK derives user_id automatically
await client.register("my-master-secret-min-32-chars", { name: "Alice" });

// Login - SDK handles the full HMAC flow
const session = await client.login("my-master-secret-min-32-chars");
console.log("Session:", session.sessionId);
```

---

### CLI Usage

```bash
# Initialize a project
cryptologin init

# Start the API server
cryptologin run --port 8000 --debug

# Register a user
cryptologin register --secret "my-master-secret-min-32-chars" \
                     --data '{"name": "Alice", "role": "admin"}'

# Login
cryptologin login --secret "my-master-secret-min-32-chars"

# List all users
cryptologin users --json

# Get user data
cryptologin get-data --user-id 892e3cac5f8d...

# Delete a user
cryptologin delete --user-id 892e3cac5f8d... --secret "master-secret" --yes

# Show system status
cryptologin status

# Show version
cryptologin --version
```

---

### Trade-offs

#### CryptoLogin is not for everyone. Be honest about the trade-offs:

**✅ Use it if:**

- You need zero-knowledge authentication
- Your users can manage a **master_secret** (password manager, hardware key)
- You want breach-resistant authentication
- Compliance requires minimal data retention (GDPR, HIPAA)

**❌ Don't use it if:**

- You need "Forgot Password" (impossible by design)
- Your users are non-technical and will forget credentials
- You need email-based account recovery

> ### **The trade-off:** Absolute security vs. convenience. Like a Bitcoin wallet: Not your keys, not your crypto. Not your master_secret, not your account.

---

### Architecture

```text
cryptologin/
├── client/
│   └── crypto_client.py     # Cryptographic operations
├── core/
│   ├── user_manager.py      # V1 manager (legacy)
│   ├── user_manager_v2.py   # V2 manager (HMAC-based)
│   └── exceptions.py        # Custom exceptions
├── storage/
│   ├── base.py              # Abstract storage
│   ├── sqlite.py            # V1 SQLite storage
│   └── sqlite_v2.py         # V2 SQLite storage
├── main.py                  # FastAPI application
└── cli.py                   # Command-line interface
```

**Two versions coexist peacefully:**

- V1: Traditional challenge-response (legacy support)
- V2: Zero-knowledge HMAC-based (recommended)

---

### Live Demo

**Try CryptoLogin right now:**

- 🌐 [Live Demo: cryptologin-website](https://erabytse.github.io/cryptologin-website/)
- 🔌 [API Endpoint: https://api.docudeeper.com/api/v1](https://api.docudeeper.com/api/v1)

---

### Documentation

- [📚 API Reference](https://github.com/erabytse/CryptoLogin/tree/main/docs)
- [🎯 Examples](https://github.com/erabytse/CryptoLogin/tree/main/examples)
- [🛡️ Security Policy](https://github.com/erabytse/CryptoLogin/blob/main/SECURITY.md)
- [🤝 Contributing Guide](https://github.com/erabytse/CryptoLogin/blob/main/CONTRIBUTING.md)

---

### Packages

| Package                | Description           | Link                                                    |
| ---------------------- | --------------------- | ------------------------------------------------------- |
| **cryptologin**        | Python server SDK     | [PyPi](https://pypi.org/project/cryptologin/)           |
| **cryptologin-client** | JavaScript client SDK | [npm](https://www.npmjs.com/package/cryptologin-client) |

---

### Roadmap

- V1 - Challenge-response authentication
- V2 - Zero-knowledge HMAC-based authentication
- JavaScript SDK with Web Crypto API
- SQLite storage with auto-migration
- FastAPI integration
- Professional CLI
- PostgreSQL storage adapter
- Redis session storage
- WebAuthn/FIDO2 support
- Flash512-Vanguard integration (v3.0)
- OAuth2 provider mode
- Mobile SDKs (React Native, Flutter)

---

### Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](https://github.com/erabytse/CryptoLogin/blob/main/CONTRIBUTING.md) before submitting PRs.

Areas where we need help:

- 🧪 Test coverage (especially edge cases)
- 📚 Documentation improvements
- 🔌 Storage adapters (PostgreSQL, Redis, MongoDB)
- 🎨 UI/UX improvements for the demo
- 🌍 Translations

---

### Security

See [SECURITY.md](https://github.com/erabytse/CryptoLogin/blob/main/SECURITY.md) for reporting vulnerabilities.

**Disclaimer:** CryptoLogin has not been audited by third-party security experts. Use at your own risk for production systems. Always consult with a security professional before deploying authentication systems.

---

### License

MIT © [erabytse](https://github.com/erabytse?spm=a2ty_o01.29997173.0.0.7c0455fbMU0RcW)

---

The future of auth isn't about building better honeypots. It's about removing the honey.
⭐ [Star on GitHub](https://github.com/erabytse/CryptoLogin?spm=a2ty_o01.29997173.0.0.7c0455fbMU0RcW) · [📦 PyPI](https://pypi.org/project/cryptologin) · [🌐 Demo](https://erabytse.github.io/cryptologin-website)
