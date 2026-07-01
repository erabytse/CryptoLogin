# CryptoLogin Architecture

Technical architecture documentation for CryptoLogin v2.1.6.

## Overview

CryptoLogin is a zero-storage authentication system where the server stores **no secrets**. Authentication is proven cryptographically via HMAC-SHA256, with the `master_secret` never leaving the client.

---

## System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ CLIENT (Browser) │
│ │
│ ┌──────────────┐ │
│ │master_secret │ ← User input (never leaves browser) │
│ └──────┬───────┘ │
│ │ │
│ ▼ │
│ ┌──────────────────────────────────────┐ │
│ │ PBKDF2-SHA512 (100k iterations) │ │
│ │ Derive user_id from master_secret │ │
│ └──────┬───────────────────────────────┘ │
│ │ │
│ ▼ │
│ ┌──────────────────────────────────────┐ │
│ │ user_id (64 hex chars) │ │
│ └──────┬───────────────────────────────┘ │
│ │ │
│ │ 1. POST /auth/login/init_v2 │
│ │ {user_id: "..."} │
│ ▼ │
│ ┌──────────────────────────────────────┐ │
│ │ challenge (64 hex chars) │ ← From server │
│ └──────┬───────────────────────────────┘ │
│ │ │
│ ▼ │
│ ┌──────────────────────────────────────┐ │
│ │ HMAC-SHA256(challenge, user_id) │ │
│ │ Compute signature locally │ │
│ └──────┬───────────────────────────────┘ │
│ │ │
│ │ 2. POST /auth/login/verify_v2 │
│ │ {user_id, hmac} │
│ ▼ │
└─────────┼────────────────────────────────────────────────────┘
│
│ HTTPS
▼
┌─────────────────────────────────────────────────────────────┐
│ SERVER (FastAPI) │
│ │
│ ┌──────────────────────────────────────┐ │
│ │ /auth/login/init_v2 │ │
│ │ Generate random challenge │ │
│ │ Store in DB temporarily │ │
│ └──────┬───────────────────────────────┘ │
│ │ │
│ ▼ │
│ ┌──────────────────────────────────────┐ │
│ │ /auth/login/verify_v2 │ │
│ │ Compute expected HMAC │ │
│ │ Compare with client HMAC │ │
│ │ (constant-time comparison) │ │
│ └──────┬───────────────────────────────┘ │
│ │ │
│ ▼ │
│ ┌──────────────────────────────────────┐ │
│ │ Create session │ │
│ │ Return session_id │ │
│ └──────────────────────────────────────┘ │
│ │
│ ┌──────────────────────────────────────┐ │
│ │ SQLite Database │ │
│ │ - user_id (derived, not secret) │ │
│ │ - user_data (optional metadata) │ │
│ │ - challenge (temporary) │ │
│ └──────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Client SDK (`cryptologin-client`)

**Technology:** JavaScript (Web Crypto API)

**Responsibilities:**

- Derive `user_id` from `master_secret` using PBKDF2-SHA512
- Compute HMAC-SHA256 signatures
- Manage sessions
- Handle API communication

**Key Files:**

- `src/core/crypto.js` - Cryptographic operations
- `src/core/client.js` - API client
- `src/utils/helpers.js` - Session management

---

### 2. Server SDK (`cryptologin`)

**Technology:** Python 3.8+

**Responsibilities:**

- Store derived `user_id` values
- Generate random challenges
- Verify HMAC signatures
- Manage sessions

**Key Files:**

- `cryptologin/core/user_manager_v2.py` - V2 authentication logic
- `cryptologin/storage/sqlite_v2.py` - Database storage
- `cryptologin/client/crypto_client.py` - Cryptographic utilities
- `cryptologin/main.py` - FastAPI application

---

### 3. Database Schema

```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,           -- 64-char hex, derived from master_secret
    user_data TEXT,                     -- JSON metadata (optional)
    created_at TEXT,                    -- ISO 8601 timestamp
    updated_at TEXT,                    -- ISO 8601 timestamp
    last_activity_at TEXT,              -- ISO 8601 timestamp
    challenge TEXT                      -- Temporary, for active login sessions
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT,
    created_at TEXT,
    expires_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

Important: The database stores no secrets. Only derived user_id values and temporary challenges.

```

## Authentication Flow (V2)

### Step-by-Step

**1. Client derives user_id**

```javascript
const userId = await deriveUserId(masterSecret);
// PBKDF2-SHA512, 100k iterations, fixed salt
// Result: 64-char hex string
```

**2. Client requests challenge**

```javascript
POST / auth / login / init_v2;
{
  user_id: "892e3cac...";
}
```

**3. Server generates challenge**

```python
challenge = crypto_client.generate_challenge(32)
# Random 64-char hex string
# Stored temporarily in database
```

**4. Client computes HMAC**

```javascript
const hmac = await computeHmac(userId, challenge);
// HMAC-SHA256(challenge, user_id)
// Result: 64-char hex signature
```

**5. Client submits HMAC**

```javascript
POST /auth/login/verify_v2
{ user_id: "...", challenge_response: "29bcb4a1..." }
```

**6. Server verifies HMAC**

```python
expected_hmac = crypto_client.compute_hmac(user_id, challenge)
if hmac.compare_digest(expected_hmac, client_hmac):
    # Authentication successful
    session = create_session(user_id)
```

**7. Session created**

```python
return {
    "session_id": "session_abc123...",
    "user_id": user_id,
    "expires_at": datetime.now() + timedelta(hours=24)
}
```

## Security Model

What the Server Knows

✅ Known:

- Derived user_id values (64-char hex)
- Optional user metadata (JSON)
- Temporary challenges (during login)
- Session IDs

❌ Unknown:

- master_secret (never transmitted)
- Passwords (none stored)
- Email addresses (not required)
- Recovery tokens (none exist)

### Cryptographic Primitives

| Component         | Algorithm                       | Purpose                                           |
| ----------------- | ------------------------------- | ------------------------------------------------- |
| Key Derivation    | PBKDF2-SHA512 (100k iterations) | Derive user_id from master_secret                 |
| Authentication    | HMAC-SHA256                     | Prove knowledge of master_secret                  |
| Comparison        | hmac.compare_digest             | Constant-time comparison (prevent timing attacks) |
| Random Generation | secrets.token_hex               | Generate challenges                               |

### Security Guarantees

- Zero-Knowledge Inspired: Server never learns master_secret
- Breach-Resistant: Database leak exposes nothing useful
- No Password Storage: Nothing to crack or brute-force
- Constant-Time Comparison: Prevents timing attacks
- Standard Primitives: No custom cryptography

## Deployment

### Development

```bash
# Clone repository
git clone https://github.com/erabytse/CryptoLogin.git
cd CryptoLogin

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Start development server
cryptologin run --debug
```

### Production

```bash
# Install from PyPI
pip install cryptologin

# Initialize
cryptologin init

# Configure environment
export ENVIRONMENT=production
export DATABASE_URL=sqlite:///cryptologin.db

# Start server
cryptologin run --host 0.0.0.0 --port 8000
```

### Docker (Future)

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install cryptologin

EXPOSE 8000
CMD ["cryptologin", "run", "--host", "0.0.0.0", "--port", "8000"]
```

## Performance

### Benchmarks

| Operation             | Time   | Notes                       |
| --------------------- | ------ | --------------------------- |
| deriveUserId (client) | ~150ms | PBKDF2 with 100k iterations |
| computeHmac (client)  | ~1ms   | HMAC-SHA256 is fast         |
| Challenge generation  | ~0.1ms | Random hex generation       |
| HMAC verification     | ~1ms   | Constant-time comparison    |
| Full login flow       | ~200ms | Network + crypto            |

## Scalability

- SQLite: Good for single-server deployments (up to ~10k users)

- PostgreSQL (future): For multi-server, high-traffic deployments

- Redis (future): For distributed session storage

## Monitoring

Health Checks

```bash
GET /health
GET /ping
```

### Metrics (Future)

- Login success rate
- Average login time
- Active sessions
- Database size0

#### Logging

```python
logger.info("User authenticated: %s", user_id[:16])
logger.warning("Invalid HMAC for user: %s", user_id[:16])
logger.error("Database connection failed: %s", error)
```

## Contributing

See [CONTRIBUTING.md](https://github.com/erabytse/CryptoLogin/blob/main/CONTRIBUTING.md) for guidelines.

**Development Setup**

```bash
# Clone
git clone https://github.com/erabytse/CryptoLogin.git

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
flake8 cryptologin/
```

## License

MIT © [erabytse](https://github.com/erabytse)
