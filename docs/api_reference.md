# CryptoLogin API Reference

Complete API documentation for CryptoLogin v2.1.5.

## Base URL

### https://api.docudeeper.com/api/v1

## Authentication

> **All endpoints (except `/health` and `/ping`) require authentication via Bearer token.**

## Authorization: Bearer <session_id>

````
## Endpoints

### Health Check

#### `GET /health`

Check if the API is healthy.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.1.5",
  "database": "connected"
}
````

## Ping

**GET /ping**

Simple ping endpoint.

Response:

```json
{
  "status": "alive",
  "pong": true,
  "version": "2.1.5"
}
```

## Registration (V2)

**POST /auth/register_v2**

Register a new user with derived user_id.

Request:

```json
{
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559",
  "user_data": {
    "name": "bob",
    "email": "bob@example.com"
  }
}
```

Response:

```json
{
  "success": true,
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559",
  "message": "User registered successfully"
}
```

Errors:

- **400: Invalid user_id format**

- **409: User already exists**

## Login Init (V2)

**POST /auth/login/init_v2**

Initiate login and get a plaintext challenge.

Request:

```json
{
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559"
}
```

Response:

```json
{
  "challenge": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
}
```

Errors:

- **404: User not found**

- **400: Invalid user_id format**

## Login Verify (V2)

**POST /auth/login/verify_v2**

Verify login with HMAC signature.

Request:

```json
{
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559",
  "challenge_response": "29bcb4a1de234c6f43fc9e3172975d83af753c808007e26d0cbc9b095ab82729"
}
```

Response:

```json
{
  "session_id": "session_abc123...",
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559",
  "expires_at": "2026-06-30T14:45:18.431336",
  "authenticated": true
}
```

Errors:

- **401: Invalid HMAC signature**

- **404: User not found**

- **400: No pending challenge**

## Logout

**POST /auth/logout**

Logout and invalidate session.

Headers:

```
Authorization: Bearer <session_id>
```

Request:

```json
{
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559"
}
```

Response:

```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

## Get User Data

**GET /user/data**

Get user data (requires authentication).

Headers:

```
Authorization: Bearer <session_id>
```

Response:

```json
{
  "user_id": "892e3cac5f8dde15595f217f5284be54a9fd7ba93a6973947370e0eaa193b559",
  "user_data": {
    "name": "bob",
    "email": "bob@example.com"
  },
  "created_at": "2026-06-28T10:00:00",
  "updated_at": "2026-06-28T10:00:00"
}
```

Errors:

- **401: Unauthorizede**

- **404: User not found**

## Error Responses

All errors follow this format:

```json
{
  "error": "Error type",
  "message": "Detailed error message",
  "code": "ERROR_CODE"
}
```

### Common Error Codes

- USER_NOT_FOUND: User does not exist
- USER_EXISTS: User already registered
- INVALID_HMAC: HMAC verification failed
- NO_CHALLENGE: No pending challenge for login
- INVALID_USER_ID: user_id format invalid
- UNAUTHORIZED: Missing or invalid session
- SESSION_EXPIRED: Session has expired

## Rate Limiting

API is rate-limited to prevent abuse:

- 100 requests per minute per IP

- 10 login attempts per minute per user

Rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1624892400
```

## SDKs

Python

```
pip install cryptologin
```

```python
from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
from cryptologin.core.user_manager_v2 import UserManagerV2

storage = SQLiteStorageV2(db_path="auth.db", auto_migrate=True)
user_manager = UserManagerV2(storage=storage)
```

JavaScript

```
npm install cryptologin-client
```

```javascript
import { createClient } from "cryptologin-client";

const client = createClient({
  baseURL: "https://api.docudeeper.com/api/v1",
});
```

## Live Demo

Try the API with our interactive demo:

- Demo V2: https://erabytse.github.io/cryptologin-website/demo_v2.html

## Support

- GitHub Issues: https://github.com/erabytse/CryptoLogin/issues
- Documentation: https://github.com/erabytse/CryptoLogin#readme
