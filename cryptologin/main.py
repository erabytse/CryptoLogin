"""
CryptoLogin – Application entry point
Zero-Storage Authentication System
"""
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi.errors import RateLimitExceeded

from .config import get_settings
from .api.routes import auth, user, health
from .api.dependencies import limiter, rate_limit_exceeded_handler
from .storage.sqlite import SQLiteStorage

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURATION
# ============================================================
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestion du cycle de vie de l'application.
    """
    # Startup
    logger.info("Starting CryptoLogin API v%s", settings.APP_VERSION)
    
    # Initialize the database
    try:
        db_path = settings.DATABASE_URL.replace("sqlite:///", "")
        storage = SQLiteStorage(db_path=db_path, auto_migrate=True)
        logger.info("Database initialized at: %s", db_path)
    except Exception as e:
        logger.error("Failed to initialize database: %s", e)
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down CryptoLogin API")


# ============================================================
# APPLICATION
# ============================================================
app = FastAPI(
    title="CryptoLogin API",
    version=settings.APP_VERSION,
    description="""
## CryptoLogin – Zero-Storage Authentication System

**CryptoLogin** is a passwordless authentication system where the server stores **zero secrets**. 
No password hashes, no emails, no recovery tokens. The server only knows a `user_id` derived 
from the user's `master_secret`, and authentication is proven cryptographically via HMAC.

### Core Principles:
- **Zero-Storage Authentication**: The server never knows your secret
- **Standard Primitives**: PBKDF2-SHA512 for key derivation, HMAC-SHA256 for authentication
- **Client-Side Derivation**: The `master_secret` never leaves the browser
- **Breach-Resistant**: If the database is leaked, there's nothing to exploit

### Authentication Flow (V2 - Recommended):
1. Client derives `user_id` from `master_secret` (PBKDF2-SHA512, 100k iterations)
2. Client calls `/auth/register_v2` with the derived `user_id`
3. Client calls `/auth/login/init_v2` to get a plaintext challenge
4. Client computes `HMAC-SHA256(challenge, user_id)` locally
5. Client calls `/auth/login/verify_v2` with the HMAC signature
6. Server verifies the HMAC (constant-time comparison) and creates a session

### Legacy Flow (V1):
1. `/auth/register` - Registration (encrypted challenge)
2. `/auth/login/init` - Obtain encrypted challenge
3. `/auth/login/verify` - Verification and Session Creation
4. Access Resources with Session ID

### Security Model:
- **No password storage**: The server only stores derived `user_id` values
- **No email required**: Authentication is purely cryptographic
- **Standard algorithms**: Built on Python's `hashlib` and `hmac` modules
- **Constant-time comparison**: Prevents timing attacks via `hmac.compare_digest`

### Trade-offs (Be Honest):
- ❌ No "Forgot Password" (impossible by design)
- ❌ Users must manage their `master_secret` securely
- ✅ Breach-resistant (nothing to steal)
- ✅ Zero-knowledge inspired architecture

---

**Documentation**: [GitHub](https://github.com/erabytse/CryptoLogin)  
**Live Demo**: [Demo V2](https://erabytse.github.io/cryptologin-website/demo_v2.html)  
**PyPI**: [cryptologin](https://pypi.org/project/cryptologin/)
""",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "CryptoLogin Support",
        "url": "https://github.com/erabytse/CryptoLogin/issues",
        "email": "support@erabytse.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    },
    terms_of_service="https://github.com/erabytse/CryptoLogin/blob/main/LICENSE"
)

# ============================================================
# MIDDLEWARE
# ============================================================

# CORS - Secure configuration
# In development: allow localhost
# In production: restrict to specific domains
ALLOWED_ORIGINS = [
    # Développement local
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://localhost:8000",
    "http://localhost:3000",
    
    # Production - Demo website
    "https://erabytse.github.io",
    "https://erabytse.github.io/cryptologin-website",
    "https://erabytse.github.io/cryptologin-website/",
    
    # Production - API
    "https://api.docudeeper.com",
]

# Add origins from the configuration (if defined)
if hasattr(settings, 'ALLOWED_ORIGINS') and settings.ALLOWED_ORIGINS:
    ALLOWED_ORIGINS.extend(settings.ALLOWED_ORIGINS)

# In production, do NOT use ‘*’
# In development, we can be more lenient
is_production = os.getenv("ENVIRONMENT", "development") == "production"

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if is_production else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "Origin",
        "User-Agent",
        "X-CSRF-Token",
    ],
    expose_headers=[
        "Content-Length",
        "Content-Type",
        "X-Request-ID",
    ],
    max_age=600,  # 10 minutes
)

# Trusted Host - Secure configuration
# In production, restrict to specific domains
# In development, allow all hosts
if is_production:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "api.docudeeper.com",
            "erabytse.github.io",
            "localhost",
            "127.0.0.1",
        ]
    )
else:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]
    )

# Rate Limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# ============================================================
# ROUTES
# ============================================================
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(user.router, prefix=settings.API_PREFIX)
app.include_router(health.router, prefix=settings.API_PREFIX)


# ============================================================
# ROOT ENDPOINTS
# ============================================================
@app.get(
    "/",
    tags=["Root"],
    summary="API Root",
    description="Returns basic API information"
)
async def root():
    """API root endpoint."""
    return {
        "name": "CryptoLogin",
        "version": settings.APP_VERSION,
        "description": "Zero-Storage Authentication System",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/api/v1/health",
        "github": "https://github.com/erabytse/CryptoLogin",
        "demo": "https://erabytse.github.io/cryptologin-website/demo_v2.html"
    }


@app.get(
    "/ping",
    tags=["Health"],
    summary="Ping",
    description="Simple health check endpoint"
)
async def ping():
    """Simple ping to check if the API is active."""
    return {
        "status": "alive",
        "pong": True,
        "version": settings.APP_VERSION
    }


@app.get(
    "/info",
    tags=["Root"],
    summary="System Information",
    description="Returns detailed system information"
)
async def info():
    """Detailed system information."""
    return {
        "name": "CryptoLogin",
        "version": settings.APP_VERSION,
        "python_version": os.sys.version,
        "environment": os.getenv("ENVIRONMENT", "development"),
        "database": settings.DATABASE_URL.replace("sqlite:///", ""),
        "features": {
            "v1_authentication": True,
            "v2_authentication": True,
            "rate_limiting": True,
            "cors": True,
        },
        "security": {
            "key_derivation": "PBKDF2-SHA512 (100,000 iterations)",
            "authentication": "HMAC-SHA256",
            "comparison": "Constant-time (hmac.compare_digest)",
        }
    }