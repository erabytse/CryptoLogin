"""
CryptoLogin - Point d'entrée de l'application
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi.errors import RateLimitExceeded

from .config import get_settings
from .api.routes import auth, user, health
from .api.dependencies import limiter, rate_limit_exceeded_handler
from .storage.sqlite import SQLiteStorage

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestion du cycle de vie de l'application.
    """
    # Startup
    logger.info("Starting CryptoLogin API v%s", settings.APP_VERSION)
    
    # Initialiser la base de données
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


# Création de l'application
app = FastAPI(
    title="CryptoLogin API",
    version=settings.APP_VERSION,
    description="""
    ## CryptoLogin - Zero-Knowledge Authentication System
    
    **CryptoLogin** is a passwordless authentication system
    based on the concept of "zero-knowledge".
    
    ### Key Principles:
    - **Zero-Knowledge**: The server never knows your secret
    - **Military-Grade Cryptography**: AES-256-GCM + Argon2id
    - **Encrypted Data**: Vault protected by your secret
    - **Secure Sessions**: Configurable lifespan
    
    ### Authentication Flow:
    1. `/register` - Registration
    2. `/login/init` - Obtain Challenge
    3. `/login/verify` - VVerification and Session Creation
    4. Access Resources with Session ID
    """,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)


# ============================================================
# MIDDLEWARE
# ============================================================

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8080",           
        "http://localhost:8080",           
        "http://localhost:3000",           
        "http://localhost:8000",
        "https://erabytse.github.io",
        "http://localhost:3000",
        "http://localhost:8000",
        "https://erabytse.github.io/cryptologin-website/",
        "http://api.docudeeper.com",
    ] + settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Trusted Host
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # À configurer en production
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


@app.get("/")
async def root():
    """API root."""
    return {
        "name": "CryptoLogin",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/ping")
async def ping():
    """Simple ping to check if the API is active."""
    return {"pong": "alive"}