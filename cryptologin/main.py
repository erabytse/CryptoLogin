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
    
    **CryptoLogin** est un système d'authentification sans mot de passe
    basé sur le concept de "zero-knowledge".
    
    ### Principes clés:
    - **Zero-Knowledge**: Le serveur ne connaît jamais votre secret
    - **Cryptographie militaire**: AES-256-GCM + Argon2id
    - **Données chiffrées**: Vault protégé par votre secret
    - **Sessions sécurisées**: Durée de vie configurable
    
    ### Flux d'authentification:
    1. `/register` - Enregistrement
    2. `/login/init` - Obtention du challenge
    3. `/login/verify` - Vérification et création de session
    4. Accès aux ressources avec le session_id
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
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    """Racine de l'API."""
    return {
        "name": "CryptoLogin",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/ping")
async def ping():
    """Ping simple pour vérifier que l'API est active."""
    return {"pong": "alive"}