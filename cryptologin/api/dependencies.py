"""
Dependencies for the CryptoLogin API
"""
from typing import Optional
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from asyncio.log import logger

from ..core.user_manager import UserManager
from ..core.user_manager_v2 import UserManagerV2
from ..storage.sqlite import SQLiteStorage
from ..storage.sqlite_v2 import SQLiteStorageV2
from ..config import get_settings, Settings
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Singletons
_user_manager_instance = None
_user_manager_v2_instance = None
_storage_instance = None
_storage_v2_instance = None


# ============================================================
# STORAGE
# ============================================================

def get_storage(settings: Settings = Depends(get_settings)) -> SQLiteStorage:
    """Retourne l'instance de stockage V1."""
    global _storage_instance
    if _storage_instance is None:
        db_path = settings.DATABASE_URL.replace("sqlite:///", "")
        _storage_instance = SQLiteStorage(db_path=db_path, auto_migrate=True)
    return _storage_instance


def get_storage_v2(settings: Settings = Depends(get_settings)) -> SQLiteStorageV2:
    """Retourne l'instance de stockage V2."""
    global _storage_v2_instance
    if _storage_v2_instance is None:
        db_path = settings.DATABASE_URL.replace("sqlite:///", "")
        _storage_v2_instance = SQLiteStorageV2(db_path=db_path, auto_migrate=True)
    return _storage_v2_instance


# ============================================================
# USER MANAGER
# ============================================================

def get_user_manager(
    storage: SQLiteStorage = Depends(get_storage)
) -> UserManager:
    """Returns the UserManager instance V1 (legacy)."""
    global _user_manager_instance
    if _user_manager_instance is None:
        _user_manager_instance = UserManager(storage=storage, session_duration_hours=24)
    return _user_manager_instance


def get_user_manager_v2(
    storage_v2: SQLiteStorageV2 = Depends(get_storage_v2)
) -> UserManagerV2:
    """Returns the UserManager instance V2 (Zero-Knowledge)."""
    global _user_manager_v2_instance
    if _user_manager_v2_instance is None:
        _user_manager_v2_instance = UserManagerV2(
            storage=storage_v2,
            session_duration_hours=24,
            v1_compatible=False
        )
    return _user_manager_v2_instance


# ============================================================
# AUTHENTIFICATION
# ============================================================

security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    user_manager: UserManager = Depends(get_user_manager),
    user_manager_v2: UserManagerV2 = Depends(get_user_manager_v2)  # CORRECTION: Ajouter V2
) -> str:
    """Valide la session et retourne l'ID utilisateur."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = credentials.credentials
    logger.debug(f"Validating session for user: {user_id[:16]}...")
    
    # CORRECTION: Vérifier d'abord avec V2, puis V1
    if user_manager_v2.validate_session(user_id):
        logger.debug(f"Session validated (V2) for user: {user_id[:16]}...")
        return user_id
    elif user_manager.validate_session(user_id):
        logger.debug(f"Session validated (V1) for user: {user_id[:16]}...")
        return user_id
    else:
        logger.warning(f"Invalid or expired session for user: {user_id[:16]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================
# RATE LIMITING
# ============================================================

limiter = Limiter(key_func=get_remote_address)


def get_limiter() -> Limiter:
    return limiter


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "Rate limit exceeded",
            "detail": f"Too many requests. Please wait {exc.retry_after} seconds.",
            "status_code": status.HTTP_429_TOO_MANY_REQUESTS,
            "retry_after": exc.retry_after
        }
    )


def reset_singletons():
    """Réinitialise les singletons (pour les tests)."""
    global _user_manager_instance, _user_manager_v2_instance
    global _storage_instance, _storage_v2_instance
    _user_manager_instance = None
    _user_manager_v2_instance = None
    _storage_instance = None
    _storage_v2_instance = None