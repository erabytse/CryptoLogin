"""
Dépendances pour l'API CryptoLogin
"""
from typing import Optional
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

from ..core.user_manager import UserManager
from ..storage.sqlite import SQLiteStorage
from ..config import get_settings, Settings
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Singleton pour UserManager
_user_manager_instance = None
_storage_instance = None


# ============================================================
# STORAGE - Singleton
# ============================================================

def get_storage(settings: Settings = Depends(get_settings)) -> SQLiteStorage:
    """Retourne l'instance de stockage (Singleton)."""
    global _storage_instance
    if _storage_instance is None:
        db_path = settings.DATABASE_URL.replace("sqlite:///", "")
        _storage_instance = SQLiteStorage(db_path=db_path, auto_migrate=True)
    return _storage_instance


# ============================================================
# USER MANAGER - Singleton
# ============================================================

def get_user_manager(storage: SQLiteStorage = Depends(get_storage)) -> UserManager:
    """Retourne l'instance du UserManager (Singleton)."""
    global _user_manager_instance
    if _user_manager_instance is None:
        _user_manager_instance = UserManager(storage=storage, session_duration_hours=24)
    return _user_manager_instance


# ============================================================
# AUTHENTIFICATION
# ============================================================

security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    user_manager: UserManager = Depends(get_user_manager)
) -> str:
    """
    Valide la session et retourne l'ID utilisateur.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = credentials.credentials
    
    # Vérifier la session
    if not user_manager.validate_session(user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user_id


# ============================================================
# RATE LIMITING
# ============================================================

limiter = Limiter(key_func=get_remote_address)


def get_limiter() -> Limiter:
    """Retourne l'instance du rate limiter."""
    return limiter


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Gestionnaire personnalisé pour les erreurs de rate limiting.
    """
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "Rate limit exceeded",
            "detail": f"Too many requests. Please wait {exc.retry_after} seconds.",
            "status_code": status.HTTP_429_TOO_MANY_REQUESTS,
            "retry_after": exc.retry_after
        }
    )


# Réinitialiser les singletons pour les tests
def reset_singletons():
    """Réinitialise les singletons (pour les tests)."""
    global _user_manager_instance, _storage_instance
    _user_manager_instance = None
    _storage_instance = None