"""
Routes de santé - Pas de rate limiting nécessaire
"""
from typing import Any
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from datetime import datetime

from ...config import get_settings, Settings
from ...storage.sqlite import SQLiteStorage
from ..dependencies import get_storage

router = APIRouter(prefix="/health", tags=["Health"])


class HealthResponse(BaseModel):
    """Réponse de santé."""
    status: str
    version: str
    timestamp: str
    database: str
    uptime: str


class ReadyResponse(BaseModel):
    """Réponse de disponibilité."""
    ready: bool
    database: bool


@router.get("", response_model=HealthResponse)
async def health_check(
    settings: Settings = Depends(get_settings)
) -> Any:
    """Vérifie l'état de santé de l'application."""
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        timestamp=datetime.now().isoformat(),
        database="sqlite",
        uptime="running"
    )


@router.get("/ready", response_model=ReadyResponse)
async def ready_check(
    storage: SQLiteStorage = Depends(get_storage)
) -> Any:
    """Vérifie si l'application est prête à servir."""
    try:
        storage.get_user_count()
        db_ready = True
    except Exception:
        db_ready = False
    
    return ReadyResponse(
        ready=db_ready,
        database=db_ready
    )