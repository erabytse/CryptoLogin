"""
Modèles Pydantic pour l'API CryptoLogin - Version Pydantic v2
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any
from datetime import datetime

# ============================================================
# REQUESTS
# ============================================================

class RegisterRequest(BaseModel):
    """Requête d'enregistrement."""
    master_secret: str = Field(..., min_length=32, description="Secret maître de l'utilisateur")
    user_data: Optional[Dict[str, Any]] = Field(default=None, description="Données initiales de l'utilisateur")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class LoginInitRequest(BaseModel):
    """Requête d'initiation de login."""
    master_secret: str = Field(..., min_length=32, description="Secret maître de l'utilisateur")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class LoginVerifyRequest(BaseModel):
    """Requête de vérification de login."""
    master_secret: str = Field(..., min_length=32, description="Secret maître de l'utilisateur")
    challenge_response: str = Field(..., description="Réponse au challenge (déchiffré)")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class UpdateDataRequest(BaseModel):
    """Requête de mise à jour des données."""
    master_secret: str = Field(..., min_length=32, description="Secret maître de l'utilisateur")
    data: Dict[str, Any] = Field(..., description="Nouvelles données")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class RotateSecretRequest(BaseModel):
    """Requête de rotation de secret."""
    old_secret: str = Field(..., min_length=32, description="Ancien secret")
    new_secret: str = Field(..., min_length=32, description="Nouveau secret")
    
    @field_validator('old_secret', 'new_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Secret must be at least 32 characters')
        return v


class DeleteUserRequest(BaseModel):
    """Requête de suppression d'utilisateur."""
    master_secret: str = Field(..., min_length=32, description="Secret maître de l'utilisateur")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v

# ============================================================
# RESPONSES
# ============================================================


class UserResponse(BaseModel):
    """Réponse utilisateur."""
    user_id: str
    created_at: datetime
    updated_at: datetime
    last_activity_at: Optional[datetime]
    has_data: bool
    has_vault: bool


class DataResponse(BaseModel):
    """Réponse des données."""
    data: Dict[str, Any]
    version: str = "1.0"


class AuthInitResponse(BaseModel):
    """Réponse d'initiation de login."""
    challenge: str
    message: str = "Please decrypt the challenge and submit it with /verify"


class AuthResponse(BaseModel):
    """Réponse d'authentification."""
    user_id: str
    session_id: str
    expires_at: datetime
    message: str = "Authentication successful"


class MessageResponse(BaseModel):
    """Réponse de message simple."""
    message: str
    success: bool = True
    data: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Réponse d'erreur."""
    error: str
    detail: Optional[str] = None
    status_code: int