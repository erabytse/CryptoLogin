"""
Pydantic models for the CryptoLogin API – Pydantic v2
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any
from datetime import datetime

# ============================================================
# REQUESTS
# ============================================================

class RegisterRequest(BaseModel):
    """Application for registration."""
    master_secret: str = Field(..., min_length=32, description="User’s secret master key")
    user_data: Optional[Dict[str, Any]] = Field(default=None, description="Initial user data")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class LoginInitRequest(BaseModel):
    """Request for login initialization."""
    master_secret: str = Field(..., min_length=32, description="User’s secret master key")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class LoginVerifyRequest(BaseModel):
    """Request for login verification."""
    master_secret: str = Field(..., min_length=32, description="User’s secret master key")
    challenge_response: str = Field(..., description="Response to the challenge (decrypted)")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class UpdateDataRequest(BaseModel):
    """Request for updating user data."""
    master_secret: str = Field(..., min_length=32, description="User’s secret master key")
    data: Dict[str, Any] = Field(..., description="New data")
    
    @field_validator('master_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class RotateSecretRequest(BaseModel):
    """Request for rotating the master secret."""
    old_secret: str = Field(..., min_length=32, description="Old master secret")
    new_secret: str = Field(..., min_length=32, description="New master secret")
    
    @field_validator('old_secret', 'new_secret')
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Master secret must be at least 32 characters')
        return v


class DeleteUserRequest(BaseModel):
    """Request for deleting a user."""
    master_secret: str = Field(..., min_length=32, description="User’s secret master key")
    
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
    """User response."""
    user_id: str
    created_at: datetime
    updated_at: datetime
    last_activity_at: Optional[datetime]
    has_data: bool
    has_vault: bool


class DataResponse(BaseModel):
    """Data response."""
    data: Dict[str, Any]
    version: str = "1.0"


class AuthInitResponse(BaseModel):
    """Response for login initialization."""
    challenge: str
    message: str = "Please decrypt the challenge and submit it with /verify"


class AuthResponse(BaseModel):
    """Response for authentication."""
    user_id: str
    session_id: str
    expires_at: datetime
    message: str = "Authentication successful"


class MessageResponse(BaseModel):
    """Response for simple messages."""
    message: str
    success: bool = True
    data: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Response for error messages."""
    error: str
    detail: Optional[str] = None
    status_code: int