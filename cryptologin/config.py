"""
Configuration centralisée pour CryptoLogin
"""
from pydantic_settings import BaseSettings
from pydantic import Field, ConfigDict, field_validator
from typing import List, Optional, Union
import json


class Settings(BaseSettings):
    """Configuration de l'application"""
    
    # Application
    APP_NAME: str = "CryptoLogin"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # API
    API_PREFIX: str = "/api/v1"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Sécurité
    SECRET_KEY: str = Field(
        default="dev-secret-key-change-in-production-1234567890",
        alias="CRYPTOLOGIN_SECRET_KEY",
        description="Clé secrète pour JWT"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Database
    DATABASE_URL: str = "sqlite:///cryptologin.db"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # CORS - Accepter à la fois liste et JSON string
    ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"]
    )
    
    # Session
    SESSION_DURATION_HOURS: int = 24
    
    # Configuration Pydantic v2
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True
    )
    
    @field_validator('ALLOWED_ORIGINS', mode='before')
    @classmethod
    def parse_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse ALLOWED_ORIGINS from string to list."""
        if isinstance(v, str):
            try:
                # Try to parse as JSON
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
                # If it's a single string, wrap it
                return [parsed] if parsed else []
            except json.JSONDecodeError:
                # If it's a comma-separated string
                if ',' in v:
                    return [item.strip() for item in v.split(',') if item.strip()]
                # Single value
                return [v] if v else []
        return v


def get_settings() -> Settings:
    """Retourne l'instance de configuration."""
    return Settings()


# Instance globale
settings = get_settings()