"""
Configuration centralisée pour CryptoLogin
"""
from pydantic_settings import BaseSettings
from pydantic import Field, ConfigDict
from typing import List, Optional


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
    
    # Sécurité - Utiliser alias pour correspondre au nom de la variable d'environnement
    SECRET_KEY: str = Field(..., alias="CRYPTOLOGIN_SECRET_KEY", description="Clé secrète pour JWT")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Database
    DATABASE_URL: str = "sqlite:///cryptologin.db"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # CORS
    ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"]
    )
    
    # Configuration Pydantic v2
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignorer les champs supplémentaires
        populate_by_name=True  # Permettre l'utilisation du nom ou de l'alias
    )


def get_settings() -> Settings:
    """Retourne l'instance de configuration."""
    return Settings()


# Instance globale
settings = get_settings()