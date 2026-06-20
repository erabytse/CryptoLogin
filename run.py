#!/usr/bin/env python
"""
Script de lancement de CryptoLogin API
"""
import uvicorn
from cryptologin.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    
    uvicorn.run(
        "cryptologin.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )