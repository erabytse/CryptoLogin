"""
CryptoLogin -  Passwordless Authentication without Password Storage
"""

__version__ = "1.0.0"
__author__ = "CryptoLogin Team by erabytse"
__license__ = "Apache-2.0"

from .core.crypto_engine import CryptoEngine
from .core.user_manager import UserManager
from .core.data_vault import DataVault
from .core.exceptions import (
    CryptoLoginError,
    CryptoError,
    InvalidSecretError,
    DecryptionError,
    IntegrityError,
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    DataVaultError,
)
from .storage.sqlite import SQLiteStorage
from .storage.memory import MemoryStorage
from .config import get_settings, Settings
from .main import app


class CryptoLogin:
    """
    Main entry point for CryptoLogin.
    
    Example:
        >>> from cryptologin import CryptoLogin
        >>> auth = CryptoLogin()
        >>> user_id = auth.register("my-secret", {"name": "John"})
    """
    
    def __init__(self, db_path: str = "cryptologin.db"):
        from .core.user_manager import UserManager
        from .storage.sqlite import SQLiteStorage
        from .core.crypto_engine import CryptoEngine
        
        self.storage = SQLiteStorage(db_path=db_path)
        self.crypto_engine = CryptoEngine()
        self.user_manager = UserManager(storage=self.storage)
    
    def register(self, master_secret: str, user_data: dict = None) -> str:
        """Register a new user."""
        return self.user_manager.register_user(master_secret, user_data)
    
    def login_init(self, master_secret: str) -> str:
        """Initiate login - returns challenge."""
        return self.user_manager.initiate_login(master_secret)
    
    def login_verify(self, master_secret: str, challenge_response: str):
        """Complete login - returns session."""
        return self.user_manager.complete_login(master_secret, challenge_response)
    
    def get_user_data(self, user_id: str, master_secret: str) -> dict:
        """Get user data."""
        return self.user_manager.get_user_data(user_id, master_secret)
    
    def update_user_data(self, user_id: str, master_secret: str, data: dict) -> bool:
        """Update user data."""
        return self.user_manager.update_user_data(user_id, master_secret, data)
    
    def delete_user(self, user_id: str, master_secret: str) -> bool:
        """Delete a user."""
        from .core.exceptions import AuthenticationError
        # Verify secret matches
        derived_id = self.crypto_engine.derive_user_id(master_secret)
        if derived_id != user_id:
            raise AuthenticationError("Secret does not match user")
        return self.user_manager.delete_user(user_id)


# Export cli main for entry point
from . import cli


__all__ = [
    "CryptoLogin",
    "CryptoEngine",
    "UserManager",
    "DataVault",
    "SQLiteStorage",
    "MemoryStorage",
    "CryptoLoginError",
    "CryptoError",
    "InvalidSecretError",
    "DecryptionError",
    "IntegrityError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "AuthenticationError",
    "DataVaultError",
    "get_settings",
    "Settings",
    "app",
    "__version__",
    "cli",
]