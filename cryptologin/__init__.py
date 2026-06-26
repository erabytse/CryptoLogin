"""
CryptoLogin - Zero-Knowledge-Inspired Passwordless Authentication
"""

__version__ = "2.0.0"
__author__ = "erabytse"
__license__ = "Apache-2.0"

# Core
from .core.crypto_engine import CryptoEngine
from .core.user_manager import UserManager
from .core.user_manager_v2 import UserManagerV2
from .core.data_vault import DataVault
from .core.exceptions import *

# Storage
from .storage.sqlite import SQLiteStorage
from .storage.memory import MemoryStorage
from .storage.sqlite_v2 import SQLiteStorageV2

# Client-side crypto (for WASM/JS)
from .client.crypto_client import CryptoClient

# Config
from .config import get_settings, Settings

# FastAPI App
from .main import app

# CLI (for entry point)
from . import cli


class CryptoLogin:
    """
    Main entry point for CryptoLogin V2 (Zero-Knowledge-Inspired).
    
    The `master_secret` NEVER leaves the client.
    The server only sees `user_id` and decrypted challenges.
    """
    
    def __init__(self, db_path: str = "cryptologin.db", use_v2: bool = True):
        """
        Initialize CryptoLogin.
        
        Args:
            db_path: Path to SQLite database
            use_v2: Use V2 Zero-Knowledge flow (default True)
        """
        if use_v2:
            self.storage = SQLiteStorageV2(db_path=db_path)
            self.user_manager = UserManagerV2(storage=self.storage)
            self._v2 = True
        else:
            self.storage = SQLiteStorage(db_path=db_path)
            self.user_manager = UserManager(storage=self.storage)
            self._v2 = False
        
        self.crypto_engine = CryptoEngine()
        self.crypto_client = CryptoClient()
    
    def register(self, user_id: str, user_data: dict = None) -> str:
        """
        Register a new user (V2).
        
        The `user_id` must be derived from `master_secret` on the client side.
        The server NEVER sees the `master_secret`.
        """
        if not self._v2:
            raise ValueError("V1 is deprecated. Use V2 with register_user_v2()")
        return self.user_manager.register_user_v2(user_id, user_data)
    
    def login_init(self, user_id: str) -> str:
        """
        Initiate login - returns encrypted challenge.
        
        The client must decrypt this challenge using the `master_secret`.
        """
        if not self._v2:
            raise ValueError("V1 is deprecated. Use V2 with initiate_login_v2()")
        return self.user_manager.initiate_login_v2(user_id)
    
    def login_verify(self, user_id: str, decrypted_challenge: str):
        """
        Verify login - sends decrypted challenge.
        
        The server verifies the decrypted challenge matches the stored one.
        """
        if not self._v2:
            raise ValueError("V1 is deprecated. Use V2 with complete_login_v2()")
        return self.user_manager.complete_login_v2(user_id, decrypted_challenge)
    
    # V1 Compatibility (deprecated)
    def register_v1(self, master_secret: str, user_data: dict = None) -> str:
        """DEPRECATED: Use register() instead."""
        import warnings
        warnings.warn("V1 is deprecated. Use register() with client-derived user_id.", DeprecationWarning)
        return self.user_manager.register_user_v1(master_secret, user_data)
    
    def login_init_v1(self, master_secret: str) -> str:
        """DEPRECATED: Use login_init() instead."""
        import warnings
        warnings.warn("V1 is deprecated. Use login_init() with user_id.", DeprecationWarning)
        return self.user_manager.initiate_login_v1(master_secret)
    
    def login_verify_v1(self, master_secret: str, challenge_response: str):
        """DEPRECATED: Use login_verify() instead."""
        import warnings
        warnings.warn("V1 is deprecated. Use login_verify() with user_id and decrypted challenge.", DeprecationWarning)
        return self.user_manager.complete_login_v1(master_secret, challenge_response)


# Export all
__all__ = [
    # Main class
    "CryptoLogin",
    # Core V2
    "CryptoEngine",
    "UserManager",
    "UserManagerV2",
    "DataVault",
    # Client
    "CryptoClient",
    # Storage
    "SQLiteStorage",
    "MemoryStorage",
    "SQLiteStorageV2",
    # Config
    "get_settings",
    "Settings",
    # App
    "app",
    # CLI
    "cli",
    # Exceptions
    "CryptoLoginError",
    "CryptoError",
    "InvalidSecretError",
    "DecryptionError",
    "IntegrityError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "AuthenticationError",
    "DataVaultError",
    # Version
    "__version__",
]