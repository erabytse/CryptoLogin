"""
Custom exceptions for CryptoLogin
"""
class CryptoLoginError(Exception):
    """Basic exception for CryptoLogin"""
    pass

class CryptoError(CryptoLoginError):
    """Generic cryptographic error"""
    pass

class InvalidSecretError(CryptoError):
    """The secret provided is invalid"""
    pass

class DecryptionError(CryptoError):
    """Decryption failed"""
    pass

class IntegrityError(CryptoError):
    """Data integrity is compromised"""
    pass

# ============================================================
# EXCEPTIONS DATA VAULT
# ============================================================

class DataVaultError(CryptoError):
    """Data Vault error"""
    pass

# ============================================================
# EXCEPTIONS USER MANAGER
# ============================================================

class UserManagerError(CryptoLoginError):
    """User Manager error"""
    pass

class UserNotFoundError(UserManagerError):
    """The user could not be found"""
    pass

class UserAlreadyExistsError(UserManagerError):
    """The user already exists"""
    pass

class AuthenticationError(UserManagerError):
    """Authentication error"""
    pass