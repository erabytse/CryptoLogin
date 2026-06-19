"""
Exceptions personnalisées pour CryptoLogin
"""
class CryptoLoginError(Exception):
    """Exception de base pour CryptoLogin"""
    pass

class CryptoError(CryptoLoginError):
    """Erreur cryptographique générique"""
    pass

class InvalidSecretError(CryptoError):
    """Le secret fourni est invalide"""
    pass

class DecryptionError(CryptoError):
    """Le déchiffrement a échoué"""
    pass

class IntegrityError(CryptoError):
    """L'intégrité des données est compromise"""
    pass

# ============================================================
# EXCEPTIONS DATA VAULT
# ============================================================

class DataVaultError(CryptoError):
    """Erreur du Data Vault"""
    pass

# ============================================================
# EXCEPTIONS USER MANAGER
# ============================================================

class UserManagerError(CryptoLoginError):
    """Erreur du gestionnaire d'utilisateurs"""
    pass

class UserNotFoundError(UserManagerError):
    """L'utilisateur n'a pas été trouvé"""
    pass

class UserAlreadyExistsError(UserManagerError):
    """L'utilisateur existe déjà"""
    pass

class AuthenticationError(UserManagerError):
    """Erreur d'authentification"""
    pass