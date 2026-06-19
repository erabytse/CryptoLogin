"""
Constantes globales du coeur cryptographique
"""
import os

# Sécurité
MIN_SECRET_LENGTH = 32  # 32 caractères minimum pour un secret maître
CHALLENGE_LENGTH = 32   # 32 octets (64 caractères hexadécimaux)

# Messages d'erreur (en anglais pour audience internationale)
ERROR_INVALID_SECRET = "Invalid master secret: {reason}"
ERROR_DECRYPTION_FAILED = "Decryption failed: possible incorrect secret or corrupted data"
ERROR_INTEGRITY_FAILED = "Token integrity check failed: data may have been tampered with"
ERROR_CRYPTO_OPERATION = "Cryptographic operation failed: {details}"

# Environnement
DEFAULT_USE_ARGON2ID = True