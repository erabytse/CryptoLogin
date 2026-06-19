"""
CryptoLogin Core Cryptographic Engine
-------------------------------------
Module de sécurité fondamental basé sur flash512-vanguard.
Ce module fournit des fonctions de dérivation d'identifiant utilisateur, de chiffrement/déchiffrement,
"""
import os
import hashlib
import hmac
from typing import Optional, Tuple
from dataclasses import dataclass
import secrets

try:
    from flash512 import Flash512Vanguard
except ImportError as e:
    raise ImportError(
        "Flash512-Vanguard is required. Please install: pip install flash512-vanguard==2.1.1"
    ) from e

from .constants import MIN_SECRET_LENGTH, CHALLENGE_LENGTH
# Importer les exceptions depuis le module central
from .exceptions import (
    CryptoLoginError,
    CryptoError,
    InvalidSecretError,
    DecryptionError,
    IntegrityError
)


@dataclass(frozen=True)
class CryptoResult:
    success: bool
    data: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


class CryptoEngine:
    def __init__(self, use_argon2id: bool = True, min_secret_length: int = MIN_SECRET_LENGTH):
        self.use_argon2id = use_argon2id
        self.min_secret_length = min_secret_length
        self._verify_module_integrity()
    
    def _verify_module_integrity(self) -> None:
        try:
            if not hasattr(Flash512Vanguard, 'protect'):
                raise IntegrityError("Flash512 module integrity check failed")
        except Exception as e:
            raise IntegrityError(f"Module integrity verification failed: {e}")
    
    def _validate_secret(self, secret: str) -> None:
        if not secret:
            raise InvalidSecretError("Secret cannot be empty")
        if len(secret) < self.min_secret_length:
            raise InvalidSecretError(
                f"Secret must be at least {self.min_secret_length} characters "
                f"(current: {len(secret)})"
            )
    
    def derive_user_id(self, master_secret: str) -> str:
        self._validate_secret(master_secret)
        try:
            sha_hash = hashlib.sha512(master_secret.encode('utf-8')).digest()
            derived_key = hashlib.pbkdf2_hmac(
                'sha512',
                master_secret.encode('utf-8'),
                sha_hash[:16],
                100000,
                dklen=32
            )
            return derived_key.hex()
        except Exception as e:
            raise CryptoError(f"User ID derivation failed: {e}")
    
    def encrypt_data(self, plaintext: str, master_secret: str) -> str:
        self._validate_secret(master_secret)
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        try:
            return Flash512Vanguard.protect(plaintext, master_secret)
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}")
    
    def decrypt_data(self, token: str, master_secret: str) -> str:
        self._validate_secret(master_secret)
        if not token:
            raise ValueError("Token cannot be empty")
        try:
            return Flash512Vanguard.open(token, master_secret)
        except Exception as e:
            error_msg = str(e).lower()
            if "integrity" in error_msg or "tamper" in error_msg or "verify" in error_msg:
                raise IntegrityError(f"Token integrity check failed: {e}")
            raise DecryptionError(f"Decryption failed: {e}")
    
    def generate_challenge(self, master_secret: str) -> Tuple[str, str]:
        self._validate_secret(master_secret)
        try:
            plaintext_challenge = secrets.token_hex(CHALLENGE_LENGTH)
            challenge_token = self.encrypt_data(plaintext_challenge, master_secret)
            return challenge_token, plaintext_challenge
        except Exception as e:
            raise CryptoError(f"Challenge generation failed: {e}")
    
    def verify_challenge(self, challenge_token: str, user_response: str, master_secret: str) -> bool:
        try:
            stored_challenge = self.decrypt_data(challenge_token, master_secret)
            return hmac.compare_digest(stored_challenge, user_response)
        except (DecryptionError, IntegrityError):
            return False
        except Exception:
            return False
    
    def verify_token_integrity(self, token: str, master_secret: str) -> bool:
        try:
            return Flash512Vanguard.verify(token, master_secret)
        except Exception:
            return False
    
    def rotate_secret(self, token: str, old_secret: str, new_secret: str) -> str:
        self._validate_secret(old_secret)
        self._validate_secret(new_secret)
        
        if not token:
            raise ValueError("Token cannot be empty")
        
        try:
            if hasattr(Flash512Vanguard, 'rotate_secret'):
                return Flash512Vanguard.rotate_secret(token, old_secret, new_secret)
            else:
                plaintext = self.decrypt_data(token, old_secret)
                return self.encrypt_data(plaintext, new_secret)
        except DecryptionError as e:
            raise CryptoError(f"Secret rotation failed: {e}")
        except Exception as e:
            raise CryptoError(f"Secret rotation failed: {e}")