"""
CryptoLogin Data Vault
----------------------
User data encryption module.

The Data Vault ensures that all sensitive user data
is encrypted before being stored. The encryption key is derived
from the master_secret, ensuring that only the user can access their
data.

Passwordless Authentication without Password Storage Architecture:
- The server never knows the master_secret
- Data is encrypted on the server side using Flash512
- The key is derived on the fly and deleted immediately
"""
import json
import logging
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, field
from datetime import datetime

from .crypto_engine import CryptoEngine, InvalidSecretError, CryptoError
from .exceptions import (
    DecryptionError,
    IntegrityError,
    DataVaultError
)

logger = logging.getLogger(__name__)


@dataclass
class VaultRecord:
    """
    Encrypted Data Vault storage.
    """
    encrypted_data: str  # Token Flash512 (AES-256-GCM)
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class DataVault:
    """
    User data vault.
    
    Responsibilities:
    - Encrypt user data using Flash512
    - Decrypt user data
    - Manage data migration during secret rotation
    
    Security:
    - AES-256-GCM with Argon2id via Flash512
    - SecureBuffer for memory erasure
    - Integrity validation via GCM tag
    """
    
    def __init__(self, crypto_engine: Optional[CryptoEngine] = None):
        """
        Initialise le Data Vault.
        
        Args:
            crypto_engine: Moteur cryptographique (créé par défaut)
        """
        self.crypto_engine = crypto_engine or CryptoEngine()
        logger.info("DataVault initialized")
    
    # ============================================================
    # 1. CHIFFREMENT / DÉCHIFFREMENT
    # ============================================================
    
    def encrypt_data(
        self,
        data: Union[Dict[str, Any], str],
        master_secret: str
    ) -> VaultRecord:
        """
        Encrypt the data using the master secret.
        
        Args:
            data: Data to be encrypted (dictionary or string)
            master_secret: The user’s master secret
            
        Returns:
            VaultRecord: A record containing the encrypted data
            
        Raises:
            InvalidSecretError: If the secret is invalid
            DataVaultError: In the event of an error
        """
        logger.debug("Encrypting vault data...")
    
        # 1. Verification of confidentiality
        try:
            self.crypto_engine._validate_secret(master_secret)
        except InvalidSecretError:
            raise
        
        # 2. Data serialisation
        try:
            if isinstance(data, dict):
                plaintext = json.dumps(data, ensure_ascii=False)
            elif isinstance(data, str):
                plaintext = data
            else:
                raise DataVaultError(f"Unsupported data type: {type(data)}")
        except Exception as e:
            raise DataVaultError(f"Data serialization failed: {e}")
        
        # 3. Encryption with Flash512
        try:
            encrypted_token = self.crypto_engine.encrypt_data(
                plaintext,
                master_secret
            )
            
            record = VaultRecord(
                encrypted_data=encrypted_token,
                version="1.0"
            )
            
            logger.debug("Vault data encrypted successfully")
            return record
            
        except CryptoError as e:
            raise DataVaultError(f"Encryption failed: {e}")
        except Exception as e:
            raise DataVaultError(f"Unexpected error during encryption: {e}")
    
    def decrypt_data(
        self,
        record: VaultRecord,
        master_secret: str
    ) -> Dict[str, Any]:
        """
        Decrypts data from the Data Vault.
        
        Args:
            record: Record containing the encrypted data
            master_secret: The user’s master secret
            
        Returns:
            Dict[str, Any]: Decrypted data
            
        Raises:
            InvalidSecretError: If the secret is invalid
            DecryptionError: If decryption fails
            IntegrityError: If the token’s integrity is compromised
            DataVaultError: In the event of an error
        """
        logger.debug("Decrypting vault data...")
        
        # 1. Validation du secret
        try:
            self.crypto_engine._validate_secret(master_secret)
        except InvalidSecretError:
            raise
        
        # 2. Record verification
        if not record or not record.encrypted_data:
            raise DataVaultError("Invalid vault record: empty data")
        
        # 3. Decryption using Flash512
        try:
            plaintext = self.crypto_engine.decrypt_data(
                record.encrypted_data,
                master_secret
            )
            
            # 4. Deserialisation
            try:
                data = json.loads(plaintext)
                logger.debug("Vault data decrypted successfully")
                return data
            except json.JSONDecodeError:
                # If it is not JSON, return it as a string
                return {"_raw": plaintext}
                
        except (CryptoError, DecryptionError, IntegrityError) as e:
            raise DataVaultError(f"Decryption failed: {e}")
        except Exception as e:
            raise DataVaultError(f"Unexpected error during decryption: {e}")
    
    # ============================================================
    # 2. ROTATION DE SECRET
    # ============================================================
    
    def rotate_vault_data(
        self,
        record: VaultRecord,
        old_secret: str,
        new_secret: str
    ) -> VaultRecord:
        """
        Rotate the Data Vault data secret.
        
        Process:
        1. Decrypt using the old secret
        2. Re-encrypt using the new secret
        
        Arguments:
            record: Record to be migrated
            old_secret: Old secret
            new_secret: New secret
            
        Returns:
            VaultRecord: New record with the new secret
            
        Raises:
            InvalidSecretError: If a secret is invalid
            DataVaultError: In the event of an error
        """
        logger.debug("Rotating vault data...")
        
        try:
            # 1. Deciphering with the ancient secret
            plaintext = self.crypto_engine.decrypt_data(
                record.encrypted_data,
                old_secret
            )
            
            # 2. Re-encrypt using the new secret
            new_encrypted = self.crypto_engine.encrypt_data(
                plaintext,
                new_secret
            )
            
            new_record = VaultRecord(
                encrypted_data=new_encrypted,
                version=record.version,
                created_at=record.created_at,
                updated_at=datetime.now()
            )
            
            logger.debug("Vault data rotated successfully")
            return new_record
            
        except (CryptoError, DecryptionError, IntegrityError) as e:
            raise DataVaultError(f"Vault rotation failed: {e}")
        except Exception as e:
            raise DataVaultError(f"Unexpected error during vault rotation: {e}")
    
    # ============================================================
    # 3. UTILITAIRES
    # ============================================================
    
    def verify_vault_integrity(
        self,
        record: VaultRecord,
        master_secret: str
    ) -> bool:
        """
        Checks the integrity of the Vault data.
        
        Args:
            record: Record to check
            master_secret: Master secret
            
        Returns:
            bool: True if the integrity check passes AND the secret is correct
        """
        try:
            # Attempt to decrypt in order to verify both integrity AND confidentiality
            self.decrypt_data(record, master_secret)
            return True
        except Exception:
            return False
    
    def is_vault_empty(self, record: Optional[VaultRecord]) -> bool:
        """
        Checks whether the Vault is empty.
        
        Args:
            record: Record to check
            
        Returns:
            bool: True if the Vault is empty
        """
        return record is None or not record.encrypted_data
    
    def create_empty_vault(self) -> VaultRecord:
        """
        Creates an empty Vault (for new users).
        
        Returns:
            VaultRecord: Record with encrypted empty data
        """
        # Note: This is just a placeholder. The Vault is created with
        # an empty dictionary encrypted with a temporary secret.
        # In practice, the Vault is created upon registration.
        empty_data = json.dumps({})
        # Use a temporary secret for encryption
        # This will be replaced when the data is first actually stored
        temp_secret = "temporary_secret_do_not_use_in_production"
        try:
            encrypted = self.crypto_engine.encrypt_data(empty_data, temp_secret)
            return VaultRecord(encrypted_data=encrypted, version="1.0")
        except Exception:
            # En cas d'échec, créer un Vault vide sans chiffrement
            return VaultRecord(encrypted_data="empty_vault", version="1.0")
    
    def serialize_record(self, record: VaultRecord) -> Dict[str, Any]:
        """
        Serialises a VaultRecord into a dictionary for storage.
        
        Args:
            record: Record to be serialised
            
        Returns:
            Dict[str, Any]: Dictionary ready for storage
        """
        return {
            "encrypted_data": record.encrypted_data,
            "version": record.version,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat()
        }
    
    @classmethod
    def deserialize_record(cls, data: Dict[str, Any]) -> VaultRecord:
        """
        Deserialises a dictionary into a VaultRecord.
        
        Args:
            data: Dictionary to be deserialised
            
        Returns:
            VaultRecord: Reconstructed record
        """
        return VaultRecord(
            encrypted_data=data.get("encrypted_data", ""),
            version=data.get("version", "1.0"),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if "updated_at" in data else datetime.now()
        )


# ============================================================
# EXCEPTIONS SPÉCIFIQUES
# ============================================================

class DataVaultError(CryptoError):
    """Data Vault error"""
    pass