"""
CryptoLogin Data Vault
----------------------
Module de chiffrement des données utilisateur.

Le Data Vault assure que toutes les données sensibles des utilisateurs
sont chiffrées avant d'être stockées. La clé de chiffrement est dérivée
du master_secret, assurant que seul l'utilisateur peut accéder à ses
données.

Zero-Knowledge Architecture:
- Le serveur ne connaît jamais le master_secret
- Les données sont chiffrées côté serveur avec Flash512
- La clé est dérivée à la volée et effacée immédiatement
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
    Enregistrement chiffré du Data Vault.
    """
    encrypted_data: str  # Token Flash512 (AES-256-GCM)
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class DataVault:
    """
    Coffre-fort des données utilisateur.
    
    Responsabilités :
    - Chiffrer les données utilisateur avec Flash512
    - Déchiffrer les données utilisateur
    - Gérer la migration de données lors de la rotation de secret
    
    Sécurité :
    - AES-256-GCM avec Argon2id via Flash512
    - SecureBuffer pour l'effacement mémoire
    - Validation d'intégrité via GCM tag
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
        Chiffre des données avec le secret maître.
        
        Args:
            data: Données à chiffrer (dictionnaire ou chaîne)
            master_secret: Secret maître de l'utilisateur
            
        Returns:
            VaultRecord: Enregistrement contenant les données chiffrées
            
        Raises:
            InvalidSecretError: Si le secret est invalide
            DataVaultError: En cas d'erreur
        """
        logger.debug("Encrypting vault data...")
    
        # 1. Validation du secret
        try:
            self.crypto_engine._validate_secret(master_secret)
        except InvalidSecretError:
            raise
        
        # 2. Sérialisation des données
        try:
            if isinstance(data, dict):
                plaintext = json.dumps(data, ensure_ascii=False)
            elif isinstance(data, str):
                plaintext = data
            else:
                raise DataVaultError(f"Unsupported data type: {type(data)}")
        except Exception as e:
            raise DataVaultError(f"Data serialization failed: {e}")
        
        # 3. Chiffrement avec Flash512
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
        Déchiffre des données du Data Vault.
        
        Args:
            record: Enregistrement contenant les données chiffrées
            master_secret: Secret maître de l'utilisateur
            
        Returns:
            Dict[str, Any]: Données déchiffrées
            
        Raises:
            InvalidSecretError: Si le secret est invalide
            DecryptionError: Si le déchiffrement échoue
            IntegrityError: Si l'intégrité du token est compromise
            DataVaultError: En cas d'erreur
        """
        logger.debug("Decrypting vault data...")
        
        # 1. Validation du secret
        try:
            self.crypto_engine._validate_secret(master_secret)
        except InvalidSecretError:
            raise
        
        # 2. Vérification du record
        if not record or not record.encrypted_data:
            raise DataVaultError("Invalid vault record: empty data")
        
        # 3. Déchiffrement avec Flash512
        try:
            plaintext = self.crypto_engine.decrypt_data(
                record.encrypted_data,
                master_secret
            )
            
            # 4. Désérialisation
            try:
                data = json.loads(plaintext)
                logger.debug("Vault data decrypted successfully")
                return data
            except json.JSONDecodeError:
                # Si ce n'est pas du JSON, retourner comme chaîne
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
        Rotate le secret des données du Data Vault.
        
        Processus :
        1. Déchiffrer avec l'ancien secret
        2. Re-chiffrer avec le nouveau secret
        
        Args:
            record: Enregistrement à migrer
            old_secret: Ancien secret
            new_secret: Nouveau secret
            
        Returns:
            VaultRecord: Nouvel enregistrement avec le nouveau secret
            
        Raises:
            InvalidSecretError: Si un secret est invalide
            DataVaultError: En cas d'erreur
        """
        logger.debug("Rotating vault data...")
        
        try:
            # 1. Déchiffrer avec l'ancien secret
            plaintext = self.crypto_engine.decrypt_data(
                record.encrypted_data,
                old_secret
            )
            
            # 2. Re-chiffrer avec le nouveau secret
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
        Vérifie l'intégrité des données du Vault.
        
        Args:
            record: Enregistrement à vérifier
            master_secret: Secret maître
            
        Returns:
            bool: True si l'intégrité est valide ET le secret est correct
        """
        try:
            # Tenter de déchiffrer pour vérifier à la fois l'intégrité ET le secret
            self.decrypt_data(record, master_secret)
            return True
        except Exception:
            return False
    
    def is_vault_empty(self, record: Optional[VaultRecord]) -> bool:
        """
        Vérifie si le Vault est vide.
        
        Args:
            record: Enregistrement à vérifier
            
        Returns:
            bool: True si le Vault est vide
        """
        return record is None or not record.encrypted_data
    
    def create_empty_vault(self) -> VaultRecord:
        """
        Crée un Vault vide (pour les nouveaux utilisateurs).
        
        Returns:
            VaultRecord: Enregistrement avec des données vides chiffrées
        """
        # Note: Ceci est juste un placeholder. Le Vault est créé avec
        # un dictionnaire vide chiffré avec un secret temporaire.
        # Dans la pratique, le Vault est créé lors de l'enregistrement.
        empty_data = json.dumps({})
        # Utiliser un secret temporaire pour le chiffrement
        # Ceci sera remplacé lors du premier stockage réel
        temp_secret = "temporary_secret_do_not_use_in_production"
        try:
            encrypted = self.crypto_engine.encrypt_data(empty_data, temp_secret)
            return VaultRecord(encrypted_data=encrypted, version="1.0")
        except Exception:
            # En cas d'échec, créer un Vault vide sans chiffrement
            return VaultRecord(encrypted_data="empty_vault", version="1.0")
    
    def serialize_record(self, record: VaultRecord) -> Dict[str, Any]:
        """
        Sérialise un VaultRecord en dictionnaire pour stockage.
        
        Args:
            record: Enregistrement à sérialiser
            
        Returns:
            Dict[str, Any]: Dictionnaire prêt pour le stockage
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
        Désérialise un dictionnaire en VaultRecord.
        
        Args:
            data: Dictionnaire à désérialiser
            
        Returns:
            VaultRecord: Enregistrement reconstitué
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
    """Erreur du Data Vault"""
    pass