"""
CryptoLogin User Manager - with Data Vault
"""
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .crypto_engine import CryptoEngine
from .data_vault import DataVault, VaultRecord, DataVaultError
from .exceptions import (
    DecryptionError,
    IntegrityError,
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    UserManagerError,
    InvalidSecretError
)
from ..storage.base import StorageInterface, UserRecord


logger = logging.getLogger(__name__)


@dataclass
class UserSession:
    user_id: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=24))
    is_active: bool = True
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at


class UserManager:
    def __init__(
        self,
        storage: StorageInterface,
        crypto_engine: Optional[CryptoEngine] = None,
        data_vault: Optional[DataVault] = None,
        session_duration_hours: int = 24
    ):
        self.storage = storage
        self.crypto_engine = crypto_engine or CryptoEngine()
        self.data_vault = data_vault or DataVault(self.crypto_engine)
        self.session_duration = timedelta(hours=session_duration_hours)
        self._sessions: Dict[str, UserSession] = {}
        logger.info("UserManager initialized with DataVault")
    
    # ============================================================
    # 1. ENREGISTREMENT
    # ============================================================
    
    def register_user(
        self,
        master_secret: str,
        user_data: Optional[Dict[str, Any]] = None
    ) -> str:
        logger.info("Registering new user...")
        try:
            user_id = self.crypto_engine.derive_user_id(master_secret)
            
            if self.storage.user_exists(user_id):
                raise UserAlreadyExistsError(f"User {user_id[:16]}... already exists")
            
            # 1. Générer le challenge
            challenge_token, _ = self.crypto_engine.generate_challenge(master_secret)
            
            # 2. Chiffrer les données utilisateur avec le Vault
            vault_record = self.data_vault.encrypt_data(
                user_data or {},
                master_secret
            )
            
            # 3. Sérialiser le VaultRecord pour le stockage
            vault_serialized = self.data_vault.serialize_record(vault_record)
            
            # 4. Créer l'enregistrement
            record = UserRecord(
                user_id=user_id,
                challenge_token=challenge_token,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                user_data=user_data or {},  # Garder une copie en clair comme fallback
                vault_data=vault_serialized
            )
            
            self.storage.save_user(record)
            logger.info("User registered successfully with Vault: %s...", user_id[:16])
            return user_id
            
        except (InvalidSecretError, UserAlreadyExistsError):
            raise
        except Exception as e:
            logger.error("User registration failed: %s", e)
            raise UserManagerError(f"Registration failed: {e}")
    
    # ============================================================
    # 2. AUTHENTIFICATION
    # ============================================================
    
    def initiate_login(self, master_secret: str) -> str:
        logger.info("Initiating login...")
        try:
            user_id = self.crypto_engine.derive_user_id(master_secret)
            logger.debug("User ID derived: %s...", user_id[:16])
            
            record = self.storage.get_user(user_id)
            if not record:
                raise UserNotFoundError(f"User {user_id[:16]}... not found")
            
            try:
                plaintext_challenge = self.crypto_engine.decrypt_data(
                    record.challenge_token,
                    master_secret
                )
                self.storage.update_user_activity(user_id)
                return plaintext_challenge
            except Exception as e:
                raise AuthenticationError("Authentication failed: invalid secret or corrupted challenge")
            
        except (InvalidSecretError, UserNotFoundError, AuthenticationError):
            raise
        except Exception as e:
            logger.error("Login initiation failed: %s", e)
            raise UserManagerError(f"Login initiation failed: {e}")
    
    def complete_login(self, master_secret: str, user_response: str) -> UserSession:
        logger.info("Completing login...")
        try:
            user_id = self.crypto_engine.derive_user_id(master_secret)
            
            record = self.storage.get_user(user_id)
            if not record:
                raise UserNotFoundError(f"User {user_id[:16]}... not found")
            
            is_valid = self.crypto_engine.verify_challenge(
                record.challenge_token,
                user_response,
                master_secret
            )
            
            if not is_valid:
                raise AuthenticationError("Authentication failed: invalid response")
            
            session = UserSession(
                user_id=user_id,
                expires_at=datetime.now() + self.session_duration
            )
            self._sessions[user_id] = session
            self.storage.update_user_activity(user_id)
            
            logger.info("User authenticated successfully: %s...", user_id[:16])
            return session
            
        except (InvalidSecretError, UserNotFoundError, AuthenticationError):
            raise
        except Exception as e:
            logger.error("Login completion failed: %s", e)
            raise UserManagerError(f"Login completion failed: {e}")
    
    # ============================================================
    # 3. GESTION DES SESSIONS
    # ============================================================
    
    def logout(self, user_id: str) -> None:
        if user_id in self._sessions:
            del self._sessions[user_id]
            logger.info("User logged out: %s...", user_id[:16])
    
    def validate_session(self, user_id: str) -> bool:
        session = self._sessions.get(user_id)
        if not session:
            return False
        if session.is_expired:
            del self._sessions[user_id]
            return False
        return True
    
    def refresh_session(self, user_id: str) -> Optional[UserSession]:
        if not self.validate_session(user_id):
            return None
        session = self._sessions[user_id]
        session.expires_at = datetime.now() + self.session_duration
        return session
    
    # ============================================================
    # 4. GESTION DES DONNÉES - AVEC DATA VAULT
    # ============================================================
    
    def get_user_data(self, user_id: str, master_secret: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves user data from the Vault.
        
        Args:
            user_id: User ID
            master_secret: Master secret for decryption
            
        Returns:
            Optional[Dict[str, Any]]: Decrypted data
        """
        record = self.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        # Si vault_data est None ou vide, utiliser user_data comme fallback
        if not record.vault_data:
            return record.user_data or {}
        
        try:
            # Désérialiser vault_data
            if isinstance(record.vault_data, str):
                try:
                    vault_dict = json.loads(record.vault_data)
                except json.JSONDecodeError:
                    vault_dict = record.vault_data
            else:
                vault_dict = record.vault_data
            
            # Si c'est un dictionnaire avec encrypted_data, déchiffrer
            if isinstance(vault_dict, dict) and 'encrypted_data' in vault_dict:
                vault_record = DataVault.deserialize_record(vault_dict)
                return self.data_vault.decrypt_data(vault_record, master_secret)
            else:
                # Si le format est incorrect, retourner user_data comme fallback
                logger.warning("Invalid vault data format for user %s..., using user_data fallback", user_id[:16])
                return record.user_data or {}
                
        except (DataVaultError, DecryptionError, IntegrityError) as e:
            logger.warning("Vault decryption failed for user %s..., using user_data fallback: %s", user_id[:16], e)
            # RETOURNER user_data COMME FALLBACK au lieu de lever une exception
            return record.user_data or {}
        except Exception as e:
            logger.error("Unexpected error getting user data: %s", e)
            return record.user_data or {}
    
    def update_user_data(
        self,
        user_id: str,
        master_secret: str,
        new_data: Dict[str, Any]
    ) -> bool:
        """
        Met à jour les données utilisateur dans le Vault.
        """
        record = self.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        try:
            # Vérifier que le secret correspond
            derived_id = self.crypto_engine.derive_user_id(master_secret)
            if derived_id != user_id:
                raise AuthenticationError("Secret does not match user")
            
            # CORRECTION: Mettre à jour user_data en clair (fallback)
            record.user_data = new_data
            
            # Chiffrer les nouvelles données dans le Vault
            vault_record = self.data_vault.encrypt_data(new_data, master_secret)
            record.vault_data = self.data_vault.serialize_record(vault_record)
            record.updated_at = datetime.now()
            
            self.storage.save_user(record)
            
            logger.info("User data updated in Vault: %s...", user_id[:16])
            return True
            
        except (InvalidSecretError, AuthenticationError):
            raise
        except Exception as e:
            logger.error("Failed to update user data: %s", e)
            raise UserManagerError(f"Failed to update user data: {e}")
        
    # ============================================================
    # 5. ROTATION DE SECRET
    # ============================================================
    
    def rotate_user_secret(self, user_id: str, old_secret: str, new_secret: str) -> bool:
        logger.info("Rotating secret for user: %s...", user_id[:16])
        
        record = self.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        try:
            # 1. Valider les secrets
            self.crypto_engine._validate_secret(old_secret)
            self.crypto_engine._validate_secret(new_secret)
            
            # 2. Vérifier l'ancien secret
            derived_id = self.crypto_engine.derive_user_id(old_secret)
            if derived_id != user_id:
                raise AuthenticationError("Old secret does not match user")
            
            # 3. Rotation du challenge
            plaintext_challenge = self.crypto_engine.decrypt_data(
                record.challenge_token,
                old_secret
            )
            new_challenge_token = self.crypto_engine.encrypt_data(
                plaintext_challenge,
                new_secret
            )
            
            # 4. Rotation du Vault
            new_vault_data = None
            if record.vault_data:
                vault_record = DataVault.deserialize_record(record.vault_data)
                new_vault_record = self.data_vault.rotate_vault_data(
                    vault_record,
                    old_secret,
                    new_secret
                )
                new_vault_data = self.data_vault.serialize_record(new_vault_record)
            
            # 5. Dériver le nouvel ID
            new_user_id = self.crypto_engine.derive_user_id(new_secret)
            
            # 6. Supprimer l'ancien enregistrement
            self.storage.delete_user(user_id)
            
            # 7. Créer le nouvel enregistrement
            new_record = UserRecord(
                user_id=new_user_id,
                challenge_token=new_challenge_token,
                created_at=record.created_at,
                updated_at=datetime.now(),
                user_data={},
                vault_data=new_vault_data,
                last_activity_at=record.last_activity_at
            )
            self.storage.save_user(new_record)
            
            # 8. Invalider les sessions
            if user_id in self._sessions:
                del self._sessions[user_id]
            
            logger.info("Secret rotated with Vault: old=%s..., new=%s...",
                       user_id[:16], new_user_id[:16])
            return True
            
        except (InvalidSecretError, AuthenticationError):
            raise
        except Exception as e:
            logger.error("Secret rotation failed: %s", e)
            raise UserManagerError(f"Secret rotation failed: {e}")
    
    # ============================================================
    # 6. SUPPRESSION
    # ============================================================
    
    def delete_user(self, user_id: str) -> bool:
        if not self.storage.user_exists(user_id):
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        result = self.storage.delete_user(user_id)
        if user_id in self._sessions:
            del self._sessions[user_id]
        return result
    
    # ============================================================
    # 7. UTILITAIRES
    # ============================================================
    
    def get_user_count(self) -> int:
        return self.storage.get_user_count()
    
    def list_users(self, limit: int = 100, offset: int = 0) -> list:
        return self.storage.list_users(limit, offset)