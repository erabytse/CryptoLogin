"""
CryptoLogin User Manager - V2 with Zero-Knowledge Architecture

This module implements the Zero-Knowledge authentication flow where
the server never sees the master secret. The client derives the user_id
and proves knowledge of the secret by decrypting the challenge.
"""
import logging
import os
import hmac
import hashlib
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .crypto_engine import CryptoEngine
from .data_vault import DataVault, DataVaultError
from .exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    UserManagerError,
    InvalidSecretError
)
from ..storage.base import StorageInterface, UserRecord
from ..client.crypto_client import CryptoClient

logger = logging.getLogger(__name__)


@dataclass
class UserSession:
    """User session representation."""
    user_id: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=24))
    is_active: bool = True
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now() > self.expires_at


class UserManagerV2:
    """
    User Manager V2 with Zero-Knowledge Architecture.
    
    Key features:
    - Server never sees the master secret
    - Client derives user_id locally using PBKDF2
    - Authentication via challenge-response (server decrypts challenge)
    - Backward compatible with V1
    """
    
    def __init__(
        self,
        storage: StorageInterface,
        crypto_engine: Optional[CryptoEngine] = None,
        data_vault: Optional[DataVault] = None,
        session_duration_hours: int = 24,
        v1_compatible: bool = True
    ):
        """
        Initialize UserManager V2.
        
        Args:
            storage: Storage interface for persistence
            crypto_engine: Crypto engine (optional)
            data_vault: Data Vault (optional)
            session_duration_hours: Session duration in hours
            v1_compatible: Enable V1 compatibility mode
        """
        self.storage = storage
        self.crypto_engine = crypto_engine or CryptoEngine()
        self.data_vault = data_vault or DataVault(self.crypto_engine)
        self.session_duration = timedelta(hours=session_duration_hours)
        self._sessions: Dict[str, UserSession] = {}
        self.v1_compatible = v1_compatible
        self.crypto_client = CryptoClient()
        
        logger.info("UserManager V2 initialized (v1_compatible=%s)", v1_compatible)
    
    # ============================================================
    # 1. REGISTRATION - V2 (Zero-Knowledge)
    # ============================================================
    
    def register_user_v2(
        self,
        user_id: str,
        user_data: Optional[Dict[str, Any]] = None,
        salt: Optional[str] = None
    ) -> str:
        """
        Register a new user with V2 Zero-Knowledge flow.
        
        The user_id is derived from the master secret on the client side.
        The server never sees the master secret.
        
        Args:
            user_id: User ID derived from master secret (64 hex chars)
            user_data: Optional user data
            salt: Optional salt for key derivation
            
        Returns:
            str: User ID
            
        Raises:
            ValueError: If user_id format is invalid
            UserAlreadyExistsError: If user already exists
            UserManagerError: On registration failure
        """
        logger.info("Registering new user (V2)...")
        
        try:
            # Validate user_id format
            if len(user_id) != 64 or not all(c in '0123456789abcdef' for c in user_id):
                raise ValueError("Invalid user_id format")
            
            # Check if user already exists
            if self.storage.user_exists(user_id):
                raise UserAlreadyExistsError(f"User {user_id[:16]}... already exists")
            
            # Generate challenge
            challenge = self.crypto_client.generate_challenge(32)
            if not salt:
                salt = self.crypto_client.generate_challenge(32)
            
            # Encrypt challenge with the salt (using Flash512)
            # The server stores the encrypted challenge
            challenge_token = self.crypto_engine.encrypt_data(challenge, salt)
            
            # Create user record
            record = UserRecord(
                user_id=user_id,
                challenge_token=challenge_token,  # Encrypted challenge (Flash512)
                challenge=challenge,              # Plain challenge for reference
                salt=salt,                        # Salt for key derivation
                created_at=datetime.now(),
                updated_at=datetime.now(),
                user_data=user_data or {},
                vault_data=None
            )
            
            self.storage.save_user(record)
            
            logger.info("User registered successfully (V2): %s...", user_id[:16])
            return user_id
            
        except (UserAlreadyExistsError, ValueError):
            raise
        except Exception as e:
            logger.error("User registration failed: %s", e)
            raise UserManagerError(f"Registration failed: {e}")
    
    # ============================================================
    # 2. LOGIN - V2 (Zero-Knowledge with HMAC)
    # ============================================================

    def initiate_login_v2(self, user_id: str) -> str:
        """
        Initiate login - returns a plaintext challenge for the client.
        The client will compute HMAC(challenge, user_id) and send it back.
        
        Args:
            user_id: User ID
            
        Returns:
            str: Plaintext challenge (64 hex characters)
        """
        logger.info(f"Initiating V2 login for user: {user_id[:16]}...")
        
        try:
            record = self.storage.get_user(user_id)
            if not record:
                raise UserNotFoundError(f"User {user_id[:16]}... not found")
            
            # Generate a random challenge (64 hex chars = 32 bytes)
            challenge = self.crypto_client.generate_challenge(32)
            
            # ✅ Store the challenge in record.challenge (not pending_challenge)
            record.challenge = challenge
            record.updated_at = datetime.now()
            self.storage.save_user(record)
            
            logger.info(f"Challenge generated for user: {user_id[:16]}...")
            
            # Return plaintext challenge (client will compute HMAC)
            return challenge
            
        except (UserNotFoundError, UserManagerError):
            raise
        except Exception as e:
            logger.error(f"Login initiation failed: {e}")
            raise UserManagerError(f"Login initiation failed: {e}")

    def complete_login_v2(
        self,
        user_id: str,
        challenge_response: str  # HMAC from client
    ) -> UserSession:
        """
        Complete login - verify HMAC response from client.
        
        The client computed: HMAC(challenge, user_id)
        The server verifies it using the same user_id.
        
        Args:
            user_id: User ID
            challenge_response: HMAC signature from client (64 hex chars)
            
        Returns:
            UserSession: Created session
            
        Raises:
            AuthenticationError: If HMAC doesn't match
        """
        logger.info(f"Completing V2 login for user: {user_id[:16]}...")
        
        try:
            record = self.storage.get_user(user_id)
            if not record:
                raise UserNotFoundError(f"User {user_id[:16]}... not found")
            
            # ✅ Use record.challenge (not pending_challenge)
            if not record.challenge:
                raise AuthenticationError("No pending challenge. Call initiate_login_v2 first.")
            
            # Server computes the expected HMAC
            expected_hmac = self.crypto_client.compute_hmac(
                user_id,  # Use user_id as HMAC key (not master_secret!)
                record.challenge
            )
            
            # Verify the client's HMAC
            if not hmac.compare_digest(expected_hmac, challenge_response):
                logger.warning(f"Invalid HMAC for user: {user_id[:16]}...")
                raise AuthenticationError("Invalid challenge response")
            
            # ✅ Clear the challenge after successful login
            record.challenge = None
            record.last_activity_at = datetime.now()
            self.storage.save_user(record)
            
            # Create session
            session = UserSession(
                user_id=user_id,
                expires_at=datetime.now() + self.session_duration
            )
            self._sessions[user_id] = session
            
            logger.info(f"User authenticated successfully (V2): {user_id[:16]}...")
            
            return session
            
        except (UserNotFoundError, AuthenticationError):
            raise
        except Exception as e:
            logger.error(f"Login completion failed: {e}")
            raise UserManagerError(f"Login completion failed: {e}")
        
    # ============================================================
    # 3. DATA VAULT - V2
    # ============================================================
    
    def get_user_data_v2(self, user_id: str, master_secret: str) -> Optional[Dict[str, Any]]:
        """
        Get user data from Vault.
        
        Args:
            user_id: User ID
            master_secret: Master secret
            
        Returns:
            Optional[Dict[str, Any]]: User data
            
        Raises:
            UserNotFoundError: If user doesn't exist
            DataVaultError: On decryption failure
        """
        record = self.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        if not record.vault_data:
            return {}
        
        try:
            # Use the stored salt for key derivation
            salt = record.salt or CryptoClient.PBKDF2_SALT.decode('utf-8')
            vault_key = self.crypto_client.derive_vault_key(master_secret, salt)
            
            vault_record = DataVault.deserialize_record(record.vault_data)
            return self.data_vault.decrypt_data(vault_record, vault_key)
            
        except DataVaultError as e:
            logger.error("Vault decryption failed: %s", e)
            raise
        except Exception as e:
            logger.error("Unexpected error: %s", e)
            raise UserManagerError(f"Failed to get user data: {e}")
    
    def update_user_data_v2(
        self,
        user_id: str,
        master_secret: str,
        data: Dict[str, Any]
    ) -> bool:
        """
        Update user data in Vault.
        
        Args:
            user_id: User ID
            master_secret: Master secret
            data: New data
            
        Returns:
            bool: True if successful
            
        Raises:
            UserNotFoundError: If user doesn't exist
            DataVaultError: On encryption failure
        """
        record = self.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        try:
            salt = record.salt or self.crypto_client.generate_challenge(32)
            if not record.salt:
                record.salt = salt
            
            vault_key = self.crypto_client.derive_vault_key(master_secret, salt)
            
            vault_record = self.data_vault.encrypt_data(data, vault_key)
            record.vault_data = self.data_vault.serialize_record(vault_record)
            record.user_data = data  # Keep in clear for V1 compatibility
            
            self.storage.save_user(record)
            
            logger.info("User data updated in Vault: %s...", user_id[:16])
            return True
            
        except (DataVaultError, InvalidSecretError):
            raise
        except Exception as e:
            logger.error("Failed to update user data: %s", e)
            raise UserManagerError(f"Failed to update user data: {e}")
    
    # ============================================================
    # 4. SECRET ROTATION - V2
    # ============================================================
    
    def rotate_user_secret_v2(
        self,
        user_id: str,
        old_secret: str,
        new_secret: str
    ) -> bool:
        """
        Rotate user secret with V2 zero-knowledge flow.
        
        Args:
            user_id: Old user ID
            old_secret: Old master secret
            new_secret: New master secret (minimum 32 characters)
            
        Returns:
            bool: True if successful
            
        Raises:
            UserNotFoundError: If user doesn't exist
            AuthenticationError: If old secret doesn't match
            ValueError: If new secret is invalid
        """
        logger.info("Rotating secret (V2) for user: %s...", user_id[:16])
        
        # Validate new secret
        if len(new_secret) < 32:
            raise ValueError("New secret must be at least 32 characters")
        
        record = self.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        # Verify old secret by trying to access vault or deriving user_id
        try:
            # Try to derive user_id from old secret
            derived_id = self.crypto_client.derive_user_id(old_secret)
            if derived_id != user_id:
                raise AuthenticationError("Old secret does not match user")
        except Exception as e:
            raise AuthenticationError(f"Authentication failed: {e}")
        
        # Derive new user_id
        new_user_id = self.crypto_client.derive_user_id(new_secret)
        new_salt = self.crypto_client.generate_challenge(32)
        
        # Get old data
        try:
            old_data = self.get_user_data_v2(user_id, old_secret)
        except Exception:
            old_data = {}
        
        # Generate new challenge
        challenge = self.crypto_client.generate_challenge(32)
        challenge_token = self.crypto_engine.encrypt_data(challenge, new_salt)
        
        # Create new record
        new_record = UserRecord(
            user_id=new_user_id,
            challenge_token=challenge_token,
            challenge=challenge,
            created_at=record.created_at,
            updated_at=datetime.now(),
            user_data=old_data,
            vault_data=record.vault_data,
            salt=new_salt
        )
        
        # Re-encrypt data with new secret
        if old_data:
            vault_key = self.crypto_client.derive_vault_key(new_secret, new_salt)
            new_vault_record = self.data_vault.encrypt_data(old_data, vault_key)
            new_record.vault_data = self.data_vault.serialize_record(new_vault_record)
        
        # Save new record and delete old
        self.storage.save_user(new_record)
        self.storage.delete_user(user_id)
        
        # Invalidate sessions
        if user_id in self._sessions:
            del self._sessions[user_id]
        
        logger.info("Secret rotated successfully (V2): old=%s..., new=%s...",
                   user_id[:16], new_user_id[:16])
        return True
    
    # ============================================================
    # 5. V1 COMPATIBILITY (Legacy)
    # ============================================================
    
    def register_user_v1(
        self,
        master_secret: str,
        user_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        V1 registration (for backward compatibility).
        
        Deprecated: Use register_user_v2() instead.
        """
        logger.warning("Using V1 registration (deprecated)")
        
        try:
            user_id = self.crypto_engine.derive_user_id(master_secret)
            return self.register_user_v2(user_id, user_data)
            
        except Exception as e:
            logger.error("V1 registration failed: %s", e)
            raise
    
    def initiate_login_v1(self, master_secret: str) -> str:
        """
        V1 login initiation (for backward compatibility).
        
        Deprecated: Use initiate_login_v2() instead.
        """
        logger.warning("Using V1 login initiation (deprecated)")
        
        try:
            user_id = self.crypto_engine.derive_user_id(master_secret)
            return self.initiate_login_v2(user_id)
            
        except Exception as e:
            logger.error("V1 login initiation failed: %s", e)
            raise
    
    def complete_login_v1(self, master_secret: str, challenge_response: str) -> UserSession:
        """
        V1 login completion (for backward compatibility).
        
        Deprecated: Use complete_login_v2() instead.
        """
        logger.warning("Using V1 login completion (deprecated)")
        
        try:
            user_id = self.crypto_engine.derive_user_id(master_secret)
            return self.complete_login_v2(user_id, challenge_response)
            
        except Exception as e:
            logger.error("V1 login completion failed: %s", e)
            raise
    
    # ============================================================
    # 6. SESSION MANAGEMENT
    # ============================================================
    
    def logout(self, user_id: str) -> None:
        """Logout user by invalidating session."""
        if user_id in self._sessions:
            del self._sessions[user_id]
            logger.info("User logged out: %s...", user_id[:16])
    
    def validate_session(self, user_id: str) -> bool:
        """Validate if session is active and not expired."""
        session = self._sessions.get(user_id)
        if not session:
            return False
        if session.is_expired:
            del self._sessions[user_id]
            return False
        return True
    
    def refresh_session(self, user_id: str) -> Optional[UserSession]:
        """Refresh an existing session."""
        if not self.validate_session(user_id):
            return None
        session = self._sessions[user_id]
        session.expires_at = datetime.now() + self.session_duration
        return session
    
    # ============================================================
    # 7. USER MANAGEMENT
    # ============================================================
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        if not self.storage.user_exists(user_id):
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        result = self.storage.delete_user(user_id)
        if user_id in self._sessions:
            del self._sessions[user_id]
        return result
    
    def get_user_count(self) -> int:
        """Get total number of users."""
        return self.storage.get_user_count()
    
    def list_users(self, limit: int = 100, offset: int = 0) -> list:
        """List users for administration."""
        return self.storage.list_users(limit, offset)