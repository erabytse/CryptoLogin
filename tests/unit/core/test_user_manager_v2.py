"""
Unit tests for UserManager V2 (Zero-Knowledge Architecture)
"""
import pytest
from cryptologin.core.user_manager_v2 import UserManagerV2
from cryptologin.core.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError
)
from cryptologin.storage.memory import MemoryStorage
from cryptologin.client.crypto_client import CryptoClient


class TestUserManagerV2:
    """Test suite for UserManager V2 with Zero-Knowledge architecture."""
    
    @pytest.fixture
    def storage(self):
        return MemoryStorage()
    
    @pytest.fixture
    def user_manager(self, storage):
        return UserManagerV2(
            storage=storage,
            session_duration_hours=1,
            v1_compatible=False
        )
    
    @pytest.fixture
    def master_secret(self):
        # Exactly 32 characters
        return "MySuperSecureMasterSecret1234567890!@#$"
    
    @pytest.fixture
    def user_id(self, master_secret):
        return CryptoClient.derive_user_id(master_secret)
    
    @pytest.fixture
    def another_secret(self):
        # Exactly 32 characters
        return "AnotherSecret1234567890!@#$%^&*."
    
    @pytest.fixture
    def new_secret(self):
        # Exactly 32 characters
        return "NewSecret1234567890!@#$%^&*+koUlzO"
    
    # ============================================================
    # REGISTRATION TESTS
    # ============================================================
    
    def test_register_user_v2_success(self, user_manager, user_id):
        """Test successful V2 registration with client-derived user_id."""
        result = user_manager.register_user_v2(user_id, {"name": "Test User"})
        assert result == user_id
        assert user_manager.storage.user_exists(user_id) is True
    
    def test_register_user_v2_already_exists(self, user_manager, user_id):
        """Test registration of an already existing user."""
        user_manager.register_user_v2(user_id)
        with pytest.raises(UserAlreadyExistsError):
            user_manager.register_user_v2(user_id)
    
    def test_register_user_v2_invalid_id(self, user_manager):
        """Test registration with invalid user_id format."""
        with pytest.raises(ValueError):
            user_manager.register_user_v2("invalid_id")
    
    # ============================================================
    # LOGIN TESTS (Zero-Knowledge)
    # ============================================================
    
    def test_login_flow_v2_success(self, user_manager, user_id, master_secret):
        """Test complete V2 login flow with challenge-response."""
        # 1. Register
        user_manager.register_user_v2(user_id)
        
        # 2. Initiate login - get encrypted challenge
        encrypted_challenge = user_manager.initiate_login_v2(user_id)
        assert isinstance(encrypted_challenge, str)
        assert len(encrypted_challenge) > 0
        
        # 3. Client decrypts challenge using master_secret
        # In a real client, this would be done with Flash512 WASM
        # For testing, we use the crypto engine directly
        decrypted_challenge = user_manager.crypto_engine.decrypt_data(
            encrypted_challenge,
            user_manager.storage.get_user(user_id).salt
        )
        assert len(decrypted_challenge) == 64
        
        # 4. Complete login - verify decrypted challenge
        session = user_manager.complete_login_v2(user_id, decrypted_challenge)
        assert session.user_id == user_id
        assert session.is_active is True
    
    def test_login_flow_v2_wrong_response(self, user_manager, user_id):
        """Test V2 login with wrong decrypted challenge."""
        user_manager.register_user_v2(user_id)
        user_manager.initiate_login_v2(user_id)
        
        with pytest.raises(AuthenticationError):
            user_manager.complete_login_v2(user_id, "wrong_challenge_1234567890abcdef")
    
    def test_login_flow_v2_wrong_user(self, user_manager, user_id):
        """Test V2 login with non-existent user."""
        with pytest.raises(UserNotFoundError):
            user_manager.initiate_login_v2(user_id)
    
    # ============================================================
    # DATA VAULT TESTS
    # ============================================================
    
    def test_vault_encrypt_decrypt_v2(self, user_manager, user_id, master_secret):
        """Test Vault encryption and decryption with master_secret."""
        user_manager.register_user_v2(user_id)
        
        test_data = {"name": "Test User", "email": "test@example.com"}
        result = user_manager.update_user_data_v2(user_id, master_secret, test_data)
        assert result is True
        
        retrieved = user_manager.get_user_data_v2(user_id, master_secret)
        assert retrieved == test_data
    
    def test_vault_wrong_secret_v2(self, user_manager, user_id, master_secret, another_secret):
        """Test Vault access with wrong master_secret."""
        user_manager.register_user_v2(user_id)
        
        test_data = {"name": "Test User"}
        user_manager.update_user_data_v2(user_id, master_secret, test_data)
        
        # Should fail with wrong secret
        with pytest.raises(Exception):
            user_manager.get_user_data_v2(user_id, another_secret)
    
    # ============================================================
    # SECRET ROTATION TESTS
    # ============================================================
    
    def test_rotate_secret_v2_success(self, user_manager, user_id, master_secret, new_secret):
        """Test successful V2 secret rotation."""
        user_manager.register_user_v2(user_id)
        user_manager.update_user_data_v2(user_id, master_secret, {"name": "Test User"})
        
        result = user_manager.rotate_user_secret_v2(user_id, master_secret, new_secret)
        assert result is True
        
        # New secret should work
        new_user_id = CryptoClient.derive_user_id(new_secret)
        encrypted_challenge = user_manager.initiate_login_v2(new_user_id)
        decrypted = user_manager.crypto_engine.decrypt_data(
            encrypted_challenge,
            user_manager.storage.get_user(new_user_id).salt
        )
        session = user_manager.complete_login_v2(new_user_id, decrypted)
        assert session.user_id == new_user_id
    
    def test_rotate_secret_v2_wrong_old_secret(self, user_manager, user_id, another_secret, new_secret):
        """Test rotation with wrong old secret."""
        user_manager.register_user_v2(user_id)
        
        with pytest.raises(AuthenticationError):
            user_manager.rotate_user_secret_v2(user_id, another_secret, new_secret)
    
    # ============================================================
    # SESSION TESTS
    # ============================================================
    
    def test_session_validation_v2(self, user_manager, user_id, master_secret):
        """Test session validation after login."""
        user_manager.register_user_v2(user_id)
        encrypted = user_manager.initiate_login_v2(user_id)
        decrypted = user_manager.crypto_engine.decrypt_data(
            encrypted,
            user_manager.storage.get_user(user_id).salt
        )
        session = user_manager.complete_login_v2(user_id, decrypted)
        
        assert user_manager.validate_session(user_id) is True
        assert user_manager.validate_session("nonexistent") is False

    def test_session_expiration_v2(self):
        """Test session expiration with zero duration."""
        storage = MemoryStorage()
        user_manager = UserManagerV2(
            storage=storage,
            session_duration_hours=-1  # Negative duration to ensure expiration
        )
        master_secret = "TestSecret1234567890!@#$%^&*+koulZo"
        user_id = CryptoClient.derive_user_id(master_secret)
        
        user_manager.register_user_v2(user_id)
        encrypted = user_manager.initiate_login_v2(user_id)
        decrypted = user_manager.crypto_engine.decrypt_data(
            encrypted,
            user_manager.storage.get_user(user_id).salt
        )
        user_manager.complete_login_v2(user_id, decrypted)
        
        assert user_manager.validate_session(user_id) is False
    
    def test_logout_v2(self, user_manager, user_id, master_secret):
        """Test logout functionality."""
        user_manager.register_user_v2(user_id)
        encrypted = user_manager.initiate_login_v2(user_id)
        decrypted = user_manager.crypto_engine.decrypt_data(
            encrypted,
            user_manager.storage.get_user(user_id).salt
        )
        user_manager.complete_login_v2(user_id, decrypted)
        
        assert user_manager.validate_session(user_id) is True
        user_manager.logout(user_id)
        assert user_manager.validate_session(user_id) is False
    
    # ============================================================
    # USER MANAGEMENT TESTS
    # ============================================================
    
    def test_delete_user_v2(self, user_manager, user_id):
        """Test user deletion."""
        user_manager.register_user_v2(user_id)
        assert user_manager.storage.user_exists(user_id) is True
        
        result = user_manager.delete_user(user_id)
        assert result is True
        assert user_manager.storage.user_exists(user_id) is False
    
    def test_delete_user_not_found_v2(self, user_manager):
        """Test deletion of non-existent user."""
        with pytest.raises(UserNotFoundError):
            user_manager.delete_user("nonexistent")
    
    # ============================================================
    # V1 COMPATIBILITY TESTS
    # ============================================================
    
    def test_v1_compatibility_mode(self, storage, master_secret):
        """Test V1 compatibility mode."""
        user_manager = UserManagerV2(
            storage=storage,
            v1_compatible=True
        )
        
        # V1 registration
        user_id = user_manager.register_user_v1(master_secret, {"name": "Test"})
        assert user_manager.storage.user_exists(user_id) is True
        
        # V1 login
        encrypted = user_manager.initiate_login_v1(master_secret)
        decrypted = user_manager.crypto_engine.decrypt_data(
            encrypted,
            user_manager.storage.get_user(user_id).salt
        )
        
        # V1 login completion
        session = user_manager.complete_login_v1(master_secret, decrypted)
        assert session.user_id == user_id
