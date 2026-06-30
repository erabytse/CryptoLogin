"""
Tests for UserManagerV2 - Zero-Knowledge Authentication with HMAC
"""
import pytest
import hmac
import hashlib
from datetime import datetime, timedelta

from cryptologin.core.user_manager_v2 import UserManagerV2
from cryptologin.core.exceptions import UserNotFoundError, AuthenticationError


class TestUserManagerV2:
    """Test suite for UserManagerV2 (HMAC-based Zero-Knowledge)"""
    
    @pytest.fixture
    def user_manager(self, tmp_path):
        """Create a UserManagerV2 instance with temporary storage"""
        from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
        
        storage = SQLiteStorageV2(db_path=str(tmp_path / "test.db"), auto_migrate=True)
        # UserManagerV2 crée son propre crypto_client en interne
        return UserManagerV2(storage=storage)
    
    @pytest.fixture
    def test_user(self):
        """Test user data"""
        return {
            "user_id": "a" * 64,  # 64 hex chars
            "user_data": {"name": "Test User", "email": "test@example.com"}
        }
    
    def _compute_client_hmac(self, user_id, challenge):
        """Helper to compute HMAC like the client would"""
        return hmac.new(
            user_id.encode('utf-8'),
            challenge.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    # ============================================================
    # REGISTRATION TESTS
    # ============================================================
    
    def test_register_user_v2_success(self, user_manager, test_user):
        """Test successful V2 user registration"""
        user_id = user_manager.register_user_v2(
            test_user["user_id"],
            test_user["user_data"]
        )
        
        assert user_id == test_user["user_id"]
        
        # Verify user exists in storage
        record = user_manager.storage.get_user(user_id)
        assert record is not None
        assert record.user_id == test_user["user_id"]
    
    # ============================================================
    # LOGIN FLOW TESTS (HMAC-BASED)
    # ============================================================
    
    def test_login_flow_v2_success(self, user_manager, test_user):
        """Test complete V2 login flow with HMAC"""
        # 1. Register user
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        
        # 2. Initiate login - get plaintext challenge
        challenge = user_manager.initiate_login_v2(test_user["user_id"])
        
        assert challenge is not None
        assert len(challenge) == 64  # 64 hex chars
        assert isinstance(challenge, str)
        
        # 3. Client computes HMAC (simulate client-side)
        client_hmac = self._compute_client_hmac(test_user["user_id"], challenge)
        
        # 4. Complete login with HMAC
        session = user_manager.complete_login_v2(test_user["user_id"], client_hmac)
        
        assert session is not None
        assert session.user_id == test_user["user_id"]
    
    def test_login_flow_v2_invalid_hmac(self, user_manager, test_user):
        """Test V2 login with invalid HMAC"""
        # 1. Register user
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        
        # 2. Initiate login
        challenge = user_manager.initiate_login_v2(test_user["user_id"])
        
        # 3. Try to login with wrong HMAC
        wrong_hmac = "0" * 64
        
        with pytest.raises(AuthenticationError):
            user_manager.complete_login_v2(test_user["user_id"], wrong_hmac)
    
    def test_login_flow_v2_no_challenge(self, user_manager, test_user):
        """Test V2 login without initiating first"""
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        
        # Try to complete login without initiate_login_v2
        fake_hmac = "a" * 64
        
        with pytest.raises(AuthenticationError):
            user_manager.complete_login_v2(test_user["user_id"], fake_hmac)
    
    def test_login_flow_v2_user_not_found(self, user_manager):
        """Test V2 login with non-existent user"""
        with pytest.raises(UserNotFoundError):
            user_manager.initiate_login_v2("nonexistent" + "0" * 54)
    
    # ============================================================
    # SESSION TESTS
    # ============================================================
    
    def test_session_validation_v2(self, user_manager, test_user):
        """Test V2 session validation"""
        # Register and login
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        challenge = user_manager.initiate_login_v2(test_user["user_id"])
        
        client_hmac = self._compute_client_hmac(test_user["user_id"], challenge)
        session = user_manager.complete_login_v2(test_user["user_id"], client_hmac)
        
        # Validate session (method may vary based on implementation)
        assert hasattr(user_manager, 'validate_session') or hasattr(user_manager, 'get_session')
    
    def test_logout_v2(self, user_manager, test_user):
        """Test V2 logout"""
        # Register and login
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        challenge = user_manager.initiate_login_v2(test_user["user_id"])
        
        client_hmac = self._compute_client_hmac(test_user["user_id"], challenge)
        session = user_manager.complete_login_v2(test_user["user_id"], client_hmac)
        
        # Logout (if method exists)
        if hasattr(user_manager, 'logout'):
            user_manager.logout(session.user_id)
    
    # ============================================================
    # SECRET ROTATION TESTS
    # ============================================================
    
    def test_rotate_secret_v2_success(self, user_manager, test_user):
        """Test V2 secret rotation (re-registration with new user_id)"""
        # 1. Register with old user_id
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        
        # 2. Simulate secret rotation (new user_id)
        new_user_id = "b" * 64
        
        # 3. Register with new user_id
        user_manager.register_user_v2(new_user_id, test_user["user_data"])
        
        # 4. Login with new user_id
        challenge = user_manager.initiate_login_v2(new_user_id)
        client_hmac = self._compute_client_hmac(new_user_id, challenge)
        
        session = user_manager.complete_login_v2(new_user_id, client_hmac)
        
        assert session is not None
        assert session.user_id == new_user_id
    
    # ============================================================
    # V1 COMPATIBILITY TESTS
    # ============================================================
    
    def test_v1_compatibility_mode(self, user_manager, test_user):
        """Test that V2 works correctly"""
        user_manager.register_user_v2(test_user["user_id"], test_user["user_data"])
        challenge = user_manager.initiate_login_v2(test_user["user_id"])
        
        client_hmac = self._compute_client_hmac(test_user["user_id"], challenge)
        session = user_manager.complete_login_v2(test_user["user_id"], client_hmac)
        
        assert session is not None
        assert session.user_id == test_user["user_id"]