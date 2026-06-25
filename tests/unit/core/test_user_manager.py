"""
Tests unitaires pour le UserManager - Version finale avec Data Vault
"""
import pytest
from cryptologin.core.user_manager import UserManager
from cryptologin.core.user_manager_v2 import UserManagerV2
from cryptologin.core.crypto_engine import CryptoEngine
from cryptologin.core.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    InvalidSecretError
)
from cryptologin.storage.memory import MemoryStorage


class TestUserManager:
    """Tests du gestionnaire d'utilisateurs - Version finale"""
    
    @pytest.fixture
    def storage(self):
        return MemoryStorage()
    
    @pytest.fixture
    def crypto_engine(self):
        return CryptoEngine(use_argon2id=False, min_secret_length=8)
    
    @pytest.fixture
    def user_manager(self, storage, crypto_engine):
        return UserManager(
            storage=storage,
            crypto_engine=crypto_engine,
            session_duration_hours=1
        )
    
    @pytest.fixture
    def master_secret(self):
        return "MySuperSecureMasterSecret1234567890!@#$"
    
    @pytest.fixture
    def another_secret(self):
        return "AnotherSecret1234567890!@#$%^&*"
    
    # ============================================================
    # TESTS D'ENREGISTREMENT - AVEC DATA VAULT
    # ============================================================
    
    def test_register_user_success(self, user_manager, master_secret):
        user_id = user_manager.register_user(master_secret)
        assert isinstance(user_id, str)
        assert len(user_id) == 64
        assert user_manager.storage.user_exists(user_id) is True
    
    def test_register_user_with_data(self, user_manager, master_secret):
        """Teste l'enregistrement avec des données - Maintenant via Data Vault"""
        user_data = {'name': 'Alice', 'email': 'alice@example.com'}
        user_id = user_manager.register_user(master_secret, user_data)
        
        # Les données sont stockées dans le Vault, pas en clair
        record = user_manager.storage.get_user(user_id)
        assert record.vault_data is not None  # Les données sont dans le Vault
        
        # Récupérer les données via l'API UserManager
        retrieved_data = user_manager.get_user_data(user_id, master_secret)
        assert retrieved_data == user_data
    
    def test_register_user_already_exists(self, user_manager, master_secret):
        user_manager.register_user(master_secret)
        with pytest.raises(UserAlreadyExistsError):
            user_manager.register_user(master_secret)
    
    def test_register_user_invalid_secret(self, user_manager):
        try:
            user_manager.register_user("short")
            assert False, "Should have raised an exception"
        except InvalidSecretError:
            pass
    
    # ============================================================
    # TESTS D'AUTHENTIFICATION
    # ============================================================
    
    def test_login_flow_success(self, user_manager, master_secret):
        user_id = user_manager.register_user(master_secret)
        challenge = user_manager.initiate_login(master_secret)
        assert isinstance(challenge, str)
        assert len(challenge) == 64
        session = user_manager.complete_login(master_secret, challenge)
        assert session.user_id == user_id
        assert session.is_active is True
    
    def test_login_flow_user_not_found(self, user_manager, master_secret):
        with pytest.raises(UserNotFoundError):
            user_manager.initiate_login(master_secret)
    
    def test_login_flow_wrong_secret(self, user_manager, master_secret, another_secret):
        user_manager.register_user(master_secret)
        with pytest.raises(UserNotFoundError):
            user_manager.initiate_login(another_secret)
    
    def test_login_flow_wrong_response(self, user_manager, master_secret):
        user_manager.register_user(master_secret)
        challenge = user_manager.initiate_login(master_secret)
        with pytest.raises(AuthenticationError):
            user_manager.complete_login(master_secret, "wrongresponse")
    
    # ============================================================
    # TESTS DE SESSIONS
    # ============================================================
    
    def test_session_validation(self, user_manager, master_secret):
        user_id = user_manager.register_user(master_secret)
        challenge = user_manager.initiate_login(master_secret)
        user_manager.complete_login(master_secret, challenge)
        assert user_manager.validate_session(user_id) is True
        assert user_manager.validate_session("nonexistent") is False
    
    def test_session_expiration(self):
        storage = MemoryStorage()
        crypto_engine = CryptoEngine(use_argon2id=False, min_secret_length=8)
        
        manager = UserManager(
            storage=storage,
            crypto_engine=crypto_engine,
            session_duration_hours=-1
        )
        secret = "TestSecret1234567890!@#$%^&*"
        
        user_id = manager.register_user(secret)
        challenge = manager.initiate_login(secret)
        manager.complete_login(secret, challenge)
        
        assert manager.validate_session(user_id) is False
    
    def test_logout(self, user_manager, master_secret):
        user_id = user_manager.register_user(master_secret)
        challenge = user_manager.initiate_login(master_secret)
        user_manager.complete_login(master_secret, challenge)
        assert user_manager.validate_session(user_id) is True
        user_manager.logout(user_id)
        assert user_manager.validate_session(user_id) is False
    
    # ============================================================
    # TESTS DE GESTION DES DONNÉES - AVEC DATA VAULT
    # ============================================================
    
    def test_get_user_data(self, user_manager, master_secret):
        """Teste la récupération des données - Via Data Vault"""
        user_data = {'name': 'Bob', 'preferences': {'theme': 'dark'}}
        user_id = user_manager.register_user(master_secret, user_data)
        
        # Récupérer les données via l'API UserManager
        data = user_manager.get_user_data(user_id, master_secret)
        assert data == user_data
    
    def test_update_user_data(self, user_manager, master_secret):
        """Teste la mise à jour des données - Via Data Vault"""
        user_id = user_manager.register_user(master_secret, {'name': 'Old'})
        new_data = {'name': 'New', 'email': 'new@example.com'}
        
        result = user_manager.update_user_data(user_id, master_secret, new_data)
        assert result is True
        
        # Vérifier que les données ont été mises à jour
        retrieved = user_manager.get_user_data(user_id, master_secret)
        assert retrieved == new_data
    
    def test_update_user_data_wrong_secret(self, user_manager, master_secret, another_secret):
        user_id = user_manager.register_user(master_secret)
        with pytest.raises(AuthenticationError):
            user_manager.update_user_data(user_id, another_secret, {'name': 'Hacker'})
    
    # ============================================================
    # TESTS DE ROTATION DE SECRET - AVEC DATA VAULT
    # ============================================================
    
    def test_rotate_secret_success(self, user_manager, master_secret):
        old_user_id = user_manager.register_user(master_secret, {'name': 'Test User'})
        new_secret = "NewSecret1234567890!@#$%^&*"
        
        result = user_manager.rotate_user_secret(old_user_id, master_secret, new_secret)
        assert result is True
        
        new_user_id = user_manager.crypto_engine.derive_user_id(new_secret)
        
        # Vérifier que le login fonctionne avec le nouveau secret
        challenge = user_manager.initiate_login(new_secret)
        assert isinstance(challenge, str)
        assert len(challenge) == 64
        
        # Vérifier que les données ont été migrées
        data = user_manager.get_user_data(new_user_id, new_secret)
        assert data == {'name': 'Test User'}
        
        # Vérifier que l'ancien ID n'existe plus
        assert user_manager.storage.user_exists(old_user_id) is False
        assert user_manager.storage.user_exists(new_user_id) is True
    
    def test_rotate_secret_wrong_old_secret(self, user_manager, master_secret, another_secret):
        user_id = user_manager.register_user(master_secret)
        with pytest.raises(AuthenticationError):
            user_manager.rotate_user_secret(user_id, another_secret, "NewSecret1234567890!@#$%^&*")
    
    def test_rotate_secret_invalid_new_secret(self, user_manager, master_secret):
        user_id = user_manager.register_user(master_secret)
        try:
            user_manager.rotate_user_secret(user_id, master_secret, "short")
            assert False, "Should have raised an exception"
        except InvalidSecretError:
            pass
    
    def test_rotate_secret_user_not_found(self, user_manager, master_secret):
        with pytest.raises(UserNotFoundError):
            user_manager.rotate_user_secret("nonexistent", master_secret, "NewSecret1234567890!@#$%^&*")
    
    def test_login_after_secret_rotation(self, user_manager, master_secret):
        old_user_id = user_manager.register_user(master_secret, {'name': 'Rotated User'})
        new_secret = "NewSecret1234567890!@#$%^&*"
        
        user_manager.rotate_user_secret(old_user_id, master_secret, new_secret)
        
        new_user_id = user_manager.crypto_engine.derive_user_id(new_secret)
        
        # Login avec le nouveau secret
        challenge = user_manager.initiate_login(new_secret)
        assert isinstance(challenge, str)
        assert len(challenge) == 64
        session = user_manager.complete_login(new_secret, challenge)
        
        assert session.user_id == new_user_id
        assert user_manager.storage.user_exists(old_user_id) is False
        assert user_manager.storage.user_exists(new_user_id) is True
        
        # Vérifier que les données sont toujours accessibles
        data = user_manager.get_user_data(new_user_id, new_secret)
        assert data == {'name': 'Rotated User'}
    
    # ============================================================
    # TESTS DE SUPPRESSION
    # ============================================================
    
    def test_delete_user(self, user_manager, master_secret):
        user_id = user_manager.register_user(master_secret)
        assert user_manager.storage.user_exists(user_id) is True
        result = user_manager.delete_user(user_id)
        assert result is True
        assert user_manager.storage.user_exists(user_id) is False
    
    def test_delete_user_not_found(self, user_manager):
        with pytest.raises(UserNotFoundError):
            user_manager.delete_user("nonexistent")
    
    # ============================================================
    # TESTS UTILITAIRES
    # ============================================================
    
    def test_get_user_count(self, user_manager, master_secret, another_secret):
        assert user_manager.get_user_count() == 0
        user_manager.register_user(master_secret)
        assert user_manager.get_user_count() == 1
        user_manager.register_user(another_secret)
        assert user_manager.get_user_count() == 2
    
    def test_list_users(self, user_manager, master_secret, another_secret):
        user_manager.register_user(master_secret)
        user_manager.register_user(another_secret)
        users = user_manager.list_users()
        assert len(users) == 2
        assert users[0]['user_id'] is not None
        assert users[0]['created_at'] is not None
        assert 'has_vault' in users[0]