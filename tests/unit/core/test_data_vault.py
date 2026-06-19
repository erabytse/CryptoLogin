"""
Tests unitaires pour le Data Vault
"""
import pytest
import json
from cryptologin.core.data_vault import DataVault, VaultRecord, DataVaultError
from cryptologin.core.crypto_engine import CryptoEngine
from cryptologin.core.exceptions import InvalidSecretError, DecryptionError


class TestDataVault:
    """Tests du Data Vault"""
    
    @pytest.fixture
    def crypto_engine(self):
        return CryptoEngine(use_argon2id=False, min_secret_length=8)
    
    @pytest.fixture
    def data_vault(self, crypto_engine):
        return DataVault(crypto_engine=crypto_engine)
    
    @pytest.fixture
    def master_secret(self):
        return "MySuperSecureMasterSecret1234567890!@#$"
    
    @pytest.fixture
    def test_data(self):
        return {
            "name": "Alice",
            "email": "alice@example.com",
            "preferences": {
                "theme": "dark",
                "notifications": True
            },
            "metadata": {
                "created_at": "2026-01-01T00:00:00"
            }
        }
    
    # ============================================================
    # TESTS DE CHIFFREMENT / DÉCHIFFREMENT
    # ============================================================
    
    def test_encrypt_decrypt_success(self, data_vault, master_secret, test_data):
        """Teste un cycle complet chiffrement/déchiffrement"""
        # Chiffrement
        record = data_vault.encrypt_data(test_data, master_secret)
        assert isinstance(record, VaultRecord)
        assert record.encrypted_data is not None
        assert len(record.encrypted_data) > 0
        assert record.version == "1.0"
        
        # Déchiffrement
        decrypted = data_vault.decrypt_data(record, master_secret)
        assert decrypted == test_data
    
    def test_encrypt_decrypt_string(self, data_vault, master_secret):
        """Teste le chiffrement d'une chaîne simple"""
        test_string = "Hello, World!"
        record = data_vault.encrypt_data(test_string, master_secret)
        decrypted = data_vault.decrypt_data(record, master_secret)
        assert decrypted["_raw"] == test_string
    
    def test_decrypt_wrong_secret(self, data_vault, master_secret, test_data):
        """Teste le déchiffrement avec un mauvais secret"""
        record = data_vault.encrypt_data(test_data, master_secret)
        wrong_secret = "WrongSecret1234567890!@#$%^&*"
        
        with pytest.raises(DataVaultError):
            data_vault.decrypt_data(record, wrong_secret)
    
    def test_decrypt_invalid_record(self, data_vault, master_secret):
        """Teste le déchiffrement d'un enregistrement invalide"""
        invalid_record = VaultRecord(encrypted_data="invalid_token")
        
        with pytest.raises(DataVaultError):
            data_vault.decrypt_data(invalid_record, master_secret)
    
    def test_encrypt_empty_data(self, data_vault, master_secret):
        """Teste le chiffrement de données vides"""
        record = data_vault.encrypt_data({}, master_secret)
        decrypted = data_vault.decrypt_data(record, master_secret)
        assert decrypted == {}
    
    # ============================================================
    # TESTS DE ROTATION
    # ============================================================
    
    def test_rotate_vault_success(self, data_vault, master_secret, test_data):
        """Teste la rotation du secret sur le Vault"""
        # Chiffrement initial
        record = data_vault.encrypt_data(test_data, master_secret)
        
        # Rotation
        new_secret = "NewSecret1234567890!@#$%^&*"
        new_record = data_vault.rotate_vault_data(record, master_secret, new_secret)
        
        assert isinstance(new_record, VaultRecord)
        assert new_record.encrypted_data != record.encrypted_data
        assert new_record.version == record.version
        assert new_record.created_at == record.created_at
        assert new_record.updated_at != record.updated_at
        
        # Vérification avec le nouveau secret
        decrypted = data_vault.decrypt_data(new_record, new_secret)
        assert decrypted == test_data
        
        # L'ancien secret ne doit plus fonctionner
        with pytest.raises(DataVaultError):
            data_vault.decrypt_data(new_record, master_secret)
    
    def test_rotate_vault_wrong_old_secret(self, data_vault, master_secret, test_data):
        """Teste la rotation avec un ancien secret incorrect"""
        record = data_vault.encrypt_data(test_data, master_secret)
        wrong_secret = "WrongSecret1234567890!@#$%^&*"
        new_secret = "NewSecret1234567890!@#$%^&*"
        
        with pytest.raises(DataVaultError):
            data_vault.rotate_vault_data(record, wrong_secret, new_secret)
    
    # ============================================================
    # TESTS D'INTÉGRITÉ
    # ============================================================
    
    def test_verify_integrity_success(self, data_vault, master_secret, test_data):
        """Teste la vérification d'intégrité réussie"""
        record = data_vault.encrypt_data(test_data, master_secret)
        assert data_vault.verify_vault_integrity(record, master_secret) is True
    
    def test_verify_integrity_failure(self, data_vault, master_secret, test_data):
        """Teste la vérification d'intégrité échouée"""
        record = data_vault.encrypt_data(test_data, master_secret)
        wrong_secret = "WrongSecret1234567890!@#$%^&*"
        assert data_vault.verify_vault_integrity(record, wrong_secret) is False
    
    # ============================================================
    # TESTS DE SÉRIALISATION
    # ============================================================
    
    def test_serialize_deserialize(self, data_vault, master_secret, test_data):
        """Teste la sérialisation/désérialisation des VaultRecord"""
        record = data_vault.encrypt_data(test_data, master_secret)
        
        # Sérialisation
        serialized = data_vault.serialize_record(record)
        assert "encrypted_data" in serialized
        assert "version" in serialized
        assert "created_at" in serialized
        assert "updated_at" in serialized
        
        # Désérialisation
        deserialized = DataVault.deserialize_record(serialized)
        assert deserialized.encrypted_data == record.encrypted_data
        assert deserialized.version == record.version
    
    # ============================================================
    # TESTS DE GESTION DU VAULT VIDE
    # ============================================================
    
    def test_is_vault_empty(self, data_vault):
        """Teste la détection d'un Vault vide"""
        empty_record = VaultRecord(encrypted_data="")
        assert data_vault.is_vault_empty(empty_record) is True
        
        non_empty_record = VaultRecord(encrypted_data="some_data")
        assert data_vault.is_vault_empty(non_empty_record) is False
    
    def test_create_empty_vault(self, data_vault):
        """Teste la création d'un Vault vide"""
        record = data_vault.create_empty_vault()
        assert isinstance(record, VaultRecord)
        assert record.encrypted_data is not None
        assert record.version == "1.0"