"""
Tests unitaires pour CryptoClient
"""
import pytest
from cryptologin.client.crypto_client import CryptoClient


class TestCryptoClient:
    """Tests du CryptoClient"""
    
    @pytest.fixture
    def master_secret(self):
        return "MySuperSecureMasterSecret1234567890!@#$"
    
    @pytest.fixture
    def challenge(self):
        return "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    
    # ============================================================
    # TESTS DE DÉRIVATION
    # ============================================================
    
    def test_derive_user_id(self, master_secret):
        """Teste la dérivation d'un ID utilisateur"""
        user_id = CryptoClient.derive_user_id(master_secret)
        assert isinstance(user_id, str)
        assert len(user_id) == 64
        assert all(c in '0123456789abcdef' for c in user_id)
    
    def test_derive_user_id_deterministic(self, master_secret):
        """Teste que la dérivation est déterministe"""
        user_id1 = CryptoClient.derive_user_id(master_secret)
        user_id2 = CryptoClient.derive_user_id(master_secret)
        assert user_id1 == user_id2
    
    def test_derive_user_id_different_secrets(self, master_secret):
        """Teste que deux secrets différents donnent des IDs différents"""
        secret2 = "AnotherSecret1234567890!@#$%^&*."
        user_id1 = CryptoClient.derive_user_id(master_secret)
        user_id2 = CryptoClient.derive_user_id(secret2)
        assert user_id1 != user_id2
    
    def test_derive_user_id_short_secret(self):
        """Teste la validation des secrets trop courts"""
        with pytest.raises(ValueError):
            CryptoClient.derive_user_id("short")
    
    # ============================================================
    # TESTS DE HMAC
    # ============================================================
    
    def test_compute_hmac(self, master_secret, challenge):
        """Teste le calcul du HMAC"""
        signature = CryptoClient.compute_hmac(master_secret, challenge)
        assert isinstance(signature, str)
        assert len(signature) == 64
        assert all(c in '0123456789abcdef' for c in signature)
    
    def test_compute_hmac_deterministic(self, master_secret, challenge):
        """Teste que le HMAC est déterministe"""
        sig1 = CryptoClient.compute_hmac(master_secret, challenge)
        sig2 = CryptoClient.compute_hmac(master_secret, challenge)
        assert sig1 == sig2
    
    def test_compute_hmac_different_challenge(self, master_secret):
        """Teste que des challenges différents donnent des signatures différentes"""
        challenge1 = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        challenge2 = "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4"
        sig1 = CryptoClient.compute_hmac(master_secret, challenge1)
        sig2 = CryptoClient.compute_hmac(master_secret, challenge2)
        assert sig1 != sig2
    
    def test_verify_hmac_success(self, master_secret, challenge):
        """Teste la vérification HMAC réussie"""
        signature = CryptoClient.compute_hmac(master_secret, challenge)
        assert CryptoClient.verify_hmac(master_secret, challenge, signature) is True
    
    def test_verify_hmac_failure(self, master_secret, challenge):
        """Teste la vérification HMAC échouée"""
        wrong_signature = "9" * 64
        assert CryptoClient.verify_hmac(master_secret, challenge, wrong_signature) is False
    
    # ============================================================
    # TESTS DE DÉRIVATION DE CLÉ VAULT
    # ============================================================
    
    def test_derive_vault_key(self, master_secret):
        """Teste la dérivation de clé pour le Vault"""
        key = CryptoClient.derive_vault_key(master_secret)
        assert isinstance(key, str)
        assert len(key) == 64
    
    def test_derive_vault_key_deterministic(self, master_secret):
        """Teste que la dérivation de clé est déterministe"""
        key1 = CryptoClient.derive_vault_key(master_secret)
        key2 = CryptoClient.derive_vault_key(master_secret)
        assert key1 == key2
    
    def test_derive_vault_key_with_salt(self, master_secret):
        """Teste la dérivation de clé avec sel personnalisé"""
        salt = "custom_salt_1234567890"
        key = CryptoClient.derive_vault_key(master_secret, salt)
        assert isinstance(key, str)
        assert len(key) == 64
    
    # ============================================================
    # TESTS DE GÉNÉRATION DE CHALLENGE
    # ============================================================
    
    def test_generate_challenge(self):
        """Teste la génération de challenge"""
        challenge = CryptoClient.generate_challenge()
        assert isinstance(challenge, str)
        assert len(challenge) == 64  # 32 bytes * 2
    
    def test_generate_challenge_different(self):
        """Teste que deux challenges sont différents"""
        challenge1 = CryptoClient.generate_challenge()
        challenge2 = CryptoClient.generate_challenge()
        assert challenge1 != challenge2
    
    def test_generate_challenge_custom_length(self):
        """Teste la génération de challenge avec longueur personnalisée"""
        challenge = CryptoClient.generate_challenge(16)
        assert len(challenge) == 32  # 16 bytes * 2