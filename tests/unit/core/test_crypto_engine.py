"""
Tests unitaires pour le CryptoEngine
"""
import pytest
import secrets
from cryptologin.core.crypto_engine import CryptoEngine, CryptoError, InvalidSecretError, DecryptionError, IntegrityError


class TestCryptoEngine:
    """Tests du moteur cryptographique"""
    
    @pytest.fixture
    def engine(self):
        """Fixture fournissant une instance de CryptoEngine"""
        return CryptoEngine(use_argon2id=False, min_secret_length=8)  # Longueur réduite pour les tests
    
    @pytest.fixture
    def master_secret(self):
        """Fixture fournissant un secret valide"""
        return "MySuperSecureMasterSecret1234567890!@#$"
    
    @pytest.fixture
    def short_secret(self):
        """Fixture fournissant un secret trop court"""
        return "short"
    
    @pytest.fixture
    def plaintext(self):
        """Fixture fournissant un texte à chiffrer"""
        return "Hello World! This is a sensitive message."
    
    # ============================================================
    # TESTS DE DÉRIVATION D'IDENTIFIANT
    # ============================================================
    
    def test_derive_user_id_success(self, engine, master_secret):
        """Teste la dérivation d'un ID utilisateur avec succès"""
        user_id = engine.derive_user_id(master_secret)
        
        assert isinstance(user_id, str)
        assert len(user_id) == 64  # 32 octets en hexadécimal = 64 caractères
        assert all(c in '0123456789abcdef' for c in user_id)
    
    def test_derive_user_id_deterministic(self, engine, master_secret):
        """Vérifie que la dérivation est déterministe"""
        user_id1 = engine.derive_user_id(master_secret)
        user_id2 = engine.derive_user_id(master_secret)
        
        assert user_id1 == user_id2
    
    def test_derive_user_id_different_secrets(self, engine):
        """Vérifie que deux secrets différents donnent des IDs différents"""
        secret1 = "SecretOne1234567890!@#$%^&*"
        secret2 = "SecretTwo1234567890!@#$%^&*"
        user_id1 = engine.derive_user_id(secret1)
        user_id2 = engine.derive_user_id(secret2)
        
        assert user_id1 != user_id2
    
    def test_derive_user_id_short_secret(self, engine, short_secret):
        """Teste la validation des secrets trop courts"""
        with pytest.raises(InvalidSecretError) as exc_info:
            engine.derive_user_id(short_secret)
        assert "Secret must be at least 8 characters" in str(exc_info.value)
    
    # ============================================================
    # TESTS DE CHIFFREMENT / DÉCHIFFREMENT
    # ============================================================
    
    def test_encrypt_decrypt_roundtrip(self, engine, master_secret, plaintext):
        """Teste un cycle complet chiffrement/déchiffrement"""
        token = engine.encrypt_data(plaintext, master_secret)
        assert isinstance(token, str)
        assert len(token) > 0
        
        decrypted = engine.decrypt_data(token, master_secret)
        assert decrypted == plaintext
    
    def test_encrypt_polymorphic(self, engine, master_secret, plaintext):
        """Vérifie que deux chiffrements du même texte produisent des tokens différents"""
        token1 = engine.encrypt_data(plaintext, master_secret)
        token2 = engine.encrypt_data(plaintext, master_secret)
        
        assert token1 != token2
        # Les deux tokens doivent se déchiffrer correctement
        assert engine.decrypt_data(token1, master_secret) == plaintext
        assert engine.decrypt_data(token2, master_secret) == plaintext
    
    def test_decryption_wrong_secret(self, engine, master_secret, plaintext):
        """Teste le déchiffrement avec un mauvais secret"""
        token = engine.encrypt_data(plaintext, master_secret)
        
        wrong_secret = "WrongSecret1234567890!@#$%^&*"
        with pytest.raises(DecryptionError):
            engine.decrypt_data(token, wrong_secret)
    
    def test_decryption_empty_token(self, engine, master_secret):
        """Teste le déchiffrement avec un token vide"""
        with pytest.raises(ValueError) as exc_info:
            engine.decrypt_data("", master_secret)
        assert "Token cannot be empty" in str(exc_info.value)
    
    def test_encrypt_empty_plaintext(self, engine, master_secret):
        """Teste le chiffrement d'un texte vide"""
        with pytest.raises(ValueError) as exc_info:
            engine.encrypt_data("", master_secret)
        assert "Plaintext cannot be empty" in str(exc_info.value)
    
    # ============================================================
    # TESTS DE GESTION DES CHALLENGES
    # ============================================================
    
    def test_generate_challenge(self, engine, master_secret):
        """Teste la génération d'un challenge"""
        challenge_token, plaintext_challenge = engine.generate_challenge(master_secret)
        
        assert isinstance(challenge_token, str)
        assert isinstance(plaintext_challenge, str)
        assert len(plaintext_challenge) == 64  # 32 octets en hex
        
        # Vérification que le token peut être déchiffré
        decrypted = engine.decrypt_data(challenge_token, master_secret)
        assert decrypted == plaintext_challenge
    
    def test_verify_challenge_success(self, engine, master_secret):
        """Teste la vérification réussie d'un challenge"""
        challenge_token, plaintext_challenge = engine.generate_challenge(master_secret)
        
        is_valid = engine.verify_challenge(
            challenge_token,
            plaintext_challenge,
            master_secret
        )
        
        assert is_valid is True
    
    def test_verify_challenge_failure_wrong_response(self, engine, master_secret):
        """Teste la vérification avec une mauvaise réponse"""
        challenge_token, _ = engine.generate_challenge(master_secret)
        
        is_valid = engine.verify_challenge(
            challenge_token,
            "wrongresponse1234567890abcdef",
            master_secret
        )
        
        assert is_valid is False
    
    def test_verify_challenge_failure_wrong_secret(self, engine, master_secret):
        """Teste la vérification avec un mauvais secret"""
        challenge_token, plaintext_challenge = engine.generate_challenge(master_secret)
        
        wrong_secret = "WrongSecret1234567890!@#$%^&*"
        is_valid = engine.verify_challenge(
            challenge_token,
            plaintext_challenge,
            wrong_secret
        )
        
        assert is_valid is False
    
    def test_verify_challenge_failure_corrupted_token(self, engine, master_secret):
        """Teste la vérification avec un token corrompu"""
        challenge_token, plaintext_challenge = engine.generate_challenge(master_secret)
        
        # Corrompre le token (trop court pour être valide)
        corrupted_token = "corrupted"
        is_valid = engine.verify_challenge(
            corrupted_token,
            plaintext_challenge,
            master_secret
        )
        
        assert is_valid is False
    
    # ============================================================
    # TESTS DE ROTATION DE SECRET
    # ============================================================
    
    def test_rotate_secret(self, engine, master_secret, plaintext):
        """Teste la rotation du secret"""
        token = engine.encrypt_data(plaintext, master_secret)
        
        new_secret = "NewSuperSecureSecret1234567890!@#$%^&*"
        rotated_token = engine.rotate_secret(token, master_secret, new_secret)
        
        assert isinstance(rotated_token, str)
        assert rotated_token != token
        
        # Vérification avec le nouveau secret
        decrypted = engine.decrypt_data(rotated_token, new_secret)
        assert decrypted == plaintext
        
        # L'ancien secret ne doit plus fonctionner
        with pytest.raises(DecryptionError):
            engine.decrypt_data(rotated_token, master_secret)
    
    # ============================================================
    # TESTS DE VÉRIFICATION D'INTÉGRITÉ
    # ============================================================
    
    def test_verify_token_integrity(self, engine, master_secret, plaintext):
        """Teste la vérification d'intégrité d'un token"""
        token = engine.encrypt_data(plaintext, master_secret)
        
        # Token intègre
        assert engine.verify_token_integrity(token, master_secret) is True
        
        # Mauvais secret
        wrong_secret = "WrongSecret1234567890!@#$%^&*"
        assert engine.verify_token_integrity(token, wrong_secret) is False
    
    def test_verify_token_integrity_corrupted(self, engine, master_secret, plaintext):
        """Teste la vérification d'intégrité d'un token corrompu"""
        token = engine.encrypt_data(plaintext, master_secret)
        
        # Corrompre le token
        corrupted_token = token[:-5] + "XXXXX"
        assert engine.verify_token_integrity(corrupted_token, master_secret) is False
    
    # ============================================================
    # TESTS DE VALIDATION DE SECRET
    # ============================================================
    
    def test_validate_secret_empty(self, engine):
        """Teste la validation d'un secret vide"""
        with pytest.raises(InvalidSecretError) as exc_info:
            engine.encrypt_data("data", "")
        assert "Secret cannot be empty" in str(exc_info.value)
    
    def test_validate_secret_too_short(self, engine, short_secret):
        """Teste la validation d'un secret trop court"""
        with pytest.raises(InvalidSecretError) as exc_info:
            engine.encrypt_data("data", short_secret)
        assert "Secret must be at least 8 characters" in str(exc_info.value)
    
    def test_encrypt_decrypt_with_argon2id(self, plaintext):
        """Teste le cycle avec Argon2id (mode production)"""
        engine = CryptoEngine(use_argon2id=True, min_secret_length=8)
        secret = "TestSecret123!@#"
        
        token = engine.encrypt_data(plaintext, secret)
        decrypted = engine.decrypt_data(token, secret)
        assert decrypted == plaintext