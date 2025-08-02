"""
Test suite for the encryption module
"""

import pytest
import secrets
from src.encryption import EncryptionEngine, EncryptionAlgorithm, EncryptionResult


class TestEncryptionEngine:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.engine = EncryptionEngine()
        self.test_data = b"This is a test message for encryption!"
    
    def test_symmetric_key_generation(self):
        """Test symmetric key generation"""
        # Test AES key generation
        aes_key = self.engine.generate_symmetric_key(EncryptionAlgorithm.AES_256_GCM)
        assert len(aes_key) == 32  # 256 bits
        
        # Test ChaCha20 key generation
        chacha_key = self.engine.generate_symmetric_key(EncryptionAlgorithm.CHACHA20_POLY1305)
        assert len(chacha_key) == 32  # 256 bits
        
        # Keys should be different
        assert aes_key != chacha_key
    
    def test_aes_gcm_encryption_decryption(self):
        """Test AES-256-GCM encryption and decryption"""
        key = self.engine.generate_symmetric_key(EncryptionAlgorithm.AES_256_GCM)
        
        # Encrypt
        result = self.engine.encrypt_aes_gcm(self.test_data, key)
        assert isinstance(result, EncryptionResult)
        assert result.algorithm == EncryptionAlgorithm.AES_256_GCM
        assert result.nonce is not None
        assert len(result.nonce) == 12  # GCM nonce size
        assert result.ciphertext != self.test_data
        
        # Decrypt
        decrypted = self.engine.decrypt_aes_gcm(result.ciphertext, key, result.nonce)
        assert decrypted == self.test_data
    
    def test_chacha20_poly1305_encryption_decryption(self):
        """Test ChaCha20-Poly1305 encryption and decryption"""
        key = self.engine.generate_symmetric_key(EncryptionAlgorithm.CHACHA20_POLY1305)
        
        # Encrypt
        result = self.engine.encrypt_chacha20_poly1305(self.test_data, key)
        assert isinstance(result, EncryptionResult)
        assert result.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305
        assert result.nonce is not None
        assert len(result.nonce) == 12  # ChaCha20-Poly1305 nonce size
        assert result.ciphertext != self.test_data
        
        # Decrypt
        decrypted = self.engine.decrypt_chacha20_poly1305(result.ciphertext, key, result.nonce)
        assert decrypted == self.test_data
    
    def test_rsa_oaep_encryption_decryption(self):
        """Test RSA-OAEP encryption and decryption"""
        key_id = "test_rsa_key"
        
        # Generate RSA keypair
        public_pem, private_pem = self.engine.generate_rsa_keypair(key_id)
        assert public_pem is not None
        assert private_pem is not None
        
        # Encrypt
        result = self.engine.encrypt_rsa_oaep(self.test_data, public_pem)
        assert isinstance(result, EncryptionResult)
        assert result.algorithm == EncryptionAlgorithm.RSA_OAEP
        assert result.ciphertext != self.test_data
        
        # Decrypt
        decrypted = self.engine.decrypt_rsa_oaep(result.ciphertext, key_id)
        assert decrypted == self.test_data
    
    def test_unified_encryption_interface(self):
        """Test the unified encryption interface"""
        # Test AES-256-GCM
        key = self.engine.generate_symmetric_key(EncryptionAlgorithm.AES_256_GCM)
        result = self.engine.encrypt(self.test_data, key, EncryptionAlgorithm.AES_256_GCM)
        decrypted = self.engine.decrypt(result, key)
        assert decrypted == self.test_data
        
        # Test ChaCha20-Poly1305
        key = self.engine.generate_symmetric_key(EncryptionAlgorithm.CHACHA20_POLY1305)
        result = self.engine.encrypt(self.test_data, key, EncryptionAlgorithm.CHACHA20_POLY1305)
        decrypted = self.engine.decrypt(result, key)
        assert decrypted == self.test_data
    
    def test_encryption_with_associated_data(self):
        """Test encryption with associated data (AEAD)"""
        key = self.engine.generate_symmetric_key(EncryptionAlgorithm.AES_256_GCM)
        associated_data = b"metadata"
        
        # Encrypt with associated data
        result = self.engine.encrypt_aes_gcm(self.test_data, key, associated_data)
        
        # Decrypt with correct associated data
        decrypted = self.engine.decrypt_aes_gcm(
            result.ciphertext, key, result.nonce, associated_data
        )
        assert decrypted == self.test_data
        
        # Decrypt with wrong associated data should fail
        with pytest.raises(Exception):
            self.engine.decrypt_aes_gcm(
                result.ciphertext, key, result.nonce, b"wrong_metadata"
            )
    
    def test_key_cleanup(self):
        """Test key cleanup functionality"""
        key_id = "test_cleanup_key"
        
        # Generate key
        self.engine.generate_rsa_keypair(key_id)
        
        # Verify key exists
        public_key = self.engine.get_public_key(key_id)
        assert public_key is not None
        
        # Clean up specific key
        self.engine.cleanup_keys(key_id)
        
        # Verify key is removed
        with pytest.raises(ValueError):
            self.engine.get_public_key(key_id)
    
    def test_invalid_algorithm(self):
        """Test handling of invalid algorithms"""
        key = secrets.token_bytes(32)
        
        # This should work with proper algorithms
        with pytest.raises(ValueError):
            # Create a mock invalid algorithm
            class InvalidAlgorithm:
                pass
            self.engine.encrypt(self.test_data, key, InvalidAlgorithm())
    
    def test_wrong_key_length(self):
        """Test handling of wrong key lengths"""
        short_key = secrets.token_bytes(16)  # Too short for AES-256
        
        # This should still work as the library handles key sizes
        # But let's test with completely invalid data
        with pytest.raises(Exception):
            self.engine.encrypt_aes_gcm(self.test_data, b"", None)
    
    def test_multiple_encryptions_different_nonces(self):
        """Test that multiple encryptions produce different nonces"""
        key = self.engine.generate_symmetric_key(EncryptionAlgorithm.AES_256_GCM)
        
        result1 = self.engine.encrypt_aes_gcm(self.test_data, key)
        result2 = self.engine.encrypt_aes_gcm(self.test_data, key)
        
        # Same plaintext should produce different ciphertexts due to different nonces
        assert result1.nonce != result2.nonce
        assert result1.ciphertext != result2.ciphertext
        
        # Both should decrypt to the same plaintext
        decrypted1 = self.engine.decrypt_aes_gcm(result1.ciphertext, key, result1.nonce)
        decrypted2 = self.engine.decrypt_aes_gcm(result2.ciphertext, key, result2.nonce)
        
        assert decrypted1 == decrypted2 == self.test_data