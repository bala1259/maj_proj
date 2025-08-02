"""
Test Suite for Multi-Algorithm Secure Messaging System
Comprehensive tests for crypto engine, session management, and authentication
"""

import asyncio
import json
import base64
import time
import pytest
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from crypto_engine import CryptoEngine, AlgorithmType, SessionKeys, EncryptedMessage
from session_manager import SessionManager, SessionState
from auth_system import AuthSystem


class TestCryptoEngine:
    """Test the cryptographic engine"""
    
    def setup_method(self):
        self.crypto_engine = CryptoEngine()
    
    def test_algorithm_enum(self):
        """Test algorithm enumeration"""
        algorithms = list(AlgorithmType)
        assert len(algorithms) == 3
        assert AlgorithmType.AES_256_GCM in algorithms
        assert AlgorithmType.CHACHA20_POLY1305 in algorithms
        assert AlgorithmType.TWOFISH in algorithms
    
    def test_dh_parameter_generation(self):
        """Test Diffie-Hellman parameter generation"""
        params = self.crypto_engine.generate_dh_parameters()
        assert params is not None
        assert params.key_size == 2048
    
    def test_dh_key_pair_generation(self):
        """Test Diffie-Hellman key pair generation"""
        params = self.crypto_engine.generate_dh_parameters()
        private_key, public_key = self.crypto_engine.generate_dh_key_pair(params)
        
        assert private_key is not None
        assert public_key is not None
        assert private_key.key_size == 2048
        assert public_key.key_size == 2048
    
    def test_shared_secret_derivation(self):
        """Test shared secret derivation"""
        params = self.crypto_engine.generate_dh_parameters()
        private_key1, public_key1 = self.crypto_engine.generate_dh_key_pair(params)
        private_key2, public_key2 = self.crypto_engine.generate_dh_key_pair(params)
        
        # Derive shared secrets
        secret1 = self.crypto_engine.derive_shared_secret(private_key1, public_key2)
        secret2 = self.crypto_engine.derive_shared_secret(private_key2, public_key1)
        
        # Shared secrets should be equal
        assert secret1 == secret2
        assert len(secret1) > 0
    
    def test_session_key_derivation(self):
        """Test session key derivation"""
        shared_secret = b"test_shared_secret_32_bytes_long"
        session_id = "test_session_123"
        algorithm = AlgorithmType.AES_256_GCM
        
        session_keys = self.crypto_engine.derive_session_keys(
            shared_secret, session_id, algorithm
        )
        
        assert session_keys is not None
        assert len(session_keys.encryption_key) == 32
        assert len(session_keys.hmac_key) == 32
        assert len(session_keys.iv_key) == 32
        assert session_keys.algorithm == algorithm
        assert session_keys.created_at > 0
        assert session_keys.expires_at > session_keys.created_at
    
    def test_nonce_generation(self):
        """Test nonce generation"""
        iv_key = b"test_iv_key_32_bytes_long"
        timestamp = time.time()
        
        nonce = self.crypto_engine.generate_nonce(iv_key, timestamp)
        
        assert len(nonce) == 12
        assert nonce != self.crypto_engine.generate_nonce(iv_key, timestamp)
    
    def test_aes_gcm_encryption_decryption(self):
        """Test AES-256-GCM encryption and decryption"""
        key = b"test_encryption_key_32_bytes"
        nonce = b"test_nonce_12"
        plaintext = b"Hello, secure world!"
        
        # Encrypt
        ciphertext, tag = self.crypto_engine.encrypt_aes_gcm(plaintext, key, nonce)
        
        assert ciphertext != plaintext
        assert len(tag) == 16
        
        # Decrypt
        decrypted = self.crypto_engine.decrypt_aes_gcm(ciphertext, key, nonce, tag)
        assert decrypted == plaintext
    
    def test_chacha20_poly1305_encryption_decryption(self):
        """Test ChaCha20-Poly1305 encryption and decryption"""
        key = b"test_encryption_key_32_bytes"
        nonce = b"test_nonce_12"
        plaintext = b"Hello, secure world!"
        
        # Encrypt
        ciphertext, tag = self.crypto_engine.encrypt_chacha20_poly1305(plaintext, key, nonce)
        
        assert ciphertext != plaintext
        assert len(tag) == 16
        
        # Decrypt
        decrypted = self.crypto_engine.decrypt_chacha20_poly1305(ciphertext, key, nonce, tag)
        assert decrypted == plaintext
    
    def test_message_encryption_decryption(self):
        """Test full message encryption and decryption"""
        session_keys = SessionKeys(
            encryption_key=b"test_encryption_key_32_bytes",
            hmac_key=b"test_hmac_key_32_bytes_long",
            iv_key=b"test_iv_key_32_bytes_long",
            algorithm=AlgorithmType.AES_256_GCM,
            created_at=time.time(),
            expires_at=time.time() + 3600
        )
        
        message = "Hello, secure messaging!"
        message_id = "test_message_123"
        
        # Encrypt
        encrypted_message = self.crypto_engine.encrypt_message(
            message, session_keys, message_id
        )
        
        assert encrypted_message.message_id == message_id
        assert encrypted_message.algorithm == AlgorithmType.AES_256_GCM.value
        assert encrypted_message.timestamp > 0
        
        # Decrypt
        decrypted_message = self.crypto_engine.decrypt_message(
            encrypted_message, session_keys
        )
        
        assert decrypted_message == message
    
    def test_message_serialization(self):
        """Test message serialization and deserialization"""
        encrypted_message = EncryptedMessage(
            ciphertext=b"test_ciphertext",
            nonce=b"test_nonce_12",
            tag=b"test_tag_16_bytes",
            algorithm=AlgorithmType.AES_256_GCM.value,
            timestamp=time.time(),
            message_id="test_123"
        )
        
        # Serialize
        serialized = self.crypto_engine.serialize_encrypted_message(encrypted_message)
        
        # Deserialize
        deserialized = self.crypto_engine.deserialize_encrypted_message(serialized)
        
        assert deserialized.ciphertext == encrypted_message.ciphertext
        assert deserialized.nonce == encrypted_message.nonce
        assert deserialized.tag == encrypted_message.tag
        assert deserialized.algorithm == encrypted_message.algorithm
        assert deserialized.message_id == encrypted_message.message_id
    
    def test_hmac_verification(self):
        """Test HMAC generation and verification"""
        message_data = b"test message data"
        hmac_key = b"test_hmac_key_32_bytes_long"
        
        # Generate HMAC
        hmac_value = self.crypto_engine.generate_message_hmac(message_data, hmac_key)
        
        # Verify HMAC
        assert self.crypto_engine.verify_message_hmac(message_data, hmac_key, hmac_value)
        
        # Test with wrong key
        wrong_key = b"wrong_hmac_key_32_bytes_long"
        assert not self.crypto_engine.verify_message_hmac(message_data, wrong_key, hmac_value)
    
    def test_key_rotation(self):
        """Test session key rotation"""
        original_keys = SessionKeys(
            encryption_key=b"original_encryption_key_32",
            hmac_key=b"original_hmac_key_32_bytes",
            iv_key=b"original_iv_key_32_bytes",
            algorithm=AlgorithmType.AES_256_GCM,
            created_at=time.time(),
            expires_at=time.time() + 3600
        )
        
        session_id = "test_session_123"
        rotated_keys = self.crypto_engine.rotate_session_keys(original_keys, session_id)
        
        assert rotated_keys.encryption_key != original_keys.encryption_key
        assert rotated_keys.hmac_key != original_keys.hmac_key
        assert rotated_keys.iv_key != original_keys.iv_key
        assert rotated_keys.algorithm == original_keys.algorithm
        assert rotated_keys.created_at > original_keys.created_at


class TestSessionManager:
    """Test the session manager"""
    
    def setup_method(self):
        self.crypto_engine = CryptoEngine()
        self.session_manager = SessionManager(self.crypto_engine)
    
    def test_session_creation(self):
        """Test session creation"""
        creator_id = "user123"
        creator_username = "testuser"
        algorithm = AlgorithmType.AES_256_GCM
        
        session_id, dh_params = self.session_manager.create_session(
            creator_id, creator_username, algorithm
        )
        
        assert session_id is not None
        assert len(session_id) > 0
        assert dh_params is not None
        
        # Check session was created
        session = self.session_manager.sessions.get(session_id)
        assert session is not None
        assert session.creator_id == creator_id
        assert session.algorithm == algorithm
        assert session.state == SessionState.INITIALIZING
    
    def test_session_joining(self):
        """Test session joining"""
        # Create session
        creator_id = "user123"
        creator_username = "testuser"
        session_id, _ = self.session_manager.create_session(creator_id, creator_username)
        
        # Join session
        joiner_id = "user456"
        joiner_username = "joiner"
        public_key = b"test_public_key"
        
        success = self.session_manager.join_session(
            session_id, joiner_id, joiner_username, public_key
        )
        
        assert success
        session = self.session_manager.sessions[session_id]
        assert joiner_id in session.participants
        assert session.participants[joiner_id].username == joiner_username
    
    def test_session_key_establishment(self):
        """Test session key establishment"""
        # Create session
        creator_id = "user123"
        creator_username = "testuser"
        session_id, _ = self.session_manager.create_session(creator_id, creator_username)
        
        # Add participants
        joiner_id = "user456"
        joiner_username = "joiner"
        public_key = b"test_public_key"
        self.session_manager.join_session(session_id, joiner_id, joiner_username, public_key)
        
        # Generate creator's key pair
        dh_params = self.crypto_engine.generate_dh_parameters()
        creator_private_key, _ = self.crypto_engine.generate_dh_key_pair(dh_params)
        
        # Establish keys
        participant_keys = {joiner_id: public_key}
        success = self.session_manager.establish_session_keys(
            session_id, creator_private_key, participant_keys
        )
        
        assert success
        session = self.session_manager.sessions[session_id]
        assert session.state == SessionState.ESTABLISHED
        assert session.session_keys is not None
    
    def test_message_sending(self):
        """Test message sending"""
        # Create session with established keys
        creator_id = "user123"
        creator_username = "testuser"
        session_id, _ = self.session_manager.create_session(creator_id, creator_username)
        
        # Add participants and establish keys
        joiner_id = "user456"
        joiner_username = "joiner"
        public_key = b"test_public_key"
        self.session_manager.join_session(session_id, joiner_id, joiner_username, public_key)
        
        dh_params = self.crypto_engine.generate_dh_parameters()
        creator_private_key, _ = self.crypto_engine.generate_dh_key_pair(dh_params)
        participant_keys = {joiner_id: public_key}
        self.session_manager.establish_session_keys(session_id, creator_private_key, participant_keys)
        
        # Send message
        message = "Hello, secure world!"
        encrypted_message = self.session_manager.send_message(session_id, creator_id, message)
        
        assert encrypted_message is not None
        assert encrypted_message.message_id is not None
        assert encrypted_message.algorithm == AlgorithmType.AES_256_GCM.value
    
    def test_message_receiving(self):
        """Test message receiving"""
        # Create session with established keys
        creator_id = "user123"
        creator_username = "testuser"
        session_id, _ = self.session_manager.create_session(creator_id, creator_username)
        
        # Add participants and establish keys
        joiner_id = "user456"
        joiner_username = "joiner"
        public_key = b"test_public_key"
        self.session_manager.join_session(session_id, joiner_id, joiner_username, public_key)
        
        dh_params = self.crypto_engine.generate_dh_parameters()
        creator_private_key, _ = self.crypto_engine.generate_dh_key_pair(dh_params)
        participant_keys = {joiner_id: public_key}
        self.session_manager.establish_session_keys(session_id, creator_private_key, participant_keys)
        
        # Send and receive message
        original_message = "Hello, secure world!"
        encrypted_message = self.session_manager.send_message(session_id, creator_id, original_message)
        
        decrypted_message = self.session_manager.receive_message(session_id, encrypted_message)
        
        assert decrypted_message == original_message
    
    def test_session_cleanup(self):
        """Test session cleanup"""
        # Create session
        creator_id = "user123"
        creator_username = "testuser"
        session_id, _ = self.session_manager.create_session(creator_id, creator_username)
        
        # Manually expire the session
        session = self.session_manager.sessions[session_id]
        session.expires_at = time.time() - 1  # Expired
        
        # Check that session is marked as expired
        session_keys = self.session_manager.get_session_keys(session_id)
        assert session_keys is None
        assert session.state == SessionState.EXPIRED
    
    def test_session_statistics(self):
        """Test session statistics"""
        # Create multiple sessions
        for i in range(3):
            creator_id = f"user{i}"
            creator_username = f"user{i}"
            self.session_manager.create_session(creator_id, creator_username)
        
        stats = self.session_manager.get_session_statistics()
        
        assert stats["total_sessions"] == 3
        assert stats["active_sessions"] == 0  # No established sessions
        assert "algorithm_usage" in stats


class TestAuthSystem:
    """Test the authentication system"""
    
    def setup_method(self):
        self.auth_system = AuthSystem()
    
    def test_user_registration(self):
        """Test user registration"""
        username = "testuser"
        email = "test@example.com"
        password = "securepassword123"
        
        user_id = self.auth_system.register_user(username, email, password)
        
        assert user_id is not None
        assert user_id in self.auth_system.users
        assert self.auth_system.users[user_id].username == username
        assert self.auth_system.users[user_id].email == email
    
    def test_user_authentication(self):
        """Test user authentication"""
        # Register user
        username = "testuser"
        email = "test@example.com"
        password = "securepassword123"
        user_id = self.auth_system.register_user(username, email, password)
        
        # Authenticate with username
        user = self.auth_system.authenticate_user(username, password)
        assert user is not None
        assert user.user_id == user_id
        
        # Authenticate with email
        user = self.auth_system.authenticate_user(email, password)
        assert user is not None
        assert user.user_id == user_id
        
        # Test wrong password
        user = self.auth_system.authenticate_user(username, "wrongpassword")
        assert user is None
    
    def test_login_logout(self):
        """Test login and logout"""
        # Register user
        username = "testuser"
        email = "test@example.com"
        password = "securepassword123"
        self.auth_system.register_user(username, email, password)
        
        # Login
        result = self.auth_system.login_user(username, password)
        assert result is not None
        assert "access_token" in result
        assert "refresh_token" in result
        assert "user_id" in result
        
        access_token = result["access_token"]
        refresh_token = result["refresh_token"]
        
        # Verify token
        payload = self.auth_system.verify_token(access_token)
        assert payload is not None
        assert payload["sub"] == result["user_id"]
        
        # Logout
        self.auth_system.logout_user(access_token, refresh_token)
        
        # Verify token is blacklisted
        payload = self.auth_system.verify_token(access_token)
        assert payload is None
    
    def test_token_refresh(self):
        """Test token refresh"""
        # Register and login user
        username = "testuser"
        email = "test@example.com"
        password = "securepassword123"
        self.auth_system.register_user(username, email, password)
        
        result = self.auth_system.login_user(username, password)
        refresh_token = result["refresh_token"]
        
        # Refresh token
        new_access_token = self.auth_system.refresh_access_token(refresh_token)
        assert new_access_token is not None
        
        # Verify new token
        payload = self.auth_system.verify_token(new_access_token)
        assert payload is not None
        assert payload["sub"] == result["user_id"]
    
    def test_password_validation(self):
        """Test password strength validation"""
        # Test weak password
        weak_password = "123"
        validation = self.auth_system.validate_password_strength(weak_password)
        assert not validation["is_valid"]
        assert len(validation["errors"]) > 0
        
        # Test strong password
        strong_password = "SecurePass123!"
        validation = self.auth_system.validate_password_strength(strong_password)
        assert validation["is_valid"]
        assert len(validation["errors"]) == 0
        assert validation["strength_score"] > 0
    
    def test_password_change(self):
        """Test password change"""
        # Register user
        username = "testuser"
        email = "test@example.com"
        password = "securepassword123"
        user_id = self.auth_system.register_user(username, email, password)
        
        # Change password
        new_password = "newsecurepass456!"
        success = self.auth_system.change_password(user_id, password, new_password)
        assert success
        
        # Verify new password works
        user = self.auth_system.authenticate_user(username, new_password)
        assert user is not None
        
        # Verify old password doesn't work
        user = self.auth_system.authenticate_user(username, password)
        assert user is None
    
    def test_user_statistics(self):
        """Test user statistics"""
        # Register multiple users
        for i in range(5):
            username = f"user{i}"
            email = f"user{i}@example.com"
            password = "securepassword123"
            self.auth_system.register_user(username, email, password)
        
        stats = self.auth_system.get_user_statistics()
        
        assert stats["total_users"] == 5
        assert stats["active_users"] == 5
        assert stats["inactive_users"] == 0


class TestIntegration:
    """Integration tests"""
    
    def setup_method(self):
        self.crypto_engine = CryptoEngine()
        self.session_manager = SessionManager(self.crypto_engine)
        self.auth_system = AuthSystem()
    
    def test_full_secure_messaging_flow(self):
        """Test complete secure messaging flow"""
        # 1. Register users
        alice_id = self.auth_system.register_user("alice", "alice@example.com", "password123")
        bob_id = self.auth_system.register_user("bob", "bob@example.com", "password456")
        
        # 2. Login users
        alice_login = self.auth_system.login_user("alice", "password123")
        bob_login = self.auth_system.login_user("bob", "password456")
        
        # 3. Create session
        session_id, dh_params = self.session_manager.create_session(
            alice_id, "alice", AlgorithmType.AES_256_GCM
        )
        
        # 4. Join session
        bob_public_key = b"bob_public_key_32_bytes_long"
        self.session_manager.join_session(session_id, bob_id, "bob", bob_public_key)
        
        # 5. Establish session keys
        dh_params_obj = self.crypto_engine.generate_dh_parameters()
        alice_private_key, _ = self.crypto_engine.generate_dh_key_pair(dh_params_obj)
        participant_keys = {bob_id: bob_public_key}
        
        success = self.session_manager.establish_session_keys(
            session_id, alice_private_key, participant_keys
        )
        assert success
        
        # 6. Send and receive messages
        message1 = "Hello Bob, this is Alice!"
        message2 = "Hello Alice, this is Bob!"
        
        encrypted1 = self.session_manager.send_message(session_id, alice_id, message1)
        encrypted2 = self.session_manager.send_message(session_id, bob_id, message2)
        
        decrypted1 = self.session_manager.receive_message(session_id, encrypted1)
        decrypted2 = self.session_manager.receive_message(session_id, encrypted2)
        
        assert decrypted1 == message1
        assert decrypted2 == message2
        
        # 7. Verify session info
        session_info = self.session_manager.get_session_info(session_id)
        assert session_info["state"] == "established"
        assert session_info["message_count"] == 2
        assert len(session_info["participants"]) == 2


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])