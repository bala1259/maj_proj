#!/usr/bin/env python3
"""
Unit tests for the crypto algorithms and session management
"""

import unittest
import sys
import os
import asyncio
import time

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.algorithms import (
    AlgorithmType, MultiAlgorithmCrypto, AES256GCM, 
    ChaCha20Poly1305, AES256CBC
)
from src.session.manager import SessionManager, SessionStatus
from src.messaging.server import SecureMessagingServer
from src.messaging.client import SecureMessagingClient


class TestCryptoAlgorithms(unittest.TestCase):
    """Test crypto algorithms"""
    
    def setUp(self):
        self.crypto = MultiAlgorithmCrypto()
        self.test_message = b"Hello, this is a test message for encryption!"
        self.test_key = b"test_key_32_bytes_long_for_encryption!"[:32]
    
    def test_aes_256_gcm(self):
        """Test AES-256-GCM encryption/decryption"""
        algorithm = self.crypto.get_algorithm(AlgorithmType.AES_256_GCM)
        
        # Test key and IV generation
        key = algorithm.generate_key()
        iv = algorithm.generate_iv()
        
        self.assertEqual(len(key), 32)
        self.assertEqual(len(iv), 12)
        
        # Test encryption/decryption
        ciphertext, tag = algorithm.encrypt(self.test_message, key, iv)
        decrypted = algorithm.decrypt(ciphertext, key, iv, tag)
        
        self.assertEqual(decrypted, self.test_message)
    
    def test_chacha20_poly1305(self):
        """Test ChaCha20-Poly1305 encryption/decryption"""
        algorithm = self.crypto.get_algorithm(AlgorithmType.CHACHA20_POLY1305)
        
        # Test key and IV generation
        key = algorithm.generate_key()
        iv = algorithm.generate_iv()
        
        self.assertEqual(len(key), 32)
        self.assertEqual(len(iv), 12)
        
        # Test encryption/decryption
        ciphertext, tag = algorithm.encrypt(self.test_message, key, iv)
        decrypted = algorithm.decrypt(ciphertext, key, iv, tag)
        
        self.assertEqual(decrypted, self.test_message)
    
    def test_aes_256_cbc(self):
        """Test AES-256-CBC encryption/decryption"""
        algorithm = self.crypto.get_algorithm(AlgorithmType.AES_256_CBC)
        
        # Test key and IV generation
        key = algorithm.generate_key()
        iv = algorithm.generate_iv()
        
        self.assertEqual(len(key), 32)
        self.assertEqual(len(iv), 16)
        
        # Test encryption/decryption
        ciphertext, tag = algorithm.encrypt(self.test_message, key, iv)
        decrypted = algorithm.decrypt(ciphertext, key, iv, tag)
        
        self.assertEqual(decrypted, self.test_message)
    
    def test_multi_algorithm_crypto(self):
        """Test multi-algorithm crypto wrapper"""
        # Test encryption with different algorithms
        algorithms = [
            AlgorithmType.AES_256_GCM,
            AlgorithmType.CHACHA20_POLY1305,
            AlgorithmType.AES_256_CBC
        ]
        
        for algorithm_type in algorithms:
            with self.subTest(algorithm=algorithm_type):
                encrypted_data = self.crypto.encrypt_message(
                    self.test_message, algorithm_type, self.test_key
                )
                
                # Verify encrypted data structure
                self.assertIn("algorithm", encrypted_data)
                self.assertIn("ciphertext", encrypted_data)
                self.assertIn("iv", encrypted_data)
                self.assertIn("tag", encrypted_data)
                self.assertEqual(encrypted_data["algorithm"], algorithm_type.value)
                
                # Test decryption
                decrypted = self.crypto.decrypt_message(encrypted_data, self.test_key)
                self.assertEqual(decrypted, self.test_message)
    
    def test_session_key_generation(self):
        """Test session key generation"""
        password = "test_password"
        key, salt = self.crypto.generate_session_key(password)
        
        self.assertEqual(len(key), 32)
        self.assertEqual(len(salt), 32)
        
        # Test with same password and salt
        key2, _ = self.crypto.generate_session_key(password, salt)
        self.assertEqual(key, key2)
        
        # Test with different salt
        key3, _ = self.crypto.generate_session_key(password)
        self.assertNotEqual(key, key3)


class TestSessionManager(unittest.TestCase):
    """Test session management"""
    
    def setUp(self):
        self.session_manager = SessionManager()
    
    def test_session_creation(self):
        """Test session creation"""
        session_id = self.session_manager.create_session("test_user")
        
        self.assertIsNotNone(session_id)
        self.assertIsInstance(session_id, str)
        
        session = self.session_manager.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session.config.session_id, session_id)
    
    def test_session_encryption_decryption(self):
        """Test session encryption and decryption"""
        session_id = self.session_manager.create_session("test_user")
        session = self.session_manager.get_session(session_id)
        
        test_message = b"Test message for session encryption"
        
        # Encrypt message
        encrypted_message = session.encrypt_message(test_message)
        
        # Verify encrypted message structure
        self.assertIn("session_id", encrypted_message)
        self.assertIn("key_id", encrypted_message)
        self.assertIn("message_id", encrypted_message)
        self.assertIn("encrypted_data", encrypted_message)
        self.assertIn("timestamp", encrypted_message)
        
        # Decrypt message
        decrypted_message = session.decrypt_message(encrypted_message)
        self.assertEqual(decrypted_message, test_message)
    
    def test_algorithm_rotation(self):
        """Test algorithm rotation"""
        session_id = self.session_manager.create_session("test_user")
        session = self.session_manager.get_session(session_id)
        
        # Test rotation to different algorithms
        algorithms = [
            AlgorithmType.CHACHA20_POLY1305,
            AlgorithmType.AES_256_CBC,
            AlgorithmType.AES_256_GCM
        ]
        
        for algorithm in algorithms:
            success = session.rotate_algorithm(algorithm)
            self.assertTrue(success)
            self.assertEqual(session.config.algorithm_type, algorithm)
    
    def test_session_timeout(self):
        """Test session timeout"""
        # Create session with short timeout
        session_id = self.session_manager.create_session(
            "test_user", session_timeout=1
        )
        
        session = self.session_manager.get_session(session_id)
        self.assertIsNotNone(session)
        
        # Wait for timeout
        time.sleep(2)
        
        # Session should be expired
        session = self.session_manager.get_session(session_id)
        self.assertIsNone(session)
    
    def test_session_termination(self):
        """Test session termination"""
        session_id = self.session_manager.create_session("test_user")
        
        # Terminate session
        success = self.session_manager.terminate_session(session_id)
        self.assertTrue(success)
        
        # Session should not be active
        session = self.session_manager.get_session(session_id)
        self.assertIsNone(session)
    
    def test_key_rotation(self):
        """Test automatic key rotation"""
        session_id = self.session_manager.create_session(
            "test_user", max_messages_per_key=2
        )
        session = self.session_manager.get_session(session_id)
        
        test_message = b"Test message"
        
        # Send first message
        encrypted1 = session.encrypt_message(test_message)
        key_id1 = encrypted1["key_id"]
        
        # Send second message (should use same key)
        encrypted2 = session.encrypt_message(test_message)
        key_id2 = encrypted2["key_id"]
        
        self.assertEqual(key_id1, key_id2)
        
        # Send third message (should rotate key)
        encrypted3 = session.encrypt_message(test_message)
        key_id3 = encrypted3["key_id"]
        
        self.assertNotEqual(key_id1, key_id3)


class TestMessagingServer(unittest.TestCase):
    """Test messaging server"""
    
    def setUp(self):
        self.server = SecureMessagingServer()
    
    def test_server_initialization(self):
        """Test server initialization"""
        self.assertEqual(self.server.host, "localhost")
        self.assertEqual(self.server.port, 8765)
        self.assertIsNotNone(self.server.session_manager)
        self.assertEqual(len(self.server.connections), 0)
        self.assertEqual(len(self.server.user_sessions), 0)
    
    def test_server_stats(self):
        """Test server statistics"""
        stats = self.server.get_server_stats()
        
        self.assertIn("active_connections", stats)
        self.assertIn("active_sessions", stats)
        self.assertIn("total_users", stats)
        
        self.assertEqual(stats["active_connections"], 0)
        self.assertEqual(stats["active_sessions"], 0)
        self.assertEqual(stats["total_users"], 0)


class TestMessagingClient(unittest.TestCase):
    """Test messaging client"""
    
    def setUp(self):
        self.client = SecureMessagingClient()
    
    def test_client_initialization(self):
        """Test client initialization"""
        self.assertEqual(self.client.server_url, "ws://localhost:8765")
        self.assertIsNone(self.client.websocket)
        self.assertIsNone(self.client.user_id)
        self.assertIsNone(self.client.session_id)
        self.assertFalse(self.client.connected)
    
    def test_callback_registration(self):
        """Test callback registration"""
        def test_callback(data):
            pass
        
        self.client.on_message_received(test_callback)
        self.client.on_message_sent(test_callback)
        self.client.on_error(test_callback)
        
        # Verify callbacks are registered
        self.assertIn(test_callback, self.client.message_callback.callbacks["message_received"])
        self.assertIn(test_callback, self.client.message_callback.callbacks["message_sent"])
        self.assertIn(test_callback, self.client.message_callback.callbacks["error"])


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    async def test_end_to_end_encryption(self):
        """Test end-to-end encryption"""
        # This would require a running server
        # For now, just test the crypto components work together
        crypto = MultiAlgorithmCrypto()
        session_manager = SessionManager()
        
        # Create session
        session_id = session_manager.create_session("test_user")
        session = session_manager.get_session(session_id)
        
        # Test message encryption/decryption
        test_message = b"Integration test message"
        encrypted = session.encrypt_message(test_message)
        decrypted = session.decrypt_message(encrypted)
        
        self.assertEqual(decrypted, test_message)


def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestCryptoAlgorithms,
        TestSessionManager,
        TestMessagingServer,
        TestMessagingClient,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)