#!/usr/bin/env python3
"""
Simple test script to verify the encryption system works
"""

import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from crypto.algorithms import MultiAlgorithmCrypto, AlgorithmType
from session.manager import SessionManager


def test_basic_encryption():
    """Test basic encryption functionality"""
    print("Testing basic encryption...")
    
    crypto = MultiAlgorithmCrypto()
    test_message = b"Hello, this is a test message!"
    test_key = b"test_key_32_bytes_long_for_encryption!"[:32]
    
    # Test each algorithm
    algorithms = [
        AlgorithmType.AES_256_GCM,
        AlgorithmType.CHACHA20_POLY1305,
        AlgorithmType.AES_256_CBC
    ]
    
    for algorithm in algorithms:
        print(f"  Testing {algorithm.value}...")
        
        # Encrypt
        encrypted_data = crypto.encrypt_message(test_message, algorithm, test_key)
        
        # Verify structure
        assert "algorithm" in encrypted_data
        assert "ciphertext" in encrypted_data
        assert "iv" in encrypted_data
        assert "tag" in encrypted_data
        assert encrypted_data["algorithm"] == algorithm.value
        
        # Decrypt
        decrypted = crypto.decrypt_message(encrypted_data, test_key)
        
        # Verify
        assert decrypted == test_message
        print(f"    ✓ {algorithm.value} works correctly")
    
    print("  ✓ All algorithms work correctly")


def test_session_management():
    """Test session management"""
    print("Testing session management...")
    
    session_manager = SessionManager()
    
    # Create session
    session_id = session_manager.create_session("test_user")
    print(f"  Created session: {session_id}")
    
    # Get session
    session = session_manager.get_session(session_id)
    assert session is not None
    print("  ✓ Session retrieved successfully")
    
    # Test encryption/decryption
    test_message = b"Session test message"
    encrypted = session.encrypt_message(test_message)
    
    # Verify structure
    assert "session_id" in encrypted
    assert "key_id" in encrypted
    assert "message_id" in encrypted
    assert "encrypted_data" in encrypted
    assert "timestamp" in encrypted
    
    # Decrypt
    decrypted = session.decrypt_message(encrypted)
    assert decrypted == test_message
    print("  ✓ Session encryption/decryption works")
    
    # Test algorithm rotation
    success = session.rotate_algorithm(AlgorithmType.CHACHA20_POLY1305)
    assert success
    print("  ✓ Algorithm rotation works")
    
    print("  ✓ Session management works correctly")


def test_key_rotation():
    """Test key rotation"""
    print("Testing key rotation...")
    
    session_manager = SessionManager()
    
    # Create session with low message limit
    session_id = session_manager.create_session(
        "test_user", max_messages_per_key=2
    )
    session = session_manager.get_session(session_id)
    
    test_message = b"Key rotation test"
    
    # Send first message
    encrypted1 = session.encrypt_message(test_message)
    key_id1 = encrypted1["key_id"]
    
    # Send second message (same key)
    encrypted2 = session.encrypt_message(test_message)
    key_id2 = encrypted2["key_id"]
    
    assert key_id1 == key_id2
    print("  ✓ First two messages use same key")
    
    # Send third message (should rotate key)
    encrypted3 = session.encrypt_message(test_message)
    key_id3 = encrypted3["key_id"]
    
    assert key_id1 != key_id3
    print("  ✓ Third message uses new key (rotation works)")
    
    print("  ✓ Key rotation works correctly")


def main():
    """Run all tests"""
    print("Secure Messaging System - System Test")
    print("=" * 50)
    
    try:
        test_basic_encryption()
        print()
        
        test_session_management()
        print()
        
        test_key_rotation()
        print()
        
        print("=" * 50)
        print("✓ All tests passed! The system is working correctly.")
        print()
        print("You can now:")
        print("  1. Run the server: python run_server.py")
        print("  2. Run the demo: python examples/demo.py")
        print("  3. Run the interactive client: python run_client.py")
        print("  4. Run full tests: python tests/test_crypto.py")
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)