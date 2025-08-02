"""
Demo Script for Multi-Algorithm Secure Messaging System
Demonstrates the key features of the secure messaging system
"""

import asyncio
import time
from crypto_engine import CryptoEngine, AlgorithmType
from session_manager import SessionManager
from auth_system import AuthSystem


async def demo_secure_messaging():
    """Demonstrate the secure messaging system"""
    
    print("🔐 Multi-Algorithm Secure Messaging System Demo")
    print("=" * 60)
    
    # Initialize components
    crypto_engine = CryptoEngine()
    session_manager = SessionManager(crypto_engine)
    auth_system = AuthSystem()
    
    print("\n📋 Step 1: User Registration and Authentication")
    print("-" * 40)
    
    # Register users
    alice_id = auth_system.register_user("alice", "alice@example.com", "SecurePass123!")
    bob_id = auth_system.register_user("bob", "bob@example.com", "SecurePass456!")
    charlie_id = auth_system.register_user("charlie", "charlie@example.com", "SecurePass789!")
    
    print(f"✅ Alice registered with ID: {alice_id}")
    print(f"✅ Bob registered with ID: {bob_id}")
    print(f"✅ Charlie registered with ID: {charlie_id}")
    
    # Login users
    alice_login = auth_system.login_user("alice", "SecurePass123!")
    bob_login = auth_system.login_user("bob", "SecurePass456!")
    charlie_login = auth_system.login_user("charlie", "SecurePass789!")
    
    print(f"✅ Alice logged in with token: {alice_login['access_token'][:20]}...")
    print(f"✅ Bob logged in with token: {bob_login['access_token'][:20]}...")
    print(f"✅ Charlie logged in with token: {charlie_login['access_token'][:20]}...")
    
    print("\n📋 Step 2: Session Creation and Key Exchange")
    print("-" * 40)
    
    # Create session with AES-256-GCM
    session_id, dh_params = session_manager.create_session(
        alice_id, "alice", AlgorithmType.AES_256_GCM
    )
    print(f"✅ Alice created session: {session_id}")
    print(f"📋 Algorithm: AES-256-GCM")
    print(f"📋 DH Parameters: {dh_params[:50]}...")
    
    # Join session
    bob_public_key = b"bob_public_key_32_bytes_long"
    charlie_public_key = b"charlie_public_key_32_bytes_long"
    
    session_manager.join_session(session_id, bob_id, "bob", bob_public_key)
    session_manager.join_session(session_id, charlie_id, "charlie", charlie_public_key)
    
    print(f"✅ Bob joined session")
    print(f"✅ Charlie joined session")
    
    # Establish session keys
    dh_params_obj = crypto_engine.generate_dh_parameters()
    alice_private_key, _ = crypto_engine.generate_dh_key_pair(dh_params_obj)
    participant_keys = {
        bob_id: bob_public_key,
        charlie_id: charlie_public_key
    }
    
    success = session_manager.establish_session_keys(
        session_id, alice_private_key, participant_keys
    )
    
    if success:
        print(f"✅ Session keys established successfully")
        print(f"📋 Session state: {session_manager.sessions[session_id].state.value}")
    else:
        print(f"❌ Failed to establish session keys")
        return
    
    print("\n📋 Step 3: Secure Message Exchange")
    print("-" * 40)
    
    # Send messages
    messages = [
        ("alice", "Hello everyone! Welcome to our secure chat."),
        ("bob", "Thanks Alice! This encryption is really cool."),
        ("charlie", "I agree! The multi-algorithm support is impressive."),
        ("alice", "Let's test different algorithms next time."),
        ("bob", "Great idea! ChaCha20-Poly1305 is supposed to be very fast."),
        ("charlie", "And Twofish provides good algorithm diversity.")
    ]
    
    for sender_name, message in messages:
        sender_id = alice_id if sender_name == "alice" else bob_id if sender_name == "bob" else charlie_id
        
        # Send message
        encrypted_message = session_manager.send_message(session_id, sender_id, message)
        
        if encrypted_message:
            print(f"📤 {sender_name.capitalize()}: {message}")
            print(f"   🔐 Encrypted ID: {encrypted_message.message_id}")
            print(f"   🔐 Algorithm: {encrypted_message.algorithm}")
            print(f"   🔐 Timestamp: {encrypted_message.timestamp}")
            
            # Decrypt and verify
            decrypted_message = session_manager.receive_message(session_id, encrypted_message)
            if decrypted_message == message:
                print(f"   ✅ Message integrity verified")
            else:
                print(f"   ❌ Message integrity check failed")
        else:
            print(f"❌ Failed to send message from {sender_name}")
    
    print("\n📋 Step 4: Session Information and Statistics")
    print("-" * 40)
    
    # Get session info
    session_info = session_manager.get_session_info(session_id)
    print(f"📊 Session Information:")
    print(f"   ID: {session_info['session_id']}")
    print(f"   State: {session_info['state']}")
    print(f"   Algorithm: {session_info['algorithm']}")
    print(f"   Participants: {len(session_info['participants'])}")
    print(f"   Messages: {session_info['message_count']}")
    print(f"   Created: {time.ctime(session_info['created_at'])}")
    print(f"   Last Activity: {time.ctime(session_info['last_activity'])}")
    
    # Get statistics
    session_stats = session_manager.get_session_statistics()
    user_stats = auth_system.get_user_statistics()
    
    print(f"\n📊 System Statistics:")
    print(f"   Total Sessions: {session_stats['total_sessions']}")
    print(f"   Active Sessions: {session_stats['active_sessions']}")
    print(f"   Total Users: {user_stats['total_users']}")
    print(f"   Active Users: {user_stats['active_users']}")
    
    print("\n📋 Step 5: Algorithm Comparison")
    print("-" * 40)
    
    # Test different algorithms
    algorithms = [AlgorithmType.AES_256_GCM, AlgorithmType.CHACHA20_POLY1305, AlgorithmType.TWOFISH]
    
    for algorithm in algorithms:
        print(f"\n🔧 Testing {algorithm.value}:")
        
        # Create test session keys
        test_keys = crypto_engine.derive_session_keys(
            b"test_shared_secret_32_bytes_long",
            f"test_session_{algorithm.value}",
            algorithm
        )
        
        # Test message
        test_message = f"Test message for {algorithm.value}"
        test_message_id = f"test_{algorithm.value}"
        
        # Measure encryption time
        start_time = time.time()
        encrypted = crypto_engine.encrypt_message(test_message, test_keys, test_message_id)
        encrypt_time = time.time() - start_time
        
        # Measure decryption time
        start_time = time.time()
        decrypted = crypto_engine.decrypt_message(encrypted, test_keys)
        decrypt_time = time.time() - start_time
        
        # Verify
        success = decrypted == test_message
        
        print(f"   ✅ Encryption: {encrypt_time*1000:.2f}ms")
        print(f"   ✅ Decryption: {decrypt_time*1000:.2f}ms")
        print(f"   ✅ Integrity: {'Pass' if success else 'Fail'}")
        
        # Get algorithm info
        alg_info = crypto_engine.get_algorithm_info(algorithm)
        print(f"   📋 Security Level: {alg_info['security_level']}")
        print(f"   📋 Performance: {alg_info['performance']}")
    
    print("\n📋 Step 6: Security Features Demonstration")
    print("-" * 40)
    
    # Demonstrate key rotation
    print("🔄 Key Rotation:")
    original_keys = session_manager.get_session_keys(session_id)
    if original_keys:
        rotated_keys = crypto_engine.rotate_session_keys(original_keys, session_id)
        print(f"   ✅ Keys rotated successfully")
        print(f"   📋 Original created: {time.ctime(original_keys.created_at)}")
        print(f"   📋 Rotated created: {time.ctime(rotated_keys.created_at)}")
    
    # Demonstrate HMAC verification
    print("\n🔐 HMAC Verification:")
    test_data = b"Important message data"
    hmac_key = b"test_hmac_key_32_bytes_long"
    
    hmac_value = crypto_engine.generate_message_hmac(test_data, hmac_key)
    verification = crypto_engine.verify_message_hmac(test_data, hmac_key, hmac_value)
    
    print(f"   ✅ HMAC generated: {hmac_value.hex()[:20]}...")
    print(f"   ✅ HMAC verified: {verification}")
    
    # Demonstrate nonce generation
    print("\n🎲 Nonce Generation:")
    iv_key = b"test_iv_key_32_bytes_long"
    timestamp = time.time()
    
    nonce1 = crypto_engine.generate_nonce(iv_key, timestamp)
    nonce2 = crypto_engine.generate_nonce(iv_key, timestamp)
    
    print(f"   ✅ Nonce 1: {nonce1.hex()}")
    print(f"   ✅ Nonce 2: {nonce2.hex()}")
    print(f"   ✅ Unique: {nonce1 != nonce2}")
    
    print("\n🎉 Demo completed successfully!")
    print("=" * 60)
    print("🔐 This system provides:")
    print("   • Multi-algorithm encryption (AES-256-GCM, ChaCha20-Poly1305, Twofish)")
    print("   • Perfect forward secrecy with Diffie-Hellman key exchange")
    print("   • Session-based key management")
    print("   • Message integrity with HMAC")
    print("   • Secure user authentication with JWT")
    print("   • Real-time messaging with WebSocket support")
    print("   • Key rotation for enhanced security")
    print("   • Comprehensive session management")


if __name__ == "__main__":
    asyncio.run(demo_secure_messaging())