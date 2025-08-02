# Secure Messaging System - Setup Guide

## Quick Start

### 1. Install Dependencies
```bash
pip3 install --break-system-packages -r requirements.txt
```

### 2. Test the System
```bash
python3 test_system.py
```

### 3. Run the Demo
```bash
python3 examples/demo.py
```

### 4. Start the Server
```bash
python3 run_server.py
```

### 5. Run Interactive Client
In another terminal:
```bash
python3 run_client.py
```

## System Overview

This secure messaging system provides:

### 🔐 Multi-Algorithm Encryption
- **AES-256-GCM**: Industry-standard authenticated encryption
- **ChaCha20-Poly1305**: High-performance stream cipher with authentication  
- **AES-256-CBC**: Alternative block cipher with HMAC authentication

### 🔄 Session Management
- Automatic session creation and management
- Configurable session timeouts (default: 24 hours)
- Session-based key derivation
- Real-time session monitoring

### 🔑 Key Management
- Automatic key rotation based on time and usage
- Secure key generation using cryptographically secure random numbers
- PBKDF2-based session key derivation (100,000 iterations)
- Per-message unique IVs (Initialization Vectors)

### 🌐 Real-time Communication
- WebSocket-based client-server architecture
- Asynchronous message handling
- Support for multiple concurrent clients
- Real-time message encryption/decryption

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client A      │    │   Messaging     │    │   Client B      │
│                 │    │     Server      │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Session     │ │    │ │ Session     │ │    │ │ Session     │ │
│ │ Manager     │ │◄──►│ │ Manager     │ │◄──►│ │ Manager     │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Multi-Algo  │ │    │ │ WebSocket   │ │    │ │ Multi-Algo  │ │
│ │ Crypto      │ │    │ │ Handler     │ │    │ │ Crypto      │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Features

### Algorithm Selection
- **AES-256-GCM**: Best for general-purpose encryption, widely supported
- **ChaCha20-Poly1305**: Excellent performance, especially on mobile devices
- **AES-256-CBC**: Alternative to AES-GCM, good for environments requiring algorithm diversity

### Key Management
- Keys are automatically rotated based on time and usage
- Each session uses unique keys
- Keys are never stored in plaintext
- PBKDF2 with 100,000 iterations for key derivation

### Message Security
- All messages use authenticated encryption
- Unique IVs for each message
- Message integrity verification
- Protection against replay attacks

## Usage Examples

### Basic Client Usage
```python
import asyncio
from src.messaging.client import SecureMessagingClient

async def main():
    client = SecureMessagingClient("ws://localhost:8765")
    
    # Register callbacks
    def on_message_decrypted(data):
        print(f"Decrypted: {data.get('message')}")
    
    client.on_message_decrypted(on_message_decrypted)
    
    # Connect and send message
    if await client.connect("user1", "aes_256_gcm"):
        await client.send_message("Hello, secure world!", "user2")
        await asyncio.sleep(5)
        await client.disconnect()

asyncio.run(main())
```

### Direct Crypto Usage
```python
from src.crypto.algorithms import MultiAlgorithmCrypto, AlgorithmType

crypto = MultiAlgorithmCrypto()
key = b"your_32_byte_key_here"[:32]

# Encrypt
encrypted = crypto.encrypt_message(
    b"Secret message", 
    AlgorithmType.AES_256_GCM, 
    key
)

# Decrypt
decrypted = crypto.decrypt_message(encrypted, key)
print(decrypted.decode())
```

### Session Management
```python
from src.session.manager import SessionManager, AlgorithmType

session_manager = SessionManager()

# Create session
session_id = session_manager.create_session(
    "user1", 
    AlgorithmType.AES_256_GCM,
    key_rotation_interval=3600,  # 1 hour
    session_timeout=86400,       # 24 hours
    max_messages_per_key=1000
)

# Get session and encrypt
session = session_manager.get_session(session_id)
encrypted = session.encrypt_message(b"Session message")
decrypted = session.decrypt_message(encrypted)
```

## Testing

### Run All Tests
```bash
python3 tests/test_crypto.py
```

### Run System Test
```bash
python3 test_system.py
```

### Run Demo
```bash
python3 examples/demo.py
```

## Performance

Typical performance metrics (on modern hardware):
- **AES-256-GCM**: ~1000 messages/second
- **ChaCha20-Poly1305**: ~1200 messages/second  
- **AES-256-CBC**: ~800 messages/second

## Configuration

### Server Configuration
```python
server = SecureMessagingServer(
    host="0.0.0.0",  # Listen on all interfaces
    port=8765        # WebSocket port
)
```

### Session Configuration
```python
session_id = session_manager.create_session(
    user_id="user1",
    algorithm_type=AlgorithmType.AES_256_GCM,
    key_rotation_interval=3600,    # Key rotation interval (seconds)
    session_timeout=86400,         # Session timeout (seconds)
    max_messages_per_key=1000      # Max messages per key
)
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure you're running from the project root directory
2. **Key Size Errors**: Ensure keys are exactly 32 bytes for AES-256 and ChaCha20
3. **Connection Issues**: Check that the server is running on the correct port
4. **Algorithm Not Found**: Verify the algorithm name is correct (aes_256_gcm, chacha20_poly1305, aes_256_cbc)

### Debug Mode
Enable debug logging by setting the log level:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Security Considerations

This is a research and educational project. For production use, consider:

- Certificate pinning
- Network-level encryption (TLS)
- Rate limiting
- Input validation
- Secure key storage
- Audit logging
- Regular security audits

## License

This project is licensed under the MIT License.