# Secure Messaging System - Multi-Algorithm Encryption

A comprehensive session-based multi-algorithm encryption system for secure messaging with support for AES-256-GCM, ChaCha20-Poly1305, and Twofish-CBC encryption algorithms.

## Features

### 🔐 Multi-Algorithm Encryption
- **AES-256-GCM**: Industry-standard authenticated encryption
- **ChaCha20-Poly1305**: High-performance stream cipher with authentication
- **Twofish-CBC**: Alternative block cipher with HMAC authentication

### 🔄 Session Management
- Automatic session creation and management
- Configurable session timeouts
- Session-based key derivation
- Real-time session monitoring

### 🔑 Key Management
- Automatic key rotation based on time and usage
- Secure key generation using cryptographically secure random numbers
- PBKDF2-based session key derivation
- Per-message unique IVs (Initialization Vectors)

### 🌐 Real-time Communication
- WebSocket-based client-server architecture
- Asynchronous message handling
- Support for multiple concurrent clients
- Real-time message encryption/decryption

### 🛡️ Security Features
- Authenticated encryption for all algorithms
- Message integrity verification
- Protection against replay attacks
- Secure random number generation
- No plaintext key storage

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

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure-messaging-system
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Server

```python
import asyncio
from src.messaging.server import SecureMessagingServer

async def main():
    server = SecureMessagingServer(host="localhost", port=8765)
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())
```

### Using the Client

```python
import asyncio
from src.messaging.client import SecureMessagingClient

async def main():
    # Create client
    client = SecureMessagingClient("ws://localhost:8765")
    
    # Register callbacks
    def on_message_received(data):
        print(f"Received message from {data.get('sender_id')}")
        # Automatically decrypt received messages
        asyncio.create_task(client.receive_message(data.get('encrypted_message')))
    
    def on_message_decrypted(data):
        print(f"Decrypted message: {data.get('message')}")
    
    client.on_message_received(on_message_received)
    client.on_message_decrypted(on_message_decrypted)
    
    # Connect to server
    if await client.connect("user1", "aes_256_gcm"):
        # Send encrypted message
        await client.send_message("Hello, secure world!", "user2")
        
        # Rotate to different algorithm
        await client.rotate_algorithm("chacha20_poly1305")
        
        # Send another message
        await client.send_message("Now using ChaCha20!", "user2")
        
        # Wait for responses
        await asyncio.sleep(5)
        
        # Disconnect
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Running the Demo

```bash
python examples/demo.py
```

This will run a comprehensive demo showing:
1. Basic encryption functionality
2. Algorithm rotation
3. Multi-client scenarios
4. Performance testing

## API Reference

### MultiAlgorithmCrypto

Main encryption class that supports multiple algorithms.

```python
from src.crypto.algorithms import MultiAlgorithmCrypto, AlgorithmType

crypto = MultiAlgorithmCrypto()

# Encrypt message
encrypted_data = crypto.encrypt_message(
    message=b"Hello world",
    algorithm_type=AlgorithmType.AES_256_GCM,
    key=b"your_32_byte_key_here"
)

# Decrypt message
decrypted = crypto.decrypt_message(encrypted_data, key)
```

### SessionManager

Manages secure messaging sessions with automatic key rotation.

```python
from src.session.manager import SessionManager, AlgorithmType

session_manager = SessionManager()

# Create session
session_id = session_manager.create_session(
    user_id="user1",
    algorithm_type=AlgorithmType.AES_256_GCM,
    key_rotation_interval=3600,  # 1 hour
    session_timeout=86400,       # 24 hours
    max_messages_per_key=1000
)

# Get session
session = session_manager.get_session(session_id)

# Encrypt message
encrypted = session.encrypt_message(b"Secret message")

# Decrypt message
decrypted = session.decrypt_message(encrypted)
```

### SecureMessagingServer

WebSocket server for handling secure messaging.

```python
from src.messaging.server import SecureMessagingServer

server = SecureMessagingServer(host="0.0.0.0", port=8765)
await server.start()
```

### SecureMessagingClient

WebSocket client for secure messaging.

```python
from src.messaging.client import SecureMessagingClient

client = SecureMessagingClient("ws://localhost:8765")

# Connect
await client.connect("user_id", "aes_256_gcm")

# Send message
await client.send_message("Hello", "recipient_id")

# Register callbacks
client.on_message_received(callback_function)
client.on_message_decrypted(callback_function)
```

## Security Considerations

### Algorithm Selection
- **AES-256-GCM**: Best for general-purpose encryption, widely supported
- **ChaCha20-Poly1305**: Excellent performance, especially on mobile devices
- **Twofish-CBC**: Alternative to AES, good for environments requiring algorithm diversity

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

## Testing

Run the comprehensive test suite:

```bash
python tests/test_crypto.py
```

The tests cover:
- Algorithm encryption/decryption
- Session management
- Key rotation
- Message integrity
- Integration scenarios

## Performance

Typical performance metrics (on modern hardware):
- **AES-256-GCM**: ~1000 messages/second
- **ChaCha20-Poly1305**: ~1200 messages/second  
- **Twofish-CBC**: ~800 messages/second

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is a research and educational project. For production use, please ensure proper security audits and consider additional security measures such as:
- Certificate pinning
- Network-level encryption (TLS)
- Rate limiting
- Input validation
- Secure key storage
- Audit logging