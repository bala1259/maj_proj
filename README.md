# Multi-Algorithm Encryption System for Secure Messaging

A comprehensive session-based multi-algorithm encryption system designed for secure peer-to-peer messaging with perfect forward secrecy, automatic key rotation, and digital signatures.

## 🔐 Features

### Core Security Features
- **Multiple Encryption Algorithms**: AES-256-GCM, ChaCha20-Poly1305, RSA-OAEP
- **Perfect Forward Secrecy**: ECDH key exchange with automatic key cleanup
- **Session Management**: Automatic key rotation based on time or message count
- **Digital Signatures**: RSA-PSS signatures for message authentication
- **Message Integrity**: Built-in tamper detection and replay protection
- **Authenticated Encryption**: AEAD support with associated data protection

### Advanced Features
- **Session-based Communication**: Isolated encryption contexts per peer
- **Automatic Key Rotation**: Configurable time and count-based rotation
- **Secure Key Exchange**: ECDH with multiple curve support (secp256r1, secp384r1, secp521r1)
- **Message Protocol**: Complete secure messaging protocol with metadata
- **High-level Client Interface**: Easy-to-use API for secure communications
- **Performance Optimized**: Efficient implementation with minimal overhead

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SecureClient  │────│ SessionManager  │────│EncryptionEngine │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────│  SecureMessage  │──────────────┘
                        └─────────────────┘
                                 │
                        ┌─────────────────┐
                        │   KeyExchange   │
                        └─────────────────┘
```

### Components

1. **EncryptionEngine**: Multi-algorithm encryption with unified interface
2. **KeyExchange**: ECDH key exchange for establishing shared secrets
3. **SessionManager**: Manages encryption sessions with automatic key rotation
4. **SecureMessage**: Secure messaging protocol with signatures and integrity
5. **SecureClient**: High-level interface for secure peer-to-peer communication

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```python
from src import SecureClient, EncryptionAlgorithm

# Create clients
alice = SecureClient("alice")
bob = SecureClient("bob")

# Exchange identities
alice_identity = alice.export_identity()
bob_identity = bob.export_identity()

# Add each other as peers
alice.add_peer("bob", signing_key=bob_identity['public_signing_key'].encode())
bob.add_peer("alice", signing_key=alice_identity['public_signing_key'].encode())

# Establish secure session
session_id, alice_public = alice.initiate_session("bob")
bob_session_id, bob_public = bob.initiate_session("alice")

# Complete key exchange
alice.complete_session(session_id, bob_public)
bob.complete_session(bob_session_id, alice_public)

# Send encrypted message
encrypted_data = alice.send_message("bob", "Hello, secure world!")

# Receive and decrypt message
sender, message, info = bob.receive_message(encrypted_data)
print(f"Received from {sender}: {message}")
```

### Run Demo

```bash
python demo.py
```

## 📚 Detailed Documentation

### Encryption Algorithms

#### AES-256-GCM
- **Type**: Symmetric authenticated encryption
- **Key Size**: 256 bits
- **Nonce**: 96 bits (automatically generated)
- **Use Case**: General purpose, hardware accelerated on modern CPUs

#### ChaCha20-Poly1305
- **Type**: Stream cipher with authentication
- **Key Size**: 256 bits
- **Nonce**: 96 bits (automatically generated)
- **Use Case**: Software-only environments, mobile devices

#### RSA-OAEP
- **Type**: Asymmetric encryption
- **Key Size**: 2048+ bits (configurable)
- **Use Case**: Key exchange, small data encryption

### Key Exchange Protocol

The system uses Elliptic Curve Diffie-Hellman (ECDH) for establishing shared secrets:

1. **Keypair Generation**: Each party generates an ECDH keypair
2. **Public Key Exchange**: Parties exchange public keys
3. **Shared Secret Derivation**: Both parties compute the same shared secret
4. **Key Derivation**: HKDF derives the final session key from the shared secret
5. **Forward Secrecy**: ECDH private keys are immediately discarded

### Session Management

Sessions provide isolated encryption contexts with automatic key rotation:

```python
from src import SessionManager, EncryptionAlgorithm

session_manager = SessionManager(
    default_algorithm=EncryptionAlgorithm.AES_256_GCM,
    default_rotation_interval=3600.0,  # 1 hour
    default_max_messages=1000,         # Rotate after 1000 messages
    session_timeout=86400.0            # 24 hour timeout
)

# Create session
session_id = session_manager.create_session("peer_id")

# Get session key (automatically rotates if needed)
key = session_manager.get_session_key(session_id)
```

### Message Protocol

The secure message protocol provides:

- **Message Encryption**: Payload encrypted with session key
- **Message Authentication**: Digital signatures for sender verification
- **Integrity Protection**: Hash verification prevents tampering
- **Replay Protection**: Sequence numbers prevent replay attacks
- **Metadata Protection**: Important metadata included in AEAD

```python
from src.message_protocol import SecureMessage, MessageType

# Create secure message handler
secure_msg = SecureMessage(encryption_engine)

# Generate signing keys
public_key, private_key = secure_msg.generate_signing_keypair("sender_id")

# Create encrypted message
envelope = secure_msg.create_message(
    payload=b"Secret message",
    sender_id="alice",
    recipient_id="bob",
    session_id="session_123",
    session_key=session_key,
    algorithm=EncryptionAlgorithm.AES_256_GCM,
    message_type=MessageType.TEXT
)

# Serialize for transmission
serialized = secure_msg.serialize_envelope(envelope)
```

## 🔧 Configuration

### Algorithm Selection

Choose encryption algorithms based on your requirements:

```python
# For maximum compatibility and performance
EncryptionAlgorithm.AES_256_GCM

# For software-only environments
EncryptionAlgorithm.CHACHA20_POLY1305

# For small data or key exchange
EncryptionAlgorithm.RSA_OAEP
```

### Key Rotation Settings

Configure automatic key rotation:

```python
SessionManager(
    default_rotation_interval=1800.0,  # 30 minutes
    default_max_messages=500,          # Rotate after 500 messages
    session_timeout=43200.0            # 12 hour timeout
)
```

### ECDH Curve Selection

Choose elliptic curves for key exchange:

```python
# Standard curves supported
KeyExchange('secp256r1')  # P-256 (recommended)
KeyExchange('secp384r1')  # P-384 (higher security)
KeyExchange('secp521r1')  # P-521 (maximum security)
```

## 🛡️ Security Considerations

### Cryptographic Strength
- **AES-256**: Industry standard, quantum-resistant for foreseeable future
- **ChaCha20**: Modern stream cipher, resistant to timing attacks
- **ECDH**: Provides perfect forward secrecy
- **RSA-PSS**: Secure signature scheme with provable security

### Implementation Security
- **Memory Safety**: Keys are securely erased after use
- **Timing Attack Resistance**: Constant-time operations where possible
- **Replay Protection**: Sequence numbers prevent message replay
- **Integrity Verification**: AEAD prevents tampering

### Best Practices
1. **Regular Key Rotation**: Use short rotation intervals for high-security applications
2. **Secure Key Storage**: Never store session keys persistently
3. **Forward Secrecy**: ECDH keys are automatically cleaned up
4. **Signature Verification**: Always verify message signatures
5. **Session Timeouts**: Use appropriate timeouts for your threat model

## 🧪 Testing

Run the test suite:

```bash
pytest tests/ -v
```

The test suite covers:
- All encryption algorithms
- Key exchange protocols
- Session management
- Message protocol
- Security features
- Error handling

## 📈 Performance

### Benchmark Results (Example)

| Algorithm          | Data Size | Encrypt Time | Decrypt Time |
|-------------------|-----------|--------------|--------------|
| AES-256-GCM       | 1KB       | 0.05ms       | 0.04ms       |
| AES-256-GCM       | 100KB     | 2.1ms        | 1.9ms        |
| ChaCha20-Poly1305 | 1KB       | 0.08ms       | 0.07ms       |
| ChaCha20-Poly1305 | 100KB     | 3.2ms        | 2.8ms        |

*Benchmarks run on modern hardware. Results may vary.*

### Performance Tips
1. **Algorithm Choice**: AES-256-GCM is generally fastest with hardware acceleration
2. **Key Reuse**: Session keys avoid expensive key derivation per message
3. **Batch Operations**: Process multiple messages in a session for efficiency
4. **Memory Management**: Regular cleanup prevents memory bloat

## 🔍 Security Audit

### Cryptographic Libraries
- **cryptography**: Industry-standard Python cryptography library
- **PyNaCl**: Bindings to libsodium for ChaCha20-Poly1305
- **ECDSA**: Elliptic curve cryptography implementation

### Security Features Checklist
- ✅ Perfect Forward Secrecy
- ✅ Authenticated Encryption
- ✅ Digital Signatures
- ✅ Key Rotation
- ✅ Replay Protection
- ✅ Integrity Verification
- ✅ Secure Key Management
- ✅ Multiple Algorithm Support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and demonstration purposes. Please review and test thoroughly before using in production environments.

## 🔗 Related Projects

- [Signal Protocol](https://signal.org/docs/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Noise Protocol Framework](http://noiseprotocol.org/)

## 📞 Support

For questions or issues, please:
1. Check the demo application for usage examples
2. Review the test suite for implementation details
3. Consult the source code documentation
