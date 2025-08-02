# Secure Multi-Algorithm Messaging System

A session-based multi-algorithm encryption system for secure messaging with support for multiple encryption algorithms, secure key exchange, and real-time communication.

## Features

- **Multi-Algorithm Support**: AES-256-GCM, ChaCha20-Poly1305, Twofish
- **Session Management**: Secure session establishment with key derivation
- **Key Exchange**: Diffie-Hellman key exchange for secure communication
- **Message Authentication**: HMAC-based message integrity verification
- **Real-time Communication**: WebSocket and MQTT support
- **User Authentication**: JWT-based authentication system
- **Forward Secrecy**: Session keys are ephemeral and not stored

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client A  │    │   Server    │    │   Client B  │
│             │    │             │    │             │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │Session  │ │    │ │Session  │ │    │ │Session  │ │
│ │Manager  │ │    │ │Manager  │ │    │ │Manager  │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │Crypto   │ │    │ │Crypto   │ │    │ │Crypto   │ │
│ │Engine   │ │    │ │Engine   │ │    │ │Engine   │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```
4. Run the server:
   ```bash
   python server.py
   ```

## Usage

### Starting the Server
```bash
python server.py
```

### Running a Client
```bash
python client.py --username alice --server localhost:8000
```

### API Endpoints

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Authenticate user
- `POST /session/create` - Create a new session
- `POST /session/join` - Join an existing session
- `GET /session/{session_id}/messages` - Get session messages
- `POST /session/{session_id}/send` - Send encrypted message

## Security Features

- **Forward Secrecy**: Each session uses unique ephemeral keys
- **Perfect Forward Secrecy**: Keys are derived using Diffie-Hellman
- **Message Integrity**: HMAC verification for all messages
- **Replay Protection**: Timestamp-based nonce generation
- **Algorithm Agility**: Support for multiple encryption algorithms
- **Key Rotation**: Automatic key rotation within sessions

## Encryption Algorithms

1. **AES-256-GCM**: Authenticated encryption with Galois/Counter Mode
2. **ChaCha20-Poly1305**: High-performance authenticated encryption
3. **Twofish**: Alternative block cipher for algorithm diversity

## Session Flow

1. **Authentication**: User authenticates with JWT token
2. **Session Creation**: Diffie-Hellman key exchange establishes shared secret
3. **Key Derivation**: Session keys derived using HKDF
4. **Algorithm Selection**: Clients negotiate preferred encryption algorithm
5. **Message Exchange**: Encrypted messages with HMAC verification
6. **Key Rotation**: Periodic key rotation for enhanced security

## Configuration

Edit `.env` file to configure:
- Server host and port
- Database settings
- JWT secret key
- Encryption preferences
- Session timeout values

## Security Considerations

- All cryptographic operations use secure random number generation
- Keys are never stored in plaintext
- Session keys are ephemeral and discarded after use
- Message authentication prevents tampering
- Algorithm negotiation prevents downgrade attacks

## License

MIT License - see LICENSE file for details.