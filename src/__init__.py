"""
Multi-Algorithm Encryption System for Secure Messaging
======================================================

A session-based encryption system supporting multiple cryptographic algorithms
for secure peer-to-peer messaging with forward secrecy.

Features:
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305, RSA-OAEP)
- ECDH key exchange for perfect forward secrecy
- Session-based key management
- Digital signatures for authentication
- Secure messaging protocol
"""

__version__ = "1.0.0"
__author__ = "Secure Messaging System"

from .session_manager import SessionManager
from .encryption import EncryptionEngine
from .key_exchange import KeyExchange
from .message_protocol import SecureMessage
from .client import SecureClient

__all__ = [
    'SessionManager',
    'EncryptionEngine', 
    'KeyExchange',
    'SecureMessage',
    'SecureClient'
]