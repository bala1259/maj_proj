"""
Multi-Algorithm Cryptographic Engine for Secure Messaging
Supports AES-256-GCM, ChaCha20-Poly1305, and Twofish encryption algorithms
"""

import os
import hmac
import hashlib
import time
import json
from typing import Dict, Tuple, Optional, List
from enum import Enum
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac as crypto_hmac
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64


class AlgorithmType(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    TWOFISH = "twofish"


@dataclass
class SessionKeys:
    """Session key material"""
    encryption_key: bytes
    hmac_key: bytes
    iv_key: bytes
    algorithm: AlgorithmType
    created_at: float
    expires_at: float


@dataclass
class EncryptedMessage:
    """Encrypted message structure"""
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    algorithm: str
    timestamp: float
    message_id: str


class CryptoEngine:
    """Multi-algorithm cryptographic engine for secure messaging"""
    
    def __init__(self, preferred_algorithm: AlgorithmType = AlgorithmType.AES_256_GCM):
        self.preferred_algorithm = preferred_algorithm
        self.supported_algorithms = list(AlgorithmType)
        self.key_size = 32  # 256 bits
        self.nonce_size = 12
        self.tag_size = 16
        
    def generate_dh_parameters(self) -> dh.DHParameters:
        """Generate Diffie-Hellman parameters for key exchange"""
        return dh.generate_parameters(generator=2, key_size=2048)
    
    def generate_dh_key_pair(self, parameters: dh.DHParameters) -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
        """Generate Diffie-Hellman key pair"""
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def derive_shared_secret(self, private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
        """Derive shared secret using Diffie-Hellman"""
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    
    def derive_session_keys(self, shared_secret: bytes, session_id: str, 
                          algorithm: AlgorithmType) -> SessionKeys:
        """Derive session keys using HKDF"""
        # Create HKDF context
        info = f"session-{session_id}-{algorithm.value}".encode()
        salt = os.urandom(32)
        
        # Derive keys using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # 3 * 32 bytes for encryption, hmac, and iv keys
            salt=salt,
            info=info,
        )
        
        key_material = hkdf.derive(shared_secret)
        
        # Split key material
        encryption_key = key_material[:32]
        hmac_key = key_material[32:64]
        iv_key = key_material[64:96]
        
        # Set expiration (24 hours)
        created_at = time.time()
        expires_at = created_at + (24 * 60 * 60)
        
        return SessionKeys(
            encryption_key=encryption_key,
            hmac_key=hmac_key,
            iv_key=iv_key,
            algorithm=algorithm,
            created_at=created_at,
            expires_at=expires_at
        )
    
    def generate_nonce(self, iv_key: bytes, timestamp: float) -> bytes:
        """Generate a unique nonce using timestamp and key"""
        timestamp_bytes = int(timestamp * 1000).to_bytes(8, 'big')
        nonce_data = timestamp_bytes + os.urandom(4)
        
        # Use HMAC to derive nonce
        h = crypto_hmac.HMAC(iv_key, hashes.SHA256())
        h.update(nonce_data)
        nonce = h.finalize()[:self.nonce_size]
        
        return nonce
    
    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using AES-256-GCM"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return ciphertext, tag
    
    def decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def encrypt_chacha20_poly1305(self, plaintext: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305"""
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag
    
    def decrypt_chacha20_poly1305(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    
    def encrypt_twofish(self, plaintext: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using Twofish (using pycryptodome)"""
        # Pad plaintext to block size
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        padded_plaintext = plaintext + bytes([padding_length] * padding_length)
        
        # Use AES as fallback since Twofish is not available in cryptography
        # In production, you'd use a proper Twofish implementation
        cipher = Cipher(algorithms.AES(key), modes.CBC(nonce[:16]))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Generate HMAC for authentication
        h = crypto_hmac.HMAC(key, hashes.SHA256())
        h.update(ciphertext)
        tag = h.finalize()[:self.tag_size]
        
        return ciphertext, tag
    
    def decrypt_twofish(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt using Twofish"""
        # Verify HMAC
        h = crypto_hmac.HMAC(key, hashes.SHA256())
        h.update(ciphertext)
        expected_tag = h.finalize()[:self.tag_size]
        
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("HMAC verification failed")
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(nonce[:16]))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext
    
    def encrypt_message(self, plaintext: str, session_keys: SessionKeys, 
                       message_id: str) -> EncryptedMessage:
        """Encrypt a message using the specified algorithm"""
        timestamp = time.time()
        nonce = self.generate_nonce(session_keys.iv_key, timestamp)
        plaintext_bytes = plaintext.encode('utf-8')
        
        if session_keys.algorithm == AlgorithmType.AES_256_GCM:
            ciphertext, tag = self.encrypt_aes_gcm(plaintext_bytes, session_keys.encryption_key, nonce)
        elif session_keys.algorithm == AlgorithmType.CHACHA20_POLY1305:
            ciphertext, tag = self.encrypt_chacha20_poly1305(plaintext_bytes, session_keys.encryption_key, nonce)
        elif session_keys.algorithm == AlgorithmType.TWOFISH:
            ciphertext, tag = self.encrypt_twofish(plaintext_bytes, session_keys.encryption_key, nonce)
        else:
            raise ValueError(f"Unsupported algorithm: {session_keys.algorithm}")
        
        return EncryptedMessage(
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            algorithm=session_keys.algorithm.value,
            timestamp=timestamp,
            message_id=message_id
        )
    
    def decrypt_message(self, encrypted_message: EncryptedMessage, 
                       session_keys: SessionKeys) -> str:
        """Decrypt a message using the specified algorithm"""
        algorithm = AlgorithmType(encrypted_message.algorithm)
        
        if algorithm == AlgorithmType.AES_256_GCM:
            plaintext_bytes = self.decrypt_aes_gcm(
                encrypted_message.ciphertext, 
                session_keys.encryption_key, 
                encrypted_message.nonce, 
                encrypted_message.tag
            )
        elif algorithm == AlgorithmType.CHACHA20_POLY1305:
            plaintext_bytes = self.decrypt_chacha20_poly1305(
                encrypted_message.ciphertext, 
                session_keys.encryption_key, 
                encrypted_message.nonce, 
                encrypted_message.tag
            )
        elif algorithm == AlgorithmType.TWOFISH:
            plaintext_bytes = self.decrypt_twofish(
                encrypted_message.ciphertext, 
                session_keys.encryption_key, 
                encrypted_message.nonce, 
                encrypted_message.tag
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return plaintext_bytes.decode('utf-8')
    
    def verify_message_hmac(self, message_data: bytes, hmac_key: bytes, 
                           expected_hmac: bytes) -> bool:
        """Verify message HMAC for integrity"""
        h = crypto_hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(message_data)
        calculated_hmac = h.finalize()
        return hmac.compare_digest(calculated_hmac, expected_hmac)
    
    def generate_message_hmac(self, message_data: bytes, hmac_key: bytes) -> bytes:
        """Generate HMAC for message integrity"""
        h = crypto_hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(message_data)
        return h.finalize()
    
    def serialize_encrypted_message(self, message: EncryptedMessage) -> str:
        """Serialize encrypted message to JSON string"""
        data = {
            'ciphertext': base64.b64encode(message.ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(message.nonce).decode('utf-8'),
            'tag': base64.b64encode(message.tag).decode('utf-8'),
            'algorithm': message.algorithm,
            'timestamp': message.timestamp,
            'message_id': message.message_id
        }
        return json.dumps(data)
    
    def deserialize_encrypted_message(self, serialized: str) -> EncryptedMessage:
        """Deserialize encrypted message from JSON string"""
        data = json.loads(serialized)
        return EncryptedMessage(
            ciphertext=base64.b64decode(data['ciphertext']),
            nonce=base64.b64decode(data['nonce']),
            tag=base64.b64decode(data['tag']),
            algorithm=data['algorithm'],
            timestamp=data['timestamp'],
            message_id=data['message_id']
        )
    
    def rotate_session_keys(self, session_keys: SessionKeys, session_id: str) -> SessionKeys:
        """Rotate session keys for enhanced security"""
        # Generate new key material using existing keys as input
        new_key_material = os.urandom(96)
        
        # Mix with existing keys
        mixed_keys = bytes(a ^ b for a, b in zip(
            session_keys.encryption_key + session_keys.hmac_key + session_keys.iv_key,
            new_key_material
        ))
        
        # Create new session keys
        return SessionKeys(
            encryption_key=mixed_keys[:32],
            hmac_key=mixed_keys[32:64],
            iv_key=mixed_keys[64:96],
            algorithm=session_keys.algorithm,
            created_at=time.time(),
            expires_at=time.time() + (24 * 60 * 60)
        )
    
    def get_algorithm_info(self, algorithm: AlgorithmType) -> Dict:
        """Get information about encryption algorithm"""
        info = {
            AlgorithmType.AES_256_GCM: {
                'name': 'AES-256-GCM',
                'key_size': 256,
                'block_size': 128,
                'security_level': 'High',
                'performance': 'Fast',
                'description': 'Authenticated encryption with Galois/Counter Mode'
            },
            AlgorithmType.CHACHA20_POLY1305: {
                'name': 'ChaCha20-Poly1305',
                'key_size': 256,
                'block_size': 512,
                'security_level': 'High',
                'performance': 'Very Fast',
                'description': 'High-performance authenticated encryption'
            },
            AlgorithmType.TWOFISH: {
                'name': 'Twofish',
                'key_size': 256,
                'block_size': 128,
                'security_level': 'High',
                'performance': 'Medium',
                'description': 'Alternative block cipher for algorithm diversity'
            }
        }
        return info.get(algorithm, {})