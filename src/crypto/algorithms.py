"""
Multi-Algorithm Encryption System
Supports AES-256-GCM, ChaCha20-Poly1305, and AES-256-CBC encryption algorithms
"""

import os
import base64
import json
from typing import Dict, Any, Optional, Tuple
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


class AlgorithmType(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    AES_256_CBC = "aes_256_cbc"


class EncryptionAlgorithm:
    """Base class for encryption algorithms"""
    
    def __init__(self, algorithm_type: AlgorithmType):
        self.algorithm_type = algorithm_type
        self.key_size = self._get_key_size()
        self.iv_size = self._get_iv_size()
    
    def _get_key_size(self) -> int:
        """Get key size in bytes"""
        if self.algorithm_type == AlgorithmType.AES_256_GCM:
            return 32
        elif self.algorithm_type == AlgorithmType.CHACHA20_POLY1305:
            return 32
        elif self.algorithm_type == AlgorithmType.AES_256_CBC:
            return 32
        return 32
    
    def _get_iv_size(self) -> int:
        """Get IV size in bytes"""
        if self.algorithm_type == AlgorithmType.AES_256_GCM:
            return 12
        elif self.algorithm_type == AlgorithmType.CHACHA20_POLY1305:
            return 12
        elif self.algorithm_type == AlgorithmType.AES_256_CBC:
            return 16
        return 16
    
    def generate_key(self) -> bytes:
        """Generate a random key"""
        return get_random_bytes(self.key_size)
    
    def generate_iv(self) -> bytes:
        """Generate a random IV"""
        return get_random_bytes(self.iv_size)
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data and return (ciphertext, tag)"""
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt data"""
        raise NotImplementedError


class AES256GCM(EncryptionAlgorithm):
    """AES-256-GCM implementation"""
    
    def __init__(self):
        super().__init__(AlgorithmType.AES_256_GCM)
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext


class ChaCha20Poly1305(EncryptionAlgorithm):
    """ChaCha20-Poly1305 implementation"""
    
    def __init__(self):
        super().__init__(AlgorithmType.CHACHA20_POLY1305)
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305"""
        cipher = ChaCha20.new(key=key, nonce=iv)
        ciphertext = cipher.encrypt(data)
        
        # Generate authentication tag using HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        tag = h.finalize()
        
        return ciphertext, tag
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        # Verify authentication tag
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        h.verify(tag)
        
        cipher = ChaCha20.new(key=key, nonce=iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext


class AES256CBC(EncryptionAlgorithm):
    """AES-256-CBC implementation"""
    
    def __init__(self):
        super().__init__(AlgorithmType.AES_256_CBC)
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        """Encrypt using AES-256-CBC"""
        # Pad data to block size
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length] * padding_length)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        
        # Generate authentication tag
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        tag = h.finalize()
        
        return ciphertext, tag
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt using AES-256-CBC"""
        # Verify authentication tag
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        h.verify(tag)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext


class MultiAlgorithmCrypto:
    """Multi-algorithm encryption system"""
    
    def __init__(self):
        self.algorithms = {
            AlgorithmType.AES_256_GCM: AES256GCM(),
            AlgorithmType.CHACHA20_POLY1305: ChaCha20Poly1305(),
            AlgorithmType.AES_256_CBC: AES256CBC()
        }
    
    def get_algorithm(self, algorithm_type: AlgorithmType) -> EncryptionAlgorithm:
        """Get algorithm instance"""
        return self.algorithms[algorithm_type]
    
    def encrypt_message(self, message: bytes, algorithm_type: AlgorithmType, 
                       key: bytes, iv: Optional[bytes] = None) -> Dict[str, Any]:
        """Encrypt a message using specified algorithm"""
        algorithm = self.get_algorithm(algorithm_type)
        
        if iv is None:
            iv = algorithm.generate_iv()
        
        ciphertext, tag = algorithm.encrypt(message, key, iv)
        
        return {
            "algorithm": algorithm_type.value,
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
    
    def decrypt_message(self, encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """Decrypt a message"""
        algorithm_type = AlgorithmType(encrypted_data["algorithm"])
        algorithm = self.get_algorithm(algorithm_type)
        
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        iv = base64.b64decode(encrypted_data["iv"])
        tag = base64.b64decode(encrypted_data["tag"])
        
        return algorithm.decrypt(ciphertext, key, iv, tag)
    
    def generate_session_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generate session key from password"""
        if salt is None:
            salt = get_random_bytes(32)
        
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        return key, salt