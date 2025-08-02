"""
Multi-Algorithm Encryption Engine
=================================

Supports multiple encryption algorithms with a unified interface:
- AES-256-GCM (Authenticated Encryption)
- ChaCha20-Poly1305 (Stream cipher with authentication)
- RSA-OAEP (Asymmetric encryption for key exchange)
"""

import os
import secrets
from enum import Enum
from typing import Tuple, Dict, Any, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_OAEP = "rsa_oaep"


@dataclass
class EncryptionResult:
    """Container for encryption results"""
    ciphertext: bytes
    nonce: Optional[bytes] = None
    tag: Optional[bytes] = None
    algorithm: Optional[EncryptionAlgorithm] = None
    metadata: Optional[Dict[str, Any]] = None


class EncryptionEngine:
    """
    Multi-algorithm encryption engine with support for both symmetric and asymmetric encryption.
    """
    
    def __init__(self):
        self.backend = default_backend()
        self._rsa_keys: Dict[str, rsa.RSAPrivateKey] = {}
    
    def generate_symmetric_key(self, algorithm: EncryptionAlgorithm) -> bytes:
        """Generate a random symmetric key for the specified algorithm"""
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return secrets.token_bytes(32)  # 256 bits
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return secrets.token_bytes(32)  # 256 bits
        else:
            raise ValueError(f"Cannot generate symmetric key for {algorithm}")
    
    def generate_rsa_keypair(self, key_id: str, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair and store private key internally
        Returns: (public_key_pem, private_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # Store private key for decryption
        self._rsa_keys[key_id] = private_key
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem, private_pem
    
    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes, 
                       associated_data: Optional[bytes] = None) -> EncryptionResult:
        """Encrypt using AES-256-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            algorithm=EncryptionAlgorithm.AES_256_GCM,
            metadata={'associated_data': associated_data is not None}
        )
    
    def decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, nonce: bytes,
                       associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt using AES-256-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    def encrypt_chacha20_poly1305(self, plaintext: bytes, key: bytes,
                                 associated_data: Optional[bytes] = None) -> EncryptionResult:
        """Encrypt using ChaCha20-Poly1305"""
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # 96-bit nonce
        
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
        
        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            algorithm=EncryptionAlgorithm.CHACHA20_POLY1305,
            metadata={'associated_data': associated_data is not None}
        )
    
    def decrypt_chacha20_poly1305(self, ciphertext: bytes, key: bytes, nonce: bytes,
                                 associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, associated_data)
    
    def encrypt_rsa_oaep(self, plaintext: bytes, public_key_pem: bytes) -> EncryptionResult:
        """Encrypt using RSA-OAEP"""
        public_key = serialization.load_pem_public_key(public_key_pem, backend=self.backend)
        
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return EncryptionResult(
            ciphertext=ciphertext,
            algorithm=EncryptionAlgorithm.RSA_OAEP
        )
    
    def decrypt_rsa_oaep(self, ciphertext: bytes, key_id: str) -> bytes:
        """Decrypt using RSA-OAEP with stored private key"""
        if key_id not in self._rsa_keys:
            raise ValueError(f"Private key for {key_id} not found")
        
        private_key = self._rsa_keys[key_id]
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    def encrypt(self, plaintext: bytes, key: bytes, algorithm: EncryptionAlgorithm,
               associated_data: Optional[bytes] = None, 
               public_key_pem: Optional[bytes] = None) -> EncryptionResult:
        """
        Unified encryption interface
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key (for symmetric algorithms)
            algorithm: Encryption algorithm to use
            associated_data: Additional authenticated data (for AEAD)
            public_key_pem: Public key (for RSA)
        """
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return self.encrypt_aes_gcm(plaintext, key, associated_data)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return self.encrypt_chacha20_poly1305(plaintext, key, associated_data)
        elif algorithm == EncryptionAlgorithm.RSA_OAEP:
            if public_key_pem is None:
                raise ValueError("RSA encryption requires public_key_pem")
            return self.encrypt_rsa_oaep(plaintext, public_key_pem)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt(self, encryption_result: EncryptionResult, key: Optional[bytes] = None,
               associated_data: Optional[bytes] = None, key_id: Optional[str] = None) -> bytes:
        """
        Unified decryption interface
        
        Args:
            encryption_result: Result from encryption
            key: Decryption key (for symmetric algorithms)  
            associated_data: Additional authenticated data (for AEAD)
            key_id: Key identifier (for RSA)
        """
        algorithm = encryption_result.algorithm
        
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            if key is None or encryption_result.nonce is None:
                raise ValueError("AES-GCM decryption requires key and nonce")
            return self.decrypt_aes_gcm(
                encryption_result.ciphertext, key, encryption_result.nonce, associated_data
            )
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            if key is None or encryption_result.nonce is None:
                raise ValueError("ChaCha20-Poly1305 decryption requires key and nonce")
            return self.decrypt_chacha20_poly1305(
                encryption_result.ciphertext, key, encryption_result.nonce, associated_data
            )
        elif algorithm == EncryptionAlgorithm.RSA_OAEP:
            if key_id is None:
                raise ValueError("RSA decryption requires key_id")
            return self.decrypt_rsa_oaep(encryption_result.ciphertext, key_id)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def get_public_key(self, key_id: str) -> bytes:
        """Get public key PEM for a stored RSA key pair"""
        if key_id not in self._rsa_keys:
            raise ValueError(f"Key ID {key_id} not found")
        
        private_key = self._rsa_keys[key_id]
        public_key = private_key.public_key()
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def cleanup_keys(self, key_id: Optional[str] = None):
        """Remove stored keys for security"""
        if key_id:
            self._rsa_keys.pop(key_id, None)
        else:
            self._rsa_keys.clear()