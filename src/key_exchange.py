"""
Elliptic Curve Diffie-Hellman Key Exchange
==========================================

Implements ECDH key exchange protocol for establishing shared secrets
between parties with perfect forward secrecy.
"""

import os
import secrets
from typing import Tuple, Optional, Dict
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


@dataclass
class KeyExchangeResult:
    """Result of key exchange containing shared secret and metadata"""
    shared_secret: bytes
    public_key: bytes
    key_id: str
    curve_name: str


class KeyExchange:
    """
    ECDH key exchange implementation with support for multiple curves
    and automatic key derivation.
    """
    
    # Supported elliptic curves
    SUPPORTED_CURVES = {
        'secp256r1': ec.SECP256R1(),
        'secp384r1': ec.SECP384R1(),
        'secp521r1': ec.SECP521R1()
    }
    
    def __init__(self, curve_name: str = 'secp256r1'):
        """
        Initialize key exchange with specified curve
        
        Args:
            curve_name: Name of elliptic curve to use
        """
        if curve_name not in self.SUPPORTED_CURVES:
            raise ValueError(f"Unsupported curve: {curve_name}. Supported: {list(self.SUPPORTED_CURVES.keys())}")
        
        self.curve_name = curve_name
        self.curve = self.SUPPORTED_CURVES[curve_name]
        self.backend = default_backend()
        self._private_keys: Dict[str, ec.EllipticCurvePrivateKey] = {}
    
    def generate_keypair(self, key_id: Optional[str] = None) -> Tuple[str, bytes]:
        """
        Generate a new ECDH keypair
        
        Args:
            key_id: Optional key identifier, generated if not provided
            
        Returns:
            Tuple of (key_id, public_key_bytes)
        """
        if key_id is None:
            key_id = secrets.token_hex(16)
        
        # Generate private key
        private_key = ec.generate_private_key(self.curve, self.backend)
        self._private_keys[key_id] = private_key
        
        # Get public key bytes
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        return key_id, public_key_bytes
    
    def perform_exchange(self, key_id: str, peer_public_key: bytes, 
                        salt: Optional[bytes] = None, 
                        info: Optional[bytes] = None,
                        key_length: int = 32) -> KeyExchangeResult:
        """
        Perform ECDH key exchange and derive shared secret
        
        Args:
            key_id: ID of our private key
            peer_public_key: Peer's public key bytes
            salt: Optional salt for HKDF (generated if not provided)
            info: Optional context info for HKDF
            key_length: Length of derived key in bytes
            
        Returns:
            KeyExchangeResult with shared secret and metadata
        """
        if key_id not in self._private_keys:
            raise ValueError(f"Private key {key_id} not found")
        
        private_key = self._private_keys[key_id]
        
        # Load peer's public key
        peer_public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve, peer_public_key
        )
        
        # Perform ECDH exchange
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key_obj)
        
        # Derive final shared secret using HKDF
        if salt is None:
            salt = os.urandom(32)
        
        if info is None:
            info = f"ECDH-{self.curve_name}".encode('utf-8')
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=info,
            backend=self.backend
        )
        
        shared_secret = hkdf.derive(shared_key)
        
        # Get our public key for the exchange
        our_public_key = private_key.public_key()
        our_public_key_bytes = our_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        return KeyExchangeResult(
            shared_secret=shared_secret,
            public_key=our_public_key_bytes,
            key_id=key_id,
            curve_name=self.curve_name
        )
    
    def get_public_key(self, key_id: str) -> bytes:
        """Get public key bytes for a stored private key"""
        if key_id not in self._private_keys:
            raise ValueError(f"Private key {key_id} not found")
        
        private_key = self._private_keys[key_id]
        public_key = private_key.public_key()
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def export_public_key_pem(self, key_id: str) -> bytes:
        """Export public key in PEM format"""
        if key_id not in self._private_keys:
            raise ValueError(f"Private key {key_id} not found")
        
        private_key = self._private_keys[key_id]
        public_key = private_key.public_key()
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def import_public_key_pem(self, pem_data: bytes) -> bytes:
        """Import public key from PEM format and convert to exchange format"""
        public_key = serialization.load_pem_public_key(pem_data, backend=self.backend)
        
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Not an elliptic curve public key")
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def cleanup_key(self, key_id: str):
        """Remove private key from memory for security"""
        self._private_keys.pop(key_id, None)
    
    def cleanup_all_keys(self):
        """Remove all private keys from memory"""
        self._private_keys.clear()
    
    def list_keys(self) -> list:
        """List all stored key IDs"""
        return list(self._private_keys.keys())
    
    @staticmethod
    def validate_curve_support(curve_name: str) -> bool:
        """Check if a curve is supported"""
        return curve_name in KeyExchange.SUPPORTED_CURVES
    
    @classmethod
    def get_supported_curves(cls) -> list:
        """Get list of supported curve names"""
        return list(cls.SUPPORTED_CURVES.keys())