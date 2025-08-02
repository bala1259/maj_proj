"""
Secure Message Protocol
=======================

Implements a secure messaging protocol with encryption, digital signatures,
message integrity, and metadata handling.
"""

import json
import time
import hashlib
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from .encryption import EncryptionEngine, EncryptionAlgorithm, EncryptionResult


class MessageType(Enum):
    """Types of secure messages"""
    TEXT = "text"
    KEY_EXCHANGE = "key_exchange"
    KEY_ROTATION = "key_rotation"
    SYSTEM = "system"
    FILE = "file"


@dataclass
class MessageMetadata:
    """Metadata for secure messages"""
    message_id: str
    sender_id: str
    recipient_id: str
    message_type: MessageType
    timestamp: float
    session_id: str
    algorithm: EncryptionAlgorithm
    sequence_number: int
    message_hash: Optional[str] = None
    signature: Optional[bytes] = None
    extra_data: Dict[str, Any] = None


@dataclass
class SecureMessageEnvelope:
    """Complete secure message envelope"""
    metadata: MessageMetadata
    encrypted_payload: bytes
    nonce: Optional[bytes] = None
    signature: Optional[bytes] = None


class SecureMessage:
    """
    Secure message protocol implementation with encryption, signatures,
    and integrity verification.
    """
    
    def __init__(self, encryption_engine: EncryptionEngine):
        """
        Initialize secure message handler
        
        Args:
            encryption_engine: Encryption engine instance
        """
        self.encryption_engine = encryption_engine
        self.backend = default_backend()
        self._signing_keys: Dict[str, rsa.RSAPrivateKey] = {}
        self._verification_keys: Dict[str, rsa.RSAPublicKey] = {}
        self._sequence_numbers: Dict[str, int] = {}  # session_id -> sequence_number
    
    def generate_signing_keypair(self, key_id: str, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA signing keypair
        
        Args:
            key_id: Identifier for the keypair
            key_size: RSA key size in bits
            
        Returns:
            Tuple of (public_key_pem, private_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # Store private key
        self._signing_keys[key_id] = private_key
        
        # Get public key for verification
        public_key = private_key.public_key()
        self._verification_keys[key_id] = public_key
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem, private_pem
    
    def import_verification_key(self, key_id: str, public_key_pem: bytes):
        """Import a public key for signature verification"""
        public_key = serialization.load_pem_public_key(public_key_pem, backend=self.backend)
        if isinstance(public_key, rsa.RSAPublicKey):
            self._verification_keys[key_id] = public_key
        else:
            raise ValueError("Only RSA public keys are supported for verification")
    
    def create_message(self, 
                      payload: bytes,
                      sender_id: str,
                      recipient_id: str,
                      session_id: str,
                      session_key: bytes,
                      algorithm: EncryptionAlgorithm,
                      message_type: MessageType = MessageType.TEXT,
                      extra_data: Optional[Dict[str, Any]] = None,
                      sign_message: bool = True) -> SecureMessageEnvelope:
        """
        Create a secure message
        
        Args:
            payload: Message payload to encrypt
            sender_id: Sender identifier
            recipient_id: Recipient identifier
            session_id: Session identifier
            session_key: Session encryption key
            algorithm: Encryption algorithm to use
            message_type: Type of message
            extra_data: Additional metadata
            sign_message: Whether to digitally sign the message
            
        Returns:
            SecureMessageEnvelope containing encrypted message
        """
        import secrets
        
        # Generate message ID and get sequence number
        message_id = secrets.token_hex(16)
        sequence_number = self._get_next_sequence_number(session_id)
        
        # Create metadata
        metadata = MessageMetadata(
            message_id=message_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            message_type=message_type,
            timestamp=time.time(),
            session_id=session_id,
            algorithm=algorithm,
            sequence_number=sequence_number,
            extra_data=extra_data or {}
        )
        
        # Calculate payload hash for integrity
        payload_hash = hashlib.sha256(payload).hexdigest()
        metadata.message_hash = payload_hash
        
        # Create a simplified metadata for associated data (exclude signature field)
        associated_metadata = {
            'message_id': metadata.message_id,
            'sender_id': metadata.sender_id,
            'recipient_id': metadata.recipient_id,
            'message_type': metadata.message_type.value,
            'timestamp': metadata.timestamp,
            'session_id': metadata.session_id,
            'algorithm': metadata.algorithm.value,
            'sequence_number': metadata.sequence_number,
            'message_hash': metadata.message_hash
        }
        metadata_json = json.dumps(associated_metadata, sort_keys=True)
        associated_data = metadata_json.encode('utf-8')
        
        # Encrypt the payload
        encryption_result = self.encryption_engine.encrypt(
            payload, session_key, algorithm, associated_data
        )
        
        # Create message envelope
        envelope = SecureMessageEnvelope(
            metadata=metadata,
            encrypted_payload=encryption_result.ciphertext,
            nonce=encryption_result.nonce
        )
        
        # Sign the message if requested
        if sign_message and sender_id in self._signing_keys:
            signature = self._sign_message(envelope, sender_id)
            envelope.signature = signature
            metadata.signature = signature
        
        return envelope
    
    def decrypt_message(self, 
                       envelope: SecureMessageEnvelope,
                       session_key: bytes,
                       verify_signature: bool = True) -> Tuple[bytes, MessageMetadata]:
        """
        Decrypt and verify a secure message
        
        Args:
            envelope: Secure message envelope
            session_key: Session decryption key
            verify_signature: Whether to verify digital signature
            
        Returns:
            Tuple of (decrypted_payload, metadata)
        """
        metadata = envelope.metadata
        
        # Verify signature if present and requested
        if verify_signature and envelope.signature and metadata.sender_id in self._verification_keys:
            if not self._verify_signature(envelope, metadata.sender_id):
                raise ValueError("Message signature verification failed")
        
        # Prepare associated data (same format as during encryption)
        associated_metadata = {
            'message_id': metadata.message_id,
            'sender_id': metadata.sender_id,
            'recipient_id': metadata.recipient_id,
            'message_type': metadata.message_type.value,
            'timestamp': metadata.timestamp,
            'session_id': metadata.session_id,
            'algorithm': metadata.algorithm.value,
            'sequence_number': metadata.sequence_number,
            'message_hash': metadata.message_hash
        }
        metadata_json = json.dumps(associated_metadata, sort_keys=True)
        associated_data = metadata_json.encode('utf-8')
        
        # Create encryption result for decryption
        encryption_result = EncryptionResult(
            ciphertext=envelope.encrypted_payload,
            nonce=envelope.nonce,
            algorithm=metadata.algorithm
        )
        
        # Decrypt payload
        try:
            decrypted_payload = self.encryption_engine.decrypt(
                encryption_result, session_key, associated_data
            )
        except Exception as e:
            raise ValueError(f"Failed to decrypt message: {e}")
        
        # Verify payload integrity
        payload_hash = hashlib.sha256(decrypted_payload).hexdigest()
        if metadata.message_hash and payload_hash != metadata.message_hash:
            raise ValueError("Message integrity verification failed")
        
        # Verify sequence number (basic replay protection)
        self._verify_sequence_number(metadata.session_id, metadata.sequence_number)
        
        return decrypted_payload, metadata
    
    def _sign_message(self, envelope: SecureMessageEnvelope, sender_id: str) -> bytes:
        """Create digital signature for message"""
        if sender_id not in self._signing_keys:
            raise ValueError(f"No signing key found for {sender_id}")
        
        private_key = self._signing_keys[sender_id]
        
        # Create message digest for signing
        message_digest = self._create_message_digest(envelope)
        
        # Sign the digest
        signature = private_key.sign(
            message_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def _verify_signature(self, envelope: SecureMessageEnvelope, sender_id: str) -> bool:
        """Verify digital signature"""
        if sender_id not in self._verification_keys:
            return False
        
        if not envelope.signature:
            return False
        
        public_key = self._verification_keys[sender_id]
        
        # Create message digest
        message_digest = self._create_message_digest(envelope)
        
        try:
            # Verify signature
            public_key.verify(
                envelope.signature,
                message_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def _create_message_digest(self, envelope: SecureMessageEnvelope) -> bytes:
        """Create digest for message signing/verification"""
        # Combine metadata and encrypted payload for signature
        metadata_dict = asdict(envelope.metadata)
        # Remove signature from metadata for digest calculation
        metadata_dict.pop('signature', None)
        
        metadata_json = json.dumps(metadata_dict, sort_keys=True, default=str)
        
        digest_data = metadata_json.encode('utf-8') + envelope.encrypted_payload
        if envelope.nonce:
            digest_data += envelope.nonce
        
        return hashlib.sha256(digest_data).digest()
    
    def _get_next_sequence_number(self, session_id: str) -> int:
        """Get next sequence number for session"""
        if session_id not in self._sequence_numbers:
            self._sequence_numbers[session_id] = 0
        
        self._sequence_numbers[session_id] += 1
        return self._sequence_numbers[session_id]
    
    def _verify_sequence_number(self, session_id: str, sequence_number: int):
        """Verify sequence number for basic replay protection"""
        if session_id not in self._sequence_numbers:
            self._sequence_numbers[session_id] = sequence_number
            return
        
        if sequence_number <= self._sequence_numbers[session_id]:
            raise ValueError(f"Invalid sequence number: {sequence_number} <= {self._sequence_numbers[session_id]}")
        
        self._sequence_numbers[session_id] = sequence_number
    
    def serialize_envelope(self, envelope: SecureMessageEnvelope) -> bytes:
        """Serialize message envelope to bytes for transmission"""
        metadata_dict = asdict(envelope.metadata)
        
        # Convert enums to strings for JSON serialization
        if 'message_type' in metadata_dict and hasattr(metadata_dict['message_type'], 'value'):
            metadata_dict['message_type'] = metadata_dict['message_type'].value
        if 'algorithm' in metadata_dict and hasattr(metadata_dict['algorithm'], 'value'):
            metadata_dict['algorithm'] = metadata_dict['algorithm'].value
        
        envelope_dict = {
            'metadata': metadata_dict,
            'encrypted_payload': envelope.encrypted_payload.hex(),
            'nonce': envelope.nonce.hex() if envelope.nonce else None,
            'signature': envelope.signature.hex() if envelope.signature else None
        }
        
        return json.dumps(envelope_dict, default=str).encode('utf-8')
    
    def deserialize_envelope(self, data: bytes) -> SecureMessageEnvelope:
        """Deserialize message envelope from bytes"""
        try:
            envelope_dict = json.loads(data.decode('utf-8'))
            
            # Reconstruct metadata
            metadata_dict = envelope_dict['metadata']
            
            # Handle enum deserialization
            if isinstance(metadata_dict['message_type'], str):
                metadata_dict['message_type'] = MessageType(metadata_dict['message_type'])
            if isinstance(metadata_dict['algorithm'], str):
                metadata_dict['algorithm'] = EncryptionAlgorithm(metadata_dict['algorithm'])
            
            metadata = MessageMetadata(**metadata_dict)
            
            # Reconstruct envelope
            envelope = SecureMessageEnvelope(
                metadata=metadata,
                encrypted_payload=bytes.fromhex(envelope_dict['encrypted_payload']),
                nonce=bytes.fromhex(envelope_dict['nonce']) if envelope_dict['nonce'] else None,
                signature=bytes.fromhex(envelope_dict['signature']) if envelope_dict['signature'] else None
            )
            
            return envelope
            
        except Exception as e:
            raise ValueError(f"Failed to deserialize message envelope: {e}")
    
    def reset_sequence_number(self, session_id: str):
        """Reset sequence number for session (use when session key rotates)"""
        self._sequence_numbers[session_id] = 0
    
    def cleanup_signing_key(self, key_id: str):
        """Remove signing key from memory"""
        self._signing_keys.pop(key_id, None)
    
    def cleanup_verification_key(self, key_id: str):
        """Remove verification key from memory"""
        self._verification_keys.pop(key_id, None)
    
    def cleanup_all_keys(self):
        """Remove all keys from memory"""
        self._signing_keys.clear()
        self._verification_keys.clear()
    
    def get_message_info(self, envelope: SecureMessageEnvelope) -> Dict[str, Any]:
        """Get information about a message"""
        return {
            'message_id': envelope.metadata.message_id,
            'sender': envelope.metadata.sender_id,
            'recipient': envelope.metadata.recipient_id,
            'type': envelope.metadata.message_type.value,
            'timestamp': envelope.metadata.timestamp,
            'session_id': envelope.metadata.session_id,
            'algorithm': envelope.metadata.algorithm.value,
            'sequence_number': envelope.metadata.sequence_number,
            'has_signature': envelope.signature is not None,
            'payload_size': len(envelope.encrypted_payload)
        }