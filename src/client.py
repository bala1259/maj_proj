"""
Secure Client Interface
======================

High-level client interface that integrates all components for easy secure messaging.
"""

import time
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass

from .session_manager import SessionManager, SessionState
from .encryption import EncryptionAlgorithm
from .message_protocol import SecureMessage, MessageType, SecureMessageEnvelope
from .key_exchange import KeyExchange


@dataclass
class PeerInfo:
    """Information about a peer"""
    peer_id: str
    public_key: Optional[bytes] = None
    signing_key: Optional[bytes] = None
    last_seen: Optional[float] = None
    session_id: Optional[str] = None


class SecureClient:
    """
    High-level secure messaging client that provides a simple interface
    for encrypted communications with multiple peers.
    """
    
    def __init__(self, 
                 client_id: str,
                 default_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM):
        """
        Initialize secure client
        
        Args:
            client_id: Unique identifier for this client
            default_algorithm: Default encryption algorithm
        """
        self.client_id = client_id
        self.default_algorithm = default_algorithm
        
        # Initialize components
        self.session_manager = SessionManager(default_algorithm=default_algorithm)
        self.secure_message = SecureMessage(self.session_manager.encryption_engine)
        
        # Peer management
        self._peers: Dict[str, PeerInfo] = {}
        
        # Message handlers
        self._message_handlers: Dict[MessageType, Callable] = {}
        
        # Generate signing keypair for this client
        self._setup_identity()
    
    def _setup_identity(self):
        """Set up client identity with signing keys"""
        public_key, private_key = self.secure_message.generate_signing_keypair(self.client_id)
        self.public_signing_key = public_key
        self.private_signing_key = private_key
    
    def add_peer(self, peer_id: str, 
                public_key: Optional[bytes] = None,
                signing_key: Optional[bytes] = None) -> bool:
        """
        Add a peer to the client
        
        Args:
            peer_id: Peer identifier
            public_key: Peer's public key (for key exchange)
            signing_key: Peer's signing public key
            
        Returns:
            True if peer was added successfully
        """
        try:
            peer_info = PeerInfo(
                peer_id=peer_id,
                public_key=public_key,
                signing_key=signing_key,
                last_seen=time.time()
            )
            
            self._peers[peer_id] = peer_info
            
            # Import signing key for verification if provided
            if signing_key:
                self.secure_message.import_verification_key(peer_id, signing_key)
            
            return True
        except Exception:
            return False
    
    def remove_peer(self, peer_id: str) -> bool:
        """Remove a peer and terminate any active session"""
        if peer_id not in self._peers:
            return False
        
        peer_info = self._peers[peer_id]
        
        # Terminate session if active
        if peer_info.session_id:
            self.session_manager.terminate_session(peer_info.session_id)
        
        # Clean up keys
        self.secure_message.cleanup_verification_key(peer_id)
        
        # Remove peer
        del self._peers[peer_id]
        
        return True
    
    def initiate_session(self, peer_id: str, 
                        algorithm: Optional[EncryptionAlgorithm] = None) -> Tuple[str, bytes]:
        """
        Initiate a secure session with a peer
        
        Args:
            peer_id: Peer to initiate session with
            algorithm: Encryption algorithm to use
            
        Returns:
            Tuple of (session_id, our_public_key_for_exchange)
        """
        if peer_id not in self._peers:
            raise ValueError(f"Peer {peer_id} not found")
        
        algorithm = algorithm or self.default_algorithm
        
        # Create session
        session_id = self.session_manager.create_session(peer_id, algorithm)
        
        # Initiate key exchange
        exchange_id, public_key = self.session_manager.initiate_key_exchange(session_id)
        
        # Update peer info
        self._peers[peer_id].session_id = session_id
        
        return session_id, public_key
    
    def complete_session(self, session_id: str, peer_public_key: bytes) -> bool:
        """
        Complete session establishment with peer's public key
        
        Args:
            session_id: Session ID from initiation
            peer_public_key: Peer's public key for ECDH
            
        Returns:
            True if session was established successfully
        """
        try:
            return self.session_manager.complete_key_exchange(session_id, peer_public_key)
        except Exception:
            return False
    
    def send_message(self, peer_id: str, message: str, 
                    message_type: MessageType = MessageType.TEXT,
                    extra_data: Optional[Dict[str, Any]] = None) -> Optional[bytes]:
        """
        Send an encrypted message to a peer
        
        Args:
            peer_id: Peer to send message to
            message: Message content
            message_type: Type of message
            extra_data: Additional metadata
            
        Returns:
            Serialized message envelope for transmission, or None if failed
        """
        if peer_id not in self._peers:
            raise ValueError(f"Peer {peer_id} not found")
        
        peer_info = self._peers[peer_id]
        
        if not peer_info.session_id:
            raise ValueError(f"No active session with peer {peer_id}")
        
        try:
            # Get session key
            session_key = self.session_manager.get_session_key(peer_info.session_id)
            session_info = self.session_manager.get_session_info(peer_info.session_id)
            
            # Create secure message
            payload = message.encode('utf-8')
            envelope = self.secure_message.create_message(
                payload=payload,
                sender_id=self.client_id,
                recipient_id=peer_id,
                session_id=peer_info.session_id,
                session_key=session_key,
                algorithm=session_info.algorithm,
                message_type=message_type,
                extra_data=extra_data
            )
            
            # Increment message count
            self.session_manager.increment_message_count(peer_info.session_id)
            
            # Update peer last seen
            peer_info.last_seen = time.time()
            
            # Serialize for transmission
            return self.secure_message.serialize_envelope(envelope)
            
        except Exception as e:
            print(f"Failed to send message to {peer_id}: {e}")
            return None
    
    def receive_message(self, serialized_envelope: bytes) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """
        Receive and decrypt a message
        
        Args:
            serialized_envelope: Serialized message envelope
            
        Returns:
            Tuple of (sender_id, message_content, message_info) or None if failed
        """
        try:
            # Deserialize envelope
            envelope = self.secure_message.deserialize_envelope(serialized_envelope)
            
            sender_id = envelope.metadata.sender_id
            session_id = envelope.metadata.session_id
            
            # Verify sender is known
            if sender_id not in self._peers:
                print(f"Received message from unknown sender: {sender_id}")
                return None
            
            # Get session key
            session_key = self.session_manager.get_session_key(session_id)
            
            # Decrypt message
            payload, metadata = self.secure_message.decrypt_message(
                envelope, session_key, verify_signature=True
            )
            
            # Update peer last seen
            self._peers[sender_id].last_seen = time.time()
            
            # Get message info
            message_info = self.secure_message.get_message_info(envelope)
            message_info['decrypted_at'] = time.time()
            
            # Decode message content
            message_content = payload.decode('utf-8')
            
            # Call message handler if registered
            if metadata.message_type in self._message_handlers:
                self._message_handlers[metadata.message_type](
                    sender_id, message_content, message_info
                )
            
            return sender_id, message_content, message_info
            
        except Exception as e:
            print(f"Failed to receive message: {e}")
            return None
    
    def register_message_handler(self, message_type: MessageType, 
                                handler: Callable[[str, str, Dict[str, Any]], None]):
        """Register a handler for specific message types"""
        self._message_handlers[message_type] = handler
    
    def get_session_info(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """Get information about session with a peer"""
        if peer_id not in self._peers:
            return None
        
        peer_info = self._peers[peer_id]
        if not peer_info.session_id:
            return None
        
        try:
            session_info = self.session_manager.get_session_info(peer_info.session_id)
            return {
                'session_id': session_info.session_id,
                'peer_id': session_info.peer_id,
                'algorithm': session_info.algorithm.value,
                'state': session_info.state.value,
                'created_at': session_info.created_at,
                'last_used': session_info.last_used,
                'message_count': session_info.message_count,
                'max_messages': session_info.max_messages,
                'rotation_interval': session_info.key_rotation_interval
            }
        except Exception:
            return None
    
    def list_peers(self) -> List[Dict[str, Any]]:
        """List all peers and their status"""
        peers = []
        for peer_id, peer_info in self._peers.items():
            session_info = None
            if peer_info.session_id:
                try:
                    session = self.session_manager.get_session_info(peer_info.session_id)
                    session_info = {
                        'session_id': session.session_id,
                        'state': session.state.value,
                        'algorithm': session.algorithm.value,
                        'message_count': session.message_count
                    }
                except Exception:
                    pass
            
            peers.append({
                'peer_id': peer_id,
                'has_public_key': peer_info.public_key is not None,
                'has_signing_key': peer_info.signing_key is not None,
                'last_seen': peer_info.last_seen,
                'session': session_info
            })
        
        return peers
    
    def rotate_session_key(self, peer_id: str) -> bool:
        """Manually rotate session key with a peer"""
        if peer_id not in self._peers:
            return False
        
        peer_info = self._peers[peer_id]
        if not peer_info.session_id:
            return False
        
        return self.session_manager.rotate_session_key(peer_info.session_id)
    
    def terminate_session(self, peer_id: str) -> bool:
        """Terminate session with a peer"""
        if peer_id not in self._peers:
            return False
        
        peer_info = self._peers[peer_id]
        if not peer_info.session_id:
            return False
        
        self.session_manager.terminate_session(peer_info.session_id)
        peer_info.session_id = None
        
        return True
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        self.session_manager.cleanup_expired_sessions()
        
        # Update peer info for terminated sessions
        for peer_info in self._peers.values():
            if peer_info.session_id:
                try:
                    session = self.session_manager.get_session_info(peer_info.session_id)
                    if session.state in [SessionState.EXPIRED, SessionState.TERMINATED]:
                        peer_info.session_id = None
                except Exception:
                    peer_info.session_id = None
    
    def get_client_statistics(self) -> Dict[str, Any]:
        """Get statistics about the client"""
        session_stats = self.session_manager.get_session_statistics()
        
        return {
            'client_id': self.client_id,
            'total_peers': len(self._peers),
            'peers_with_sessions': len([p for p in self._peers.values() if p.session_id]),
            'default_algorithm': self.default_algorithm.value,
            'session_statistics': session_stats
        }
    
    def export_identity(self) -> Dict[str, str]:
        """Export client identity for sharing"""
        return {
            'client_id': self.client_id,
            'public_signing_key': self.public_signing_key.decode('utf-8')
        }
    
    def cleanup(self):
        """Clean up all resources"""
        # Terminate all sessions
        for peer_info in self._peers.values():
            if peer_info.session_id:
                self.session_manager.terminate_session(peer_info.session_id)
        
        # Clean up all keys and sessions
        self.session_manager.cleanup_all_sessions()
        self.secure_message.cleanup_all_keys()
        
        # Clear peer list
        self._peers.clear()
        self._message_handlers.clear()