"""
Session Management System
========================

Manages encryption sessions with automatic key rotation, forward secrecy,
and session lifecycle management.
"""

import time
import secrets
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from .encryption import EncryptionEngine, EncryptionAlgorithm
from .key_exchange import KeyExchange, KeyExchangeResult


class SessionState(Enum):
    """Session states"""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    ROTATING = "rotating"
    EXPIRED = "expired"
    TERMINATED = "terminated"


@dataclass
class SessionInfo:
    """Information about an active session"""
    session_id: str
    peer_id: str
    algorithm: EncryptionAlgorithm
    state: SessionState
    created_at: float
    last_used: float
    key_rotation_interval: float
    max_messages: int
    message_count: int = 0
    current_key: Optional[bytes] = None
    next_key: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """
    Manages encryption sessions with automatic key rotation and forward secrecy.
    
    Features:
    - Automatic key rotation based on time or message count
    - Perfect forward secrecy through ECDH key exchange
    - Session lifecycle management
    - Multiple concurrent sessions
    """
    
    def __init__(self, 
                 default_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
                 default_rotation_interval: float = 3600.0,  # 1 hour
                 default_max_messages: int = 1000,
                 session_timeout: float = 86400.0):  # 24 hours
        """
        Initialize session manager
        
        Args:
            default_algorithm: Default encryption algorithm for new sessions
            default_rotation_interval: Default key rotation interval in seconds
            default_max_messages: Default max messages per key
            session_timeout: Session timeout in seconds
        """
        self.default_algorithm = default_algorithm
        self.default_rotation_interval = default_rotation_interval
        self.default_max_messages = default_max_messages
        self.session_timeout = session_timeout
        
        self.encryption_engine = EncryptionEngine()
        self.key_exchange = KeyExchange()
        
        self._sessions: Dict[str, SessionInfo] = {}
        self._peer_sessions: Dict[str, str] = {}  # peer_id -> session_id mapping
    
    def create_session(self, peer_id: str, 
                      algorithm: Optional[EncryptionAlgorithm] = None,
                      rotation_interval: Optional[float] = None,
                      max_messages: Optional[int] = None) -> str:
        """
        Create a new encryption session
        
        Args:
            peer_id: Identifier for the peer
            algorithm: Encryption algorithm to use
            rotation_interval: Key rotation interval in seconds
            max_messages: Maximum messages per key
            
        Returns:
            Session ID
        """
        session_id = secrets.token_hex(16)
        algorithm = algorithm or self.default_algorithm
        rotation_interval = rotation_interval or self.default_rotation_interval
        max_messages = max_messages or self.default_max_messages
        
        # Generate initial key
        initial_key = self.encryption_engine.generate_symmetric_key(algorithm)
        
        session = SessionInfo(
            session_id=session_id,
            peer_id=peer_id,
            algorithm=algorithm,
            state=SessionState.INITIALIZING,
            created_at=time.time(),
            last_used=time.time(),
            key_rotation_interval=rotation_interval,
            max_messages=max_messages,
            current_key=initial_key
        )
        
        self._sessions[session_id] = session
        self._peer_sessions[peer_id] = session_id
        
        return session_id
    
    def initiate_key_exchange(self, session_id: str) -> Tuple[str, bytes]:
        """
        Initiate ECDH key exchange for session establishment
        
        Args:
            session_id: Session to initiate exchange for
            
        Returns:
            Tuple of (key_exchange_id, public_key_bytes)
        """
        if session_id not in self._sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self._sessions[session_id]
        
        # Generate ECDH keypair for this session
        key_exchange_id, public_key = self.key_exchange.generate_keypair()
        
        # Store the exchange ID in session metadata
        session.metadata['key_exchange_id'] = key_exchange_id
        session.state = SessionState.INITIALIZING
        
        return key_exchange_id, public_key
    
    def complete_key_exchange(self, session_id: str, peer_public_key: bytes) -> bool:
        """
        Complete ECDH key exchange and activate session
        
        Args:
            session_id: Session to complete exchange for
            peer_public_key: Peer's public key
            
        Returns:
            True if exchange completed successfully
        """
        if session_id not in self._sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self._sessions[session_id]
        key_exchange_id = session.metadata.get('key_exchange_id')
        
        if not key_exchange_id:
            raise ValueError("No key exchange initiated for this session")
        
        try:
            # Perform key exchange
            exchange_result = self.key_exchange.perform_exchange(
                key_exchange_id, peer_public_key
            )
            
            # Use the shared secret as the session key
            session.current_key = exchange_result.shared_secret
            session.state = SessionState.ACTIVE
            session.last_used = time.time()
            
            # Clean up the ECDH key pair for forward secrecy
            self.key_exchange.cleanup_key(key_exchange_id)
            
            return True
            
        except Exception as e:
            session.state = SessionState.TERMINATED
            raise e
    
    def get_session_key(self, session_id: str) -> bytes:
        """Get current encryption key for session"""
        if session_id not in self._sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self._sessions[session_id]
        
        if session.state != SessionState.ACTIVE:
            raise ValueError(f"Session {session_id} is not active (state: {session.state})")
        
        # Check if key rotation is needed
        self._check_key_rotation(session_id)
        
        session.last_used = time.time()
        return session.current_key
    
    def rotate_session_key(self, session_id: str) -> bool:
        """
        Manually rotate the session key
        
        Args:
            session_id: Session to rotate key for
            
        Returns:
            True if rotation was successful
        """
        if session_id not in self._sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self._sessions[session_id]
        
        if session.state != SessionState.ACTIVE:
            return False
        
        # Generate new key
        new_key = self.encryption_engine.generate_symmetric_key(session.algorithm)
        
        # Update session
        session.current_key = new_key
        session.message_count = 0
        session.last_used = time.time()
        
        return True
    
    def increment_message_count(self, session_id: str):
        """Increment message count for session"""
        if session_id in self._sessions:
            session = self._sessions[session_id]
            session.message_count += 1
            session.last_used = time.time()
    
    def _check_key_rotation(self, session_id: str):
        """Check if key rotation is needed and perform it"""
        session = self._sessions[session_id]
        current_time = time.time()
        
        # Check time-based rotation
        time_since_creation = current_time - session.created_at
        if time_since_creation >= session.key_rotation_interval:
            self.rotate_session_key(session_id)
            return
        
        # Check message count-based rotation
        if session.message_count >= session.max_messages:
            self.rotate_session_key(session_id)
            return
    
    def get_session_info(self, session_id: str) -> SessionInfo:
        """Get session information"""
        if session_id not in self._sessions:
            raise ValueError(f"Session {session_id} not found")
        
        return self._sessions[session_id]
    
    def get_session_by_peer(self, peer_id: str) -> Optional[str]:
        """Get session ID for a peer"""
        return self._peer_sessions.get(peer_id)
    
    def list_sessions(self) -> Dict[str, SessionInfo]:
        """List all sessions"""
        return self._sessions.copy()
    
    def list_active_sessions(self) -> Dict[str, SessionInfo]:
        """List only active sessions"""
        return {
            sid: session for sid, session in self._sessions.items()
            if session.state == SessionState.ACTIVE
        }
    
    def terminate_session(self, session_id: str):
        """Terminate a session and clean up keys"""
        if session_id not in self._sessions:
            return
        
        session = self._sessions[session_id]
        session.state = SessionState.TERMINATED
        session.current_key = None
        session.next_key = None
        
        # Remove from peer mapping
        if session.peer_id in self._peer_sessions:
            del self._peer_sessions[session.peer_id]
        
        # Clean up any associated key exchange keys
        key_exchange_id = session.metadata.get('key_exchange_id')
        if key_exchange_id:
            self.key_exchange.cleanup_key(key_exchange_id)
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self._sessions.items():
            if current_time - session.last_used > self.session_timeout:
                session.state = SessionState.EXPIRED
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.terminate_session(session_id)
            del self._sessions[session_id]
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """Get statistics about all sessions"""
        stats = {
            'total_sessions': len(self._sessions),
            'active_sessions': len([s for s in self._sessions.values() 
                                  if s.state == SessionState.ACTIVE]),
            'expired_sessions': len([s for s in self._sessions.values() 
                                   if s.state == SessionState.EXPIRED]),
            'terminated_sessions': len([s for s in self._sessions.values() 
                                      if s.state == SessionState.TERMINATED]),
            'algorithms_in_use': list(set(s.algorithm for s in self._sessions.values())),
            'average_message_count': sum(s.message_count for s in self._sessions.values()) / max(1, len(self._sessions))
        }
        
        return stats
    
    def cleanup_all_sessions(self):
        """Clean up all sessions and keys"""
        for session_id in list(self._sessions.keys()):
            self.terminate_session(session_id)
        
        self._sessions.clear()
        self._peer_sessions.clear()
        self.encryption_engine.cleanup_keys()
        self.key_exchange.cleanup_all_keys()