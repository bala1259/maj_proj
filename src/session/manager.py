"""
Session Management System
Handles secure messaging sessions with key management and algorithm rotation
"""

import time
import uuid
import json
import base64
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from threading import Lock
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from src.crypto.algorithms import AlgorithmType, MultiAlgorithmCrypto


class SessionStatus(Enum):
    """Session status enumeration"""
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"


@dataclass
class SessionConfig:
    """Session configuration"""
    session_id: str
    algorithm_type: AlgorithmType
    key_rotation_interval: int  # seconds
    session_timeout: int  # seconds
    max_messages_per_key: int
    created_at: float
    last_activity: float


@dataclass
class SessionKey:
    """Session key information"""
    key_id: str
    key: bytes
    algorithm_type: AlgorithmType
    created_at: float
    message_count: int
    max_messages: int


class SessionManager:
    """Manages secure messaging sessions"""
    
    def __init__(self):
        self.sessions: Dict[str, 'Session'] = {}
        self.lock = Lock()
        self.crypto = MultiAlgorithmCrypto()
    
    def create_session(self, user_id: str, algorithm_type: AlgorithmType = AlgorithmType.AES_256_GCM,
                      key_rotation_interval: int = 3600, session_timeout: int = 86400,
                      max_messages_per_key: int = 1000) -> str:
        """Create a new session"""
        session_id = str(uuid.uuid4())
        
        config = SessionConfig(
            session_id=session_id,
            algorithm_type=algorithm_type,
            key_rotation_interval=key_rotation_interval,
            session_timeout=session_timeout,
            max_messages_per_key=max_messages_per_key,
            created_at=time.time(),
            last_activity=time.time()
        )
        
        session = Session(config, self.crypto)
        
        with self.lock:
            self.sessions[session_id] = session
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional['Session']:
        """Get session by ID"""
        with self.lock:
            session = self.sessions.get(session_id)
            if session and session.is_active():
                session.update_activity()
                return session
            elif session and not session.is_active():
                self._cleanup_session(session_id)
            return None
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a session"""
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].terminate()
                return True
            return False
    
    def list_active_sessions(self) -> List[Dict]:
        """List all active sessions"""
        with self.lock:
            active_sessions = []
            expired_sessions = []
            
            for session_id, session in self.sessions.items():
                if session.is_active():
                    active_sessions.append(session.to_dict())
                else:
                    expired_sessions.append(session_id)
            
            # Clean up expired sessions
            for session_id in expired_sessions:
                self._cleanup_session(session_id)
            
            return active_sessions
    
    def _cleanup_session(self, session_id: str):
        """Clean up expired session"""
        if session_id in self.sessions:
            del self.sessions[session_id]


class Session:
    """Individual session instance"""
    
    def __init__(self, config: SessionConfig, crypto: MultiAlgorithmCrypto):
        self.config = config
        self.crypto = crypto
        self.status = SessionStatus.ACTIVE
        self.keys: Dict[str, SessionKey] = {}
        self.current_key_id: Optional[str] = None
        self.message_counter = 0
        
        # Generate initial key
        self._generate_new_key()
    
    def encrypt_message(self, message: bytes, algorithm_type: Optional[AlgorithmType] = None) -> Dict:
        """Encrypt a message"""
        if not self.is_active():
            raise ValueError("Session is not active")
        
        # Check if we need to rotate keys
        self._check_key_rotation()
        
        # Use specified algorithm or session default
        if algorithm_type is None:
            algorithm_type = self.config.algorithm_type
        
        # Get current key
        current_key = self.keys[self.current_key_id]
        
        # Encrypt message
        encrypted_data = self.crypto.encrypt_message(
            message, algorithm_type, current_key.key
        )
        
        # Update message counter
        current_key.message_count += 1
        self.message_counter += 1
        
        return {
            "session_id": self.config.session_id,
            "key_id": self.current_key_id,
            "message_id": self.message_counter,
            "encrypted_data": encrypted_data,
            "timestamp": time.time()
        }
    
    def decrypt_message(self, encrypted_message: Dict) -> bytes:
        """Decrypt a message"""
        if not self.is_active():
            raise ValueError("Session is not active")
        
        key_id = encrypted_message["key_id"]
        if key_id not in self.keys:
            raise ValueError("Invalid key ID")
        
        key = self.keys[key_id]
        encrypted_data = encrypted_message["encrypted_data"]
        
        return self.crypto.decrypt_message(encrypted_data, key.key)
    
    def rotate_algorithm(self, new_algorithm: AlgorithmType) -> bool:
        """Rotate to a new algorithm"""
        if not self.is_active():
            return False
        
        self.config.algorithm_type = new_algorithm
        self._generate_new_key()
        return True
    
    def _generate_new_key(self):
        """Generate a new session key"""
        key_id = str(uuid.uuid4())
        key = get_random_bytes(32)
        
        session_key = SessionKey(
            key_id=key_id,
            key=key,
            algorithm_type=self.config.algorithm_type,
            created_at=time.time(),
            message_count=0,
            max_messages=self.config.max_messages_per_key
        )
        
        self.keys[key_id] = session_key
        self.current_key_id = key_id
    
    def _check_key_rotation(self):
        """Check if key rotation is needed"""
        if not self.current_key_id:
            self._generate_new_key()
            return
        
        current_key = self.keys[self.current_key_id]
        current_time = time.time()
        
        # Check message count limit
        if current_key.message_count >= current_key.max_messages:
            self._generate_new_key()
            return
        
        # Check time-based rotation
        if current_time - current_key.created_at >= self.config.key_rotation_interval:
            self._generate_new_key()
            return
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.config.last_activity = time.time()
    
    def is_active(self) -> bool:
        """Check if session is active"""
        if self.status != SessionStatus.ACTIVE:
            return False
        
        current_time = time.time()
        if current_time - self.config.last_activity > self.config.session_timeout:
            self.status = SessionStatus.EXPIRED
            return False
        
        return True
    
    def terminate(self):
        """Terminate the session"""
        self.status = SessionStatus.TERMINATED
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary"""
        return {
            "session_id": self.config.session_id,
            "status": self.status.value,
            "algorithm_type": self.config.algorithm_type.value,
            "created_at": self.config.created_at,
            "last_activity": self.config.last_activity,
            "message_count": self.message_counter,
            "active_keys": len(self.keys)
        }