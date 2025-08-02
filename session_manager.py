"""
Session Manager for Multi-Algorithm Secure Messaging
Handles session establishment, key exchange, and session lifecycle
"""

import uuid
import time
import json
import asyncio
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from crypto_engine import CryptoEngine, SessionKeys, AlgorithmType, EncryptedMessage


class SessionState(Enum):
    """Session states"""
    INITIALIZING = "initializing"
    KEY_EXCHANGE = "key_exchange"
    ESTABLISHED = "established"
    EXPIRED = "expired"
    TERMINATED = "terminated"


@dataclass
class SessionParticipant:
    """Session participant information"""
    user_id: str
    username: str
    public_key: bytes
    joined_at: float
    last_seen: float
    is_online: bool = True


@dataclass
class Session:
    """Session information"""
    session_id: str
    creator_id: str
    participants: Dict[str, SessionParticipant]
    state: SessionState
    algorithm: AlgorithmType
    created_at: float
    expires_at: float
    dh_parameters: Optional[bytes] = None
    session_keys: Optional[SessionKeys] = None
    message_count: int = 0
    last_activity: float = 0.0


class SessionManager:
    """Manages secure messaging sessions"""
    
    def __init__(self, crypto_engine: CryptoEngine):
        self.crypto_engine = crypto_engine
        self.sessions: Dict[str, Session] = {}
        self.user_sessions: Dict[str, List[str]] = {}  # user_id -> session_ids
        self.session_cleanup_interval = 3600  # 1 hour
        self.max_session_age = 24 * 3600  # 24 hours
        
    async def start_cleanup_task(self):
        """Start background task for session cleanup"""
        asyncio.create_task(self._cleanup_expired_sessions())
    
    async def _cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        while True:
            try:
                current_time = time.time()
                expired_sessions = []
                
                for session_id, session in self.sessions.items():
                    if current_time > session.expires_at:
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    await self.terminate_session(session_id)
                
                await asyncio.sleep(self.session_cleanup_interval)
            except Exception as e:
                print(f"Error in session cleanup: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    def create_session(self, creator_id: str, creator_username: str, 
                      algorithm: AlgorithmType = None) -> Tuple[str, bytes]:
        """Create a new session and return session ID and DH parameters"""
        session_id = str(uuid.uuid4())
        
        if algorithm is None:
            algorithm = self.crypto_engine.preferred_algorithm
        
        # Generate DH parameters
        dh_params = self.crypto_engine.generate_dh_parameters()
        dh_params_bytes = dh_params.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        
        # Create session
        session = Session(
            session_id=session_id,
            creator_id=creator_id,
            participants={},
            state=SessionState.INITIALIZING,
            algorithm=algorithm,
            created_at=time.time(),
            expires_at=time.time() + self.max_session_age,
            dh_parameters=dh_params_bytes
        )
        
        # Add creator as first participant
        creator = SessionParticipant(
            user_id=creator_id,
            username=creator_username,
            public_key=b'',  # Will be set during key exchange
            joined_at=time.time(),
            last_seen=time.time()
        )
        session.participants[creator_id] = creator
        
        # Store session
        self.sessions[session_id] = session
        
        # Update user sessions mapping
        if creator_id not in self.user_sessions:
            self.user_sessions[creator_id] = []
        self.user_sessions[creator_id].append(session_id)
        
        return session_id, dh_params_bytes
    
    def join_session(self, session_id: str, user_id: str, username: str, 
                    public_key: bytes) -> bool:
        """Join an existing session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        if session.state == SessionState.TERMINATED:
            return False
        
        # Add participant
        participant = SessionParticipant(
            user_id=user_id,
            username=username,
            public_key=public_key,
            joined_at=time.time(),
            last_seen=time.time()
        )
        session.participants[user_id] = participant
        
        # Update user sessions mapping
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        if session_id not in self.user_sessions[user_id]:
            self.user_sessions[user_id].append(session_id)
        
        session.last_activity = time.time()
        return True
    
    def establish_session_keys(self, session_id: str, creator_private_key: dh.DHPrivateKey,
                             participant_public_keys: Dict[str, bytes]) -> bool:
        """Establish session keys using Diffie-Hellman key exchange"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        if session.state != SessionState.INITIALIZING:
            return False
        
        try:
            # Load DH parameters
            dh_params = serialization.load_pem_parameters(session.dh_parameters)
            
            # Calculate shared secret with all participants
            shared_secrets = []
            for user_id, public_key_bytes in participant_public_keys.items():
                if user_id in session.participants:
                    # Deserialize public key
                    peer_public_key = serialization.load_pem_public_key(public_key_bytes)
                    
                    # Derive shared secret
                    shared_secret = self.crypto_engine.derive_shared_secret(
                        creator_private_key, peer_public_key
                    )
                    shared_secrets.append(shared_secret)
            
            # Combine shared secrets using XOR
            if shared_secrets:
                combined_secret = shared_secrets[0]
                for secret in shared_secrets[1:]:
                    combined_secret = bytes(a ^ b for a, b in zip(combined_secret, secret))
                
                # Derive session keys
                session.session_keys = self.crypto_engine.derive_session_keys(
                    combined_secret, session_id, session.algorithm
                )
                
                session.state = SessionState.ESTABLISHED
                session.last_activity = time.time()
                return True
            
        except Exception as e:
            print(f"Error establishing session keys: {e}")
            return False
        
        return False
    
    def get_session_keys(self, session_id: str) -> Optional[SessionKeys]:
        """Get session keys for a session"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        if session.state != SessionState.ESTABLISHED:
            return None
        
        # Check if keys are expired
        if time.time() > session.session_keys.expires_at:
            session.state = SessionState.EXPIRED
            return None
        
        return session.session_keys
    
    def rotate_session_keys(self, session_id: str) -> bool:
        """Rotate session keys for enhanced security"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        if session.state != SessionState.ESTABLISHED or session.session_keys is None:
            return False
        
        try:
            # Rotate keys
            session.session_keys = self.crypto_engine.rotate_session_keys(
                session.session_keys, session_id
            )
            session.last_activity = time.time()
            return True
        except Exception as e:
            print(f"Error rotating session keys: {e}")
            return False
    
    def send_message(self, session_id: str, sender_id: str, message: str) -> Optional[EncryptedMessage]:
        """Send an encrypted message in a session"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        if session.state != SessionState.ESTABLISHED or session.session_keys is None:
            return None
        
        if sender_id not in session.participants:
            return None
        
        try:
            # Generate message ID
            message_id = str(uuid.uuid4())
            
            # Encrypt message
            encrypted_message = self.crypto_engine.encrypt_message(
                message, session.session_keys, message_id
            )
            
            # Update session
            session.message_count += 1
            session.last_activity = time.time()
            session.participants[sender_id].last_seen = time.time()
            
            return encrypted_message
            
        except Exception as e:
            print(f"Error sending message: {e}")
            return None
    
    def receive_message(self, session_id: str, encrypted_message: EncryptedMessage) -> Optional[str]:
        """Receive and decrypt a message in a session"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        if session.state != SessionState.ESTABLISHED or session.session_keys is None:
            return None
        
        try:
            # Decrypt message
            plaintext = self.crypto_engine.decrypt_message(encrypted_message, session.session_keys)
            
            # Update session activity
            session.last_activity = time.time()
            
            return plaintext
            
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """Get session information"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        return {
            'session_id': session.session_id,
            'creator_id': session.creator_id,
            'state': session.state.value,
            'algorithm': session.algorithm.value,
            'created_at': session.created_at,
            'expires_at': session.expires_at,
            'message_count': session.message_count,
            'last_activity': session.last_activity,
            'participants': [
                {
                    'user_id': p.user_id,
                    'username': p.username,
                    'joined_at': p.joined_at,
                    'last_seen': p.last_seen,
                    'is_online': p.is_online
                }
                for p in session.participants.values()
            ]
        }
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get all sessions for a user"""
        if user_id not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in self.user_sessions[user_id]:
            session_info = self.get_session_info(session_id)
            if session_info:
                sessions.append(session_info)
        
        return sessions
    
    def update_participant_status(self, session_id: str, user_id: str, is_online: bool):
        """Update participant online status"""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        
        if user_id in session.participants:
            session.participants[user_id].is_online = is_online
            session.participants[user_id].last_seen = time.time()
    
    def leave_session(self, session_id: str, user_id: str) -> bool:
        """Leave a session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        if user_id in session.participants:
            del session.participants[user_id]
            
            # Remove from user sessions mapping
            if user_id in self.user_sessions and session_id in self.user_sessions[user_id]:
                self.user_sessions[user_id].remove(session_id)
            
            # If no participants left, terminate session
            if not session.participants:
                self.terminate_session(session_id)
            
            return True
        
        return False
    
    async def terminate_session(self, session_id: str) -> bool:
        """Terminate a session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session.state = SessionState.TERMINATED
        
        # Remove from user sessions mapping
        for user_id in session.participants:
            if user_id in self.user_sessions and session_id in self.user_sessions[user_id]:
                self.user_sessions[user_id].remove(session_id)
        
        # Clear session keys
        session.session_keys = None
        
        # Remove session
        del self.sessions[session_id]
        
        return True
    
    def get_active_sessions_count(self) -> int:
        """Get count of active sessions"""
        return len([s for s in self.sessions.values() if s.state == SessionState.ESTABLISHED])
    
    def get_total_sessions_count(self) -> int:
        """Get total count of sessions"""
        return len(self.sessions)
    
    def get_session_statistics(self) -> Dict:
        """Get session statistics"""
        stats = {
            'total_sessions': len(self.sessions),
            'active_sessions': 0,
            'expired_sessions': 0,
            'terminated_sessions': 0,
            'total_participants': 0,
            'algorithm_usage': {}
        }
        
        for session in self.sessions.values():
            if session.state == SessionState.ESTABLISHED:
                stats['active_sessions'] += 1
            elif session.state == SessionState.EXPIRED:
                stats['expired_sessions'] += 1
            elif session.state == SessionState.TERMINATED:
                stats['terminated_sessions'] += 1
            
            stats['total_participants'] += len(session.participants)
            
            algorithm = session.algorithm.value
            if algorithm not in stats['algorithm_usage']:
                stats['algorithm_usage'][algorithm] = 0
            stats['algorithm_usage'][algorithm] += 1
        
        return stats