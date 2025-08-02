"""
FastAPI Server for Multi-Algorithm Secure Messaging
Provides REST API and WebSocket endpoints for secure messaging
"""

import os
import asyncio
import json
import base64
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import uvicorn

from crypto_engine import CryptoEngine, AlgorithmType, EncryptedMessage
from session_manager import SessionManager
from auth_system import AuthSystem

# Security
security = HTTPBearer()

# Pydantic models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: str = Field(..., regex=r"^[^@]+@[^@]+\.[^@]+$")
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    username: str
    password: str

class SessionCreate(BaseModel):
    algorithm: Optional[str] = None

class SessionJoin(BaseModel):
    session_id: str
    public_key: str

class MessageSend(BaseModel):
    message: str

class TokenRefresh(BaseModel):
    refresh_token: str

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

# Global instances
crypto_engine = CryptoEngine()
session_manager = SessionManager(crypto_engine)
auth_system = AuthSystem()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, List[str]] = {}  # user_id -> connection_ids
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        connection_id = f"{user_id}_{id(websocket)}"
        self.active_connections[connection_id] = websocket
        
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(connection_id)
    
    def disconnect(self, connection_id: str):
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        
        # Remove from user connections
        for user_id, connections in self.user_connections.items():
            if connection_id in connections:
                connections.remove(connection_id)
                if not connections:
                    del self.user_connections[user_id]
    
    async def send_personal_message(self, message: str, connection_id: str):
        if connection_id in self.active_connections:
            await self.active_connections[connection_id].send_text(message)
    
    async def broadcast_to_session(self, message: str, session_id: str, exclude_user: str = None):
        # Get all users in the session
        session_info = session_manager.get_session_info(session_id)
        if not session_info:
            return
        
        for participant in session_info['participants']:
            user_id = participant['user_id']
            if exclude_user and user_id == exclude_user:
                continue
            
            # Send to all connections of this user
            if user_id in self.user_connections:
                for connection_id in self.user_connections[user_id]:
                    await self.send_personal_message(message, connection_id)

manager = ConnectionManager()

# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = auth_system.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

# Startup and shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await session_manager.start_cleanup_task()
    print("Secure messaging server started")
    yield
    # Shutdown
    print("Secure messaging server shutting down")

# Create FastAPI app
app = FastAPI(
    title="Secure Multi-Algorithm Messaging API",
    description="A secure messaging system with support for multiple encryption algorithms",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication endpoints
@app.post("/auth/register", response_model=Dict)
async def register_user(user_data: UserRegister):
    """Register a new user"""
    # Validate password strength
    password_validation = auth_system.validate_password_strength(user_data.password)
    if not password_validation["is_valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password validation failed", "errors": password_validation["errors"]}
        )
    
    user_id = auth_system.register_user(
        user_data.username, 
        user_data.email, 
        user_data.password
    )
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )
    
    return {"message": "User registered successfully", "user_id": user_id}

@app.post("/auth/login", response_model=Dict)
async def login_user(user_data: UserLogin):
    """Login user and return tokens"""
    result = auth_system.login_user(user_data.username, user_data.password)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    return result

@app.post("/auth/refresh", response_model=Dict)
async def refresh_token(token_data: TokenRefresh):
    """Refresh access token"""
    new_token = auth_system.refresh_access_token(token_data.refresh_token)
    
    if not new_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    return {"access_token": new_token, "token_type": "bearer"}

@app.post("/auth/logout")
async def logout_user(current_user: Dict = Depends(get_current_user)):
    """Logout user"""
    # In a real implementation, you'd need to pass the actual tokens
    # For now, we'll just return success
    return {"message": "Logged out successfully"}

@app.post("/auth/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: Dict = Depends(get_current_user)
):
    """Change user password"""
    success = auth_system.change_password(
        current_user["sub"],
        password_data.old_password,
        password_data.new_password
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid old password or new password too weak"
        )
    
    return {"message": "Password changed successfully"}

# Session endpoints
@app.post("/session/create", response_model=Dict)
async def create_session(
    session_data: SessionCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Create a new secure messaging session"""
    user = auth_system.get_user_by_id(current_user["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    algorithm = None
    if session_data.algorithm:
        try:
            algorithm = AlgorithmType(session_data.algorithm)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported algorithm: {session_data.algorithm}"
            )
    
    session_id, dh_params = session_manager.create_session(
        current_user["sub"], user.username, algorithm
    )
    
    return {
        "session_id": session_id,
        "dh_parameters": base64.b64encode(dh_params).decode('utf-8'),
        "algorithm": session_manager.sessions[session_id].algorithm.value
    }

@app.post("/session/join", response_model=Dict)
async def join_session(
    join_data: SessionJoin,
    current_user: Dict = Depends(get_current_user)
):
    """Join an existing session"""
    user = auth_system.get_user_by_id(current_user["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        public_key = base64.b64decode(join_data.public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid public key format")
    
    success = session_manager.join_session(
        join_data.session_id,
        current_user["sub"],
        user.username,
        public_key
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to join session")
    
    return {"message": "Successfully joined session"}

@app.post("/session/{session_id}/establish")
async def establish_session_keys(
    session_id: str,
    participant_keys: Dict[str, str],
    current_user: Dict = Depends(get_current_user)
):
    """Establish session keys using Diffie-Hellman"""
    session = session_manager.sessions.get(session_id)
    if not session or session.creator_id != current_user["sub"]:
        raise HTTPException(status_code=404, detail="Session not found or access denied")
    
    # Decode public keys
    decoded_keys = {}
    for user_id, key_b64 in participant_keys.items():
        try:
            decoded_keys[user_id] = base64.b64decode(key_b64)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid public key for user {user_id}")
    
    # Generate creator's key pair
    dh_params = session_manager.crypto_engine.generate_dh_parameters()
    creator_private_key, creator_public_key = session_manager.crypto_engine.generate_dh_key_pair(dh_params)
    
    # Establish session keys
    success = session_manager.establish_session_keys(
        session_id, creator_private_key, decoded_keys
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to establish session keys")
    
    # Return creator's public key
    from cryptography.hazmat.primitives import serialization
    creator_public_key_bytes = creator_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        "message": "Session keys established",
        "creator_public_key": base64.b64encode(creator_public_key_bytes).decode('utf-8')
    }

@app.get("/session/{session_id}/info")
async def get_session_info(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get session information"""
    session_info = session_manager.get_session_info(session_id)
    
    if not session_info:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Check if user is participant
    user_participant = None
    for participant in session_info['participants']:
        if participant['user_id'] == current_user["sub"]:
            user_participant = participant
            break
    
    if not user_participant:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return session_info

@app.get("/sessions")
async def get_user_sessions(current_user: Dict = Depends(get_current_user)):
    """Get all sessions for the current user"""
    sessions = session_manager.get_user_sessions(current_user["sub"])
    return {"sessions": sessions}

@app.post("/session/{session_id}/send")
async def send_message(
    session_id: str,
    message_data: MessageSend,
    current_user: Dict = Depends(get_current_user)
):
    """Send an encrypted message"""
    encrypted_message = session_manager.send_message(
        session_id, current_user["sub"], message_data.message
    )
    
    if not encrypted_message:
        raise HTTPException(status_code=400, detail="Failed to send message")
    
    # Serialize encrypted message
    serialized_message = session_manager.crypto_engine.serialize_encrypted_message(encrypted_message)
    
    # Broadcast to all participants via WebSocket
    await manager.broadcast_to_session(
        json.dumps({
            "type": "message",
            "session_id": session_id,
            "sender_id": current_user["sub"],
            "sender_username": current_user["username"],
            "encrypted_message": serialized_message,
            "timestamp": encrypted_message.timestamp
        }),
        session_id,
        exclude_user=current_user["sub"]
    )
    
    return {
        "message": "Message sent successfully",
        "message_id": encrypted_message.message_id,
        "encrypted_message": serialized_message
    }

@app.post("/session/{session_id}/receive")
async def receive_message(
    session_id: str,
    encrypted_message_data: str,
    current_user: Dict = Depends(get_current_user)
):
    """Receive and decrypt a message"""
    try:
        encrypted_message = session_manager.crypto_engine.deserialize_encrypted_message(
            encrypted_message_data
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid encrypted message format")
    
    plaintext = session_manager.receive_message(session_id, encrypted_message)
    
    if not plaintext:
        raise HTTPException(status_code=400, detail="Failed to decrypt message")
    
    return {"plaintext": plaintext}

@app.post("/session/{session_id}/rotate-keys")
async def rotate_session_keys(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Rotate session keys"""
    success = session_manager.rotate_session_keys(session_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to rotate session keys")
    
    return {"message": "Session keys rotated successfully"}

@app.delete("/session/{session_id}/leave")
async def leave_session(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Leave a session"""
    success = session_manager.leave_session(session_id, current_user["sub"])
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to leave session")
    
    return {"message": "Successfully left session"}

# WebSocket endpoint
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    """WebSocket endpoint for real-time messaging"""
    await manager.connect(websocket, user_id)
    connection_id = f"{user_id}_{id(websocket)}"
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Handle different message types
            if message_data.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            
            elif message_data.get("type") == "message":
                # Handle incoming message
                session_id = message_data.get("session_id")
                encrypted_message_data = message_data.get("encrypted_message")
                
                if session_id and encrypted_message_data:
                    # Broadcast to other participants
                    await manager.broadcast_to_session(
                        json.dumps(message_data),
                        session_id,
                        exclude_user=user_id
                    )
    
    except WebSocketDisconnect:
        manager.disconnect(connection_id)

# Algorithm information
@app.get("/algorithms")
async def get_supported_algorithms():
    """Get information about supported encryption algorithms"""
    algorithms = {}
    for algorithm in AlgorithmType:
        algorithms[algorithm.value] = crypto_engine.get_algorithm_info(algorithm)
    
    return {"algorithms": algorithms}

# Statistics endpoints
@app.get("/stats/sessions")
async def get_session_statistics():
    """Get session statistics"""
    return session_manager.get_session_statistics()

@app.get("/stats/users")
async def get_user_statistics():
    """Get user statistics"""
    return auth_system.get_user_statistics()

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_sessions": session_manager.get_active_sessions_count(),
        "total_users": len(auth_system.users)
    }

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )