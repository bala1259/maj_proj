"""
Secure Messaging Server
Handles WebSocket connections and message routing with encryption
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional
from datetime import datetime
import websockets
from websockets.server import WebSocketServerProtocol
from pydantic import BaseModel

from src.session.manager import SessionManager
from src.crypto.algorithms import AlgorithmType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MessageRequest(BaseModel):
    """Message request model"""
    session_id: str
    message: str
    algorithm_type: Optional[str] = None
    recipient_id: Optional[str] = None


class MessageResponse(BaseModel):
    """Message response model"""
    success: bool
    message_id: Optional[str] = None
    encrypted_data: Optional[Dict] = None
    error: Optional[str] = None
    timestamp: float


class SecureMessagingServer:
    """Secure messaging server with WebSocket support"""
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.session_manager = SessionManager()
        self.connections: Dict[str, WebSocketServerProtocol] = {}
        self.user_sessions: Dict[str, str] = {}  # user_id -> session_id
        
    async def start(self):
        """Start the WebSocket server"""
        logger.info(f"Starting secure messaging server on {self.host}:{self.port}")
        
        async with websockets.serve(self.handle_connection, self.host, self.port):
            await asyncio.Future()  # run forever
    
    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle WebSocket connection"""
        client_id = None
        
        try:
            # Wait for client identification
            auth_message = await websocket.recv()
            auth_data = json.loads(auth_message)
            
            if auth_data.get("type") == "auth":
                client_id = auth_data.get("user_id")
                if not client_id:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Invalid user ID"
                    }))
                    return
                
                # Store connection
                self.connections[client_id] = websocket
                
                # Create or get session
                session_id = self.user_sessions.get(client_id)
                if not session_id:
                    algorithm_type = AlgorithmType(auth_data.get("algorithm", "aes_256_gcm"))
                    session_id = self.session_manager.create_session(
                        client_id, algorithm_type
                    )
                    self.user_sessions[client_id] = session_id
                
                await websocket.send(json.dumps({
                    "type": "auth_success",
                    "session_id": session_id,
                    "message": "Authentication successful"
                }))
                
                logger.info(f"Client {client_id} connected with session {session_id}")
                
                # Handle messages
                async for message in websocket:
                    await self.handle_message(client_id, message)
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling connection for {client_id}: {e}")
            if websocket.open:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Internal server error"
                }))
        finally:
            if client_id:
                self.connections.pop(client_id, None)
    
    async def handle_message(self, client_id: str, message: str):
        """Handle incoming message"""
        try:
            data = json.loads(message)
            message_type = data.get("type")
            
            if message_type == "send_message":
                await self.handle_send_message(client_id, data)
            elif message_type == "receive_message":
                await self.handle_receive_message(client_id, data)
            elif message_type == "rotate_algorithm":
                await self.handle_rotate_algorithm(client_id, data)
            elif message_type == "get_session_info":
                await self.handle_get_session_info(client_id)
            else:
                await self.send_error(client_id, f"Unknown message type: {message_type}")
                
        except json.JSONDecodeError:
            await self.send_error(client_id, "Invalid JSON format")
        except Exception as e:
            logger.error(f"Error handling message from {client_id}: {e}")
            await self.send_error(client_id, "Internal server error")
    
    async def handle_send_message(self, client_id: str, data: Dict):
        """Handle send message request"""
        try:
            session_id = self.user_sessions.get(client_id)
            if not session_id:
                await self.send_error(client_id, "No active session")
                return
            
            session = self.session_manager.get_session(session_id)
            if not session:
                await self.send_error(client_id, "Session expired")
                return
            
            message_text = data.get("message", "")
            if not message_text:
                await self.send_error(client_id, "Empty message")
                return
            
            # Encrypt message
            algorithm_type = None
            if data.get("algorithm_type"):
                algorithm_type = AlgorithmType(data["algorithm_type"])
            
            encrypted_message = session.encrypt_message(
                message_text.encode('utf-8'), algorithm_type
            )
            
            # Send encrypted message back to sender
            await self.send_message(client_id, {
                "type": "message_sent",
                "message_id": encrypted_message["message_id"],
                "encrypted_data": encrypted_message["encrypted_data"],
                "timestamp": encrypted_message["timestamp"]
            })
            
            # If recipient specified, forward message
            recipient_id = data.get("recipient_id")
            if recipient_id and recipient_id in self.connections:
                await self.send_message(recipient_id, {
                    "type": "message_received",
                    "sender_id": client_id,
                    "encrypted_message": encrypted_message,
                    "timestamp": datetime.now().timestamp()
                })
                
        except Exception as e:
            logger.error(f"Error sending message from {client_id}: {e}")
            await self.send_error(client_id, "Failed to send message")
    
    async def handle_receive_message(self, client_id: str, data: Dict):
        """Handle receive message request"""
        try:
            session_id = self.user_sessions.get(client_id)
            if not session_id:
                await self.send_error(client_id, "No active session")
                return
            
            session = self.session_manager.get_session(session_id)
            if not session:
                await self.send_error(client_id, "Session expired")
                return
            
            encrypted_message = data.get("encrypted_message", {})
            if not encrypted_message:
                await self.send_error(client_id, "No encrypted message provided")
                return
            
            # Decrypt message
            decrypted_message = session.decrypt_message(encrypted_message)
            
            await self.send_message(client_id, {
                "type": "message_decrypted",
                "message": decrypted_message.decode('utf-8'),
                "message_id": encrypted_message.get("message_id"),
                "timestamp": datetime.now().timestamp()
            })
            
        except Exception as e:
            logger.error(f"Error receiving message for {client_id}: {e}")
            await self.send_error(client_id, "Failed to decrypt message")
    
    async def handle_rotate_algorithm(self, client_id: str, data: Dict):
        """Handle algorithm rotation request"""
        try:
            session_id = self.user_sessions.get(client_id)
            if not session_id:
                await self.send_error(client_id, "No active session")
                return
            
            session = self.session_manager.get_session(session_id)
            if not session:
                await self.send_error(client_id, "Session expired")
                return
            
            new_algorithm = AlgorithmType(data.get("algorithm_type", "aes_256_gcm"))
            success = session.rotate_algorithm(new_algorithm)
            
            if success:
                await self.send_message(client_id, {
                    "type": "algorithm_rotated",
                    "algorithm_type": new_algorithm.value,
                    "timestamp": datetime.now().timestamp()
                })
            else:
                await self.send_error(client_id, "Failed to rotate algorithm")
                
        except Exception as e:
            logger.error(f"Error rotating algorithm for {client_id}: {e}")
            await self.send_error(client_id, "Failed to rotate algorithm")
    
    async def handle_get_session_info(self, client_id: str):
        """Handle session info request"""
        try:
            session_id = self.user_sessions.get(client_id)
            if not session_id:
                await self.send_error(client_id, "No active session")
                return
            
            session = self.session_manager.get_session(session_id)
            if not session:
                await self.send_error(client_id, "Session expired")
                return
            
            session_info = session.to_dict()
            await self.send_message(client_id, {
                "type": "session_info",
                "session_info": session_info,
                "timestamp": datetime.now().timestamp()
            })
            
        except Exception as e:
            logger.error(f"Error getting session info for {client_id}: {e}")
            await self.send_error(client_id, "Failed to get session info")
    
    async def send_message(self, client_id: str, message: Dict):
        """Send message to client"""
        if client_id in self.connections:
            websocket = self.connections[client_id]
            if websocket.open:
                await websocket.send(json.dumps(message))
    
    async def send_error(self, client_id: str, error_message: str):
        """Send error message to client"""
        await self.send_message(client_id, {
            "type": "error",
            "message": error_message,
            "timestamp": datetime.now().timestamp()
        })
    
    def get_server_stats(self) -> Dict:
        """Get server statistics"""
        return {
            "active_connections": len(self.connections),
            "active_sessions": len(self.session_manager.list_active_sessions()),
            "total_users": len(self.user_sessions)
        }


async def main():
    """Main function to run the server"""
    server = SecureMessagingServer()
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())