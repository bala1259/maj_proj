"""
Secure Messaging Client
WebSocket client for secure messaging with encryption
"""

import asyncio
import json
import logging
from typing import Dict, Optional, Callable, List
from datetime import datetime
import websockets
from websockets.client import WebSocketClientProtocol
from pydantic import BaseModel

from src.crypto.algorithms import AlgorithmType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MessageCallback:
    """Message callback handler"""
    
    def __init__(self):
        self.callbacks: Dict[str, List[Callable]] = {
            "message_received": [],
            "message_sent": [],
            "message_decrypted": [],
            "algorithm_rotated": [],
            "session_info": [],
            "error": []
        }
    
    def register(self, event_type: str, callback: Callable):
        """Register a callback for an event type"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def trigger(self, event_type: str, data: Dict):
        """Trigger callbacks for an event type"""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error in callback for {event_type}: {e}")


class SecureMessagingClient:
    """Secure messaging client with WebSocket support"""
    
    def __init__(self, server_url: str = "ws://localhost:8765"):
        self.server_url = server_url
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.user_id: Optional[str] = None
        self.session_id: Optional[str] = None
        self.connected = False
        self.message_callback = MessageCallback()
        self.pending_messages: List[Dict] = []
        
    async def connect(self, user_id: str, algorithm_type: str = "aes_256_gcm"):
        """Connect to the messaging server"""
        try:
            self.user_id = user_id
            self.websocket = await websockets.connect(self.server_url)
            
            # Send authentication message
            auth_message = {
                "type": "auth",
                "user_id": user_id,
                "algorithm": algorithm_type
            }
            
            await self.websocket.send(json.dumps(auth_message))
            
            # Wait for authentication response
            response = await self.websocket.recv()
            response_data = json.loads(response)
            
            if response_data.get("type") == "auth_success":
                self.session_id = response_data.get("session_id")
                self.connected = True
                logger.info(f"Connected to server with session {self.session_id}")
                
                # Start message listener
                asyncio.create_task(self._message_listener())
                
                # Send pending messages
                await self._send_pending_messages()
                
                return True
            else:
                logger.error(f"Authentication failed: {response_data}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from the server"""
        self.connected = False
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
    
    async def send_message(self, message: str, recipient_id: Optional[str] = None, 
                          algorithm_type: Optional[str] = None):
        """Send an encrypted message"""
        if not self.connected:
            self.pending_messages.append({
                "type": "send_message",
                "message": message,
                "recipient_id": recipient_id,
                "algorithm_type": algorithm_type
            })
            return
        
        try:
            message_data = {
                "type": "send_message",
                "message": message
            }
            
            if recipient_id:
                message_data["recipient_id"] = recipient_id
            if algorithm_type:
                message_data["algorithm_type"] = algorithm_type
            
            await self.websocket.send(json.dumps(message_data))
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
    
    async def receive_message(self, encrypted_message: Dict):
        """Receive and decrypt a message"""
        if not self.connected:
            return
        
        try:
            message_data = {
                "type": "receive_message",
                "encrypted_message": encrypted_message
            }
            
            await self.websocket.send(json.dumps(message_data))
            
        except Exception as e:
            logger.error(f"Failed to receive message: {e}")
    
    async def rotate_algorithm(self, new_algorithm: str):
        """Rotate to a new encryption algorithm"""
        if not self.connected:
            return
        
        try:
            message_data = {
                "type": "rotate_algorithm",
                "algorithm_type": new_algorithm
            }
            
            await self.websocket.send(json.dumps(message_data))
            
        except Exception as e:
            logger.error(f"Failed to rotate algorithm: {e}")
    
    async def get_session_info(self):
        """Get current session information"""
        if not self.connected:
            return
        
        try:
            message_data = {
                "type": "get_session_info"
            }
            
            await self.websocket.send(json.dumps(message_data))
            
        except Exception as e:
            logger.error(f"Failed to get session info: {e}")
    
    async def _message_listener(self):
        """Listen for incoming messages"""
        try:
            async for message in self.websocket:
                await self._handle_message(message)
        except websockets.exceptions.ConnectionClosed:
            logger.info("Connection to server closed")
            self.connected = False
        except Exception as e:
            logger.error(f"Error in message listener: {e}")
            self.connected = False
    
    async def _handle_message(self, message: str):
        """Handle incoming message"""
        try:
            data = json.loads(message)
            message_type = data.get("type")
            
            # Trigger callbacks
            self.message_callback.trigger(message_type, data)
            
            # Log message
            if message_type == "message_received":
                logger.info(f"Received message from {data.get('sender_id')}")
            elif message_type == "message_sent":
                logger.info(f"Message sent successfully (ID: {data.get('message_id')})")
            elif message_type == "message_decrypted":
                logger.info(f"Message decrypted: {data.get('message')}")
            elif message_type == "algorithm_rotated":
                logger.info(f"Algorithm rotated to {data.get('algorithm_type')}")
            elif message_type == "session_info":
                logger.info(f"Session info: {data.get('session_info')}")
            elif message_type == "error":
                logger.error(f"Server error: {data.get('message')}")
                
        except json.JSONDecodeError:
            logger.error("Invalid JSON message received")
        except Exception as e:
            logger.error(f"Error handling message: {e}")
    
    async def _send_pending_messages(self):
        """Send any pending messages after connection"""
        for message_data in self.pending_messages:
            try:
                await self.websocket.send(json.dumps(message_data))
            except Exception as e:
                logger.error(f"Failed to send pending message: {e}")
        
        self.pending_messages.clear()
    
    def on_message_received(self, callback: Callable):
        """Register callback for received messages"""
        self.message_callback.register("message_received", callback)
    
    def on_message_sent(self, callback: Callable):
        """Register callback for sent messages"""
        self.message_callback.register("message_sent", callback)
    
    def on_message_decrypted(self, callback: Callable):
        """Register callback for decrypted messages"""
        self.message_callback.register("message_decrypted", callback)
    
    def on_algorithm_rotated(self, callback: Callable):
        """Register callback for algorithm rotation"""
        self.message_callback.register("algorithm_rotated", callback)
    
    def on_error(self, callback: Callable):
        """Register callback for errors"""
        self.message_callback.register("error", callback)


# Example usage and testing
async def example_client():
    """Example client usage"""
    client = SecureMessagingClient()
    
    # Register callbacks
    def on_message_received(data):
        print(f"Received message from {data.get('sender_id')}")
        # Automatically decrypt received messages
        asyncio.create_task(client.receive_message(data.get('encrypted_message')))
    
    def on_message_decrypted(data):
        print(f"Decrypted message: {data.get('message')}")
    
    def on_error(data):
        print(f"Error: {data.get('message')}")
    
    client.on_message_received(on_message_received)
    client.on_message_decrypted(on_message_decrypted)
    client.on_error(on_error)
    
    # Connect to server
    if await client.connect("user1", "aes_256_gcm"):
        print("Connected successfully!")
        
        # Send a message
        await client.send_message("Hello, secure world!", "user2")
        
        # Wait for some time
        await asyncio.sleep(5)
        
        # Rotate algorithm
        await client.rotate_algorithm("chacha20_poly1305")
        
        # Get session info
        await client.get_session_info()
        
        # Wait a bit more
        await asyncio.sleep(5)
        
        # Disconnect
        await client.disconnect()
    else:
        print("Failed to connect")


if __name__ == "__main__":
    asyncio.run(example_client())