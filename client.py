"""
Client Application for Multi-Algorithm Secure Messaging
Demonstrates how to use the secure messaging system
"""

import asyncio
import json
import base64
import argparse
import websockets
import aiohttp
from typing import Dict, Optional, List
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from crypto_engine import CryptoEngine, AlgorithmType
from session_manager import SessionManager


class SecureMessagingClient:
    """Client for the secure messaging system"""
    
    def __init__(self, server_url: str, username: str, password: str):
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.crypto_engine = CryptoEngine()
        self.session_manager = SessionManager(self.crypto_engine)
        
        # Authentication
        self.access_token = None
        self.refresh_token = None
        self.user_id = None
        
        # WebSocket connection
        self.websocket = None
        
        # Session storage
        self.sessions: Dict[str, Dict] = {}
        self.current_session_id = None
    
    async def register(self) -> bool:
        """Register a new user account"""
        async with aiohttp.ClientSession() as session:
            data = {
                "username": self.username,
                "email": f"{self.username}@example.com",
                "password": self.password
            }
            
            async with session.post(f"{self.server_url}/auth/register", json=data) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"✅ Registered successfully: {result['message']}")
                    return True
                else:
                    error = await response.json()
                    print(f"❌ Registration failed: {error}")
                    return False
    
    async def login(self) -> bool:
        """Login to the system"""
        async with aiohttp.ClientSession() as session:
            data = {
                "username": self.username,
                "password": self.password
            }
            
            async with session.post(f"{self.server_url}/auth/login", json=data) as response:
                if response.status == 200:
                    result = await response.json()
                    self.access_token = result["access_token"]
                    self.refresh_token = result["refresh_token"]
                    self.user_id = result["user_id"]
                    print(f"✅ Logged in successfully as {self.username}")
                    return True
                else:
                    error = await response.json()
                    print(f"❌ Login failed: {error}")
                    return False
    
    async def create_session(self, algorithm: str = None) -> Optional[str]:
        """Create a new secure messaging session"""
        if not self.access_token:
            print("❌ Not authenticated")
            return None
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            data = {}
            if algorithm:
                data["algorithm"] = algorithm
            
            async with session.post(f"{self.server_url}/session/create", 
                                  json=data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    session_id = result["session_id"]
                    dh_params_b64 = result["dh_parameters"]
                    algorithm_name = result["algorithm"]
                    
                    # Store session info
                    self.sessions[session_id] = {
                        "session_id": session_id,
                        "algorithm": algorithm_name,
                        "dh_parameters": dh_params_b64,
                        "is_creator": True,
                        "participants": [self.username]
                    }
                    
                    print(f"✅ Created session {session_id} with {algorithm_name}")
                    print(f"📋 DH Parameters: {dh_params_b64[:50]}...")
                    return session_id
                else:
                    error = await response.json()
                    print(f"❌ Failed to create session: {error}")
                    return None
    
    async def join_session(self, session_id: str) -> bool:
        """Join an existing session"""
        if not self.access_token:
            print("❌ Not authenticated")
            return False
        
        # Generate DH key pair
        dh_params = self.crypto_engine.generate_dh_parameters()
        private_key, public_key = self.crypto_engine.generate_dh_key_pair(dh_params)
        
        # Serialize public key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            data = {
                "session_id": session_id,
                "public_key": public_key_b64
            }
            
            async with session.post(f"{self.server_url}/session/join", 
                                  json=data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    # Store session info
                    self.sessions[session_id] = {
                        "session_id": session_id,
                        "is_creator": False,
                        "private_key": private_key,
                        "public_key": public_key,
                        "participants": [self.username]
                    }
                    
                    print(f"✅ Joined session {session_id}")
                    return True
                else:
                    error = await response.json()
                    print(f"❌ Failed to join session: {error}")
                    return False
    
    async def establish_session_keys(self, session_id: str, participant_keys: Dict[str, str]) -> bool:
        """Establish session keys using Diffie-Hellman"""
        if not self.access_token:
            print("❌ Not authenticated")
            return False
        
        session = self.sessions.get(session_id)
        if not session or not session.get("is_creator"):
            print("❌ Only session creator can establish keys")
            return False
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            async with session.post(f"{self.server_url}/session/{session_id}/establish", 
                                  json=participant_keys, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    creator_public_key = result["creator_public_key"]
                    print(f"✅ Session keys established")
                    print(f"📋 Creator public key: {creator_public_key[:50]}...")
                    return True
                else:
                    error = await response.json()
                    print(f"❌ Failed to establish session keys: {error}")
                    return False
    
    async def send_message(self, session_id: str, message: str) -> bool:
        """Send an encrypted message"""
        if not self.access_token:
            print("❌ Not authenticated")
            return False
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            data = {"message": message}
            
            async with session.post(f"{self.server_url}/session/{session_id}/send", 
                                  json=data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    message_id = result["message_id"]
                    print(f"✅ Message sent (ID: {message_id})")
                    return True
                else:
                    error = await response.json()
                    print(f"❌ Failed to send message: {error}")
                    return False
    
    async def get_session_info(self, session_id: str) -> Optional[Dict]:
        """Get session information"""
        if not self.access_token:
            print("❌ Not authenticated")
            return None
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            async with session.get(f"{self.server_url}/session/{session_id}/info", 
                                 headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error = await response.json()
                    print(f"❌ Failed to get session info: {error}")
                    return None
    
    async def list_sessions(self) -> List[Dict]:
        """List all user sessions"""
        if not self.access_token:
            print("❌ Not authenticated")
            return []
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            async with session.get(f"{self.server_url}/sessions", 
                                 headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    return result["sessions"]
                else:
                    error = await response.json()
                    print(f"❌ Failed to list sessions: {error}")
                    return []
    
    async def connect_websocket(self):
        """Connect to WebSocket for real-time messaging"""
        if not self.user_id:
            print("❌ Not authenticated")
            return
        
        try:
            self.websocket = await websockets.connect(f"{self.server_url.replace('http', 'ws')}/ws/{self.user_id}")
            print(f"✅ Connected to WebSocket")
            
            # Start listening for messages
            asyncio.create_task(self._listen_websocket())
            
        except Exception as e:
            print(f"❌ Failed to connect to WebSocket: {e}")
    
    async def _listen_websocket(self):
        """Listen for WebSocket messages"""
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                
                if data.get("type") == "message":
                    session_id = data.get("session_id")
                    sender_username = data.get("sender_username")
                    encrypted_message = data.get("encrypted_message")
                    timestamp = data.get("timestamp")
                    
                    print(f"\n📨 Message from {sender_username} in session {session_id}")
                    print(f"⏰ {timestamp}")
                    print(f"🔐 Encrypted: {encrypted_message[:100]}...")
                    
                    # In a real implementation, you'd decrypt the message here
                    # using the session keys
                
                elif data.get("type") == "pong":
                    print("🏓 Pong received")
        
        except websockets.exceptions.ConnectionClosed:
            print("❌ WebSocket connection closed")
        except Exception as e:
            print(f"❌ WebSocket error: {e}")
    
    async def disconnect_websocket(self):
        """Disconnect from WebSocket"""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            print("✅ Disconnected from WebSocket")
    
    async def get_algorithms(self) -> Dict:
        """Get supported encryption algorithms"""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.server_url}/algorithms") as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"❌ Failed to get algorithms")
                    return {}
    
    async def get_health(self) -> Dict:
        """Get server health status"""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.server_url}/health") as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"❌ Failed to get health status")
                    return {}


async def interactive_client(server_url: str, username: str, password: str):
    """Interactive client session"""
    client = SecureMessagingClient(server_url, username, password)
    
    print(f"🔐 Secure Messaging Client")
    print(f"📡 Server: {server_url}")
    print(f"👤 User: {username}")
    print("=" * 50)
    
    # Check server health
    health = await client.get_health()
    if health:
        print(f"🏥 Server Status: {health.get('status', 'unknown')}")
        print(f"📊 Active Sessions: {health.get('active_sessions', 0)}")
        print(f"👥 Total Users: {health.get('total_users', 0)}")
    
    # Get supported algorithms
    algorithms = await client.get_algorithms()
    if algorithms:
        print(f"\n🔧 Supported Algorithms:")
        for alg_name, alg_info in algorithms["algorithms"].items():
            print(f"  • {alg_info['name']}: {alg_info['description']}")
    
    # Try to login, register if needed
    if not await client.login():
        print(f"\n📝 Registration required...")
        if await client.register():
            if not await client.login():
                print("❌ Failed to login after registration")
                return
        else:
            print("❌ Failed to register")
            return
    
    # Connect to WebSocket
    await client.connect_websocket()
    
    # Main interactive loop
    while True:
        print(f"\n📋 Available Commands:")
        print(f"  1. create <algorithm>  - Create new session")
        print(f"  2. join <session_id>   - Join existing session")
        print(f"  3. send <session_id> <message> - Send message")
        print(f"  4. info <session_id>   - Get session info")
        print(f"  5. list               - List sessions")
        print(f"  6. algorithms         - Show algorithms")
        print(f"  7. health             - Server health")
        print(f"  8. quit               - Exit")
        
        try:
            command = input(f"\n💬 Enter command: ").strip().split()
            if not command:
                continue
            
            cmd = command[0].lower()
            
            if cmd == "quit":
                break
            
            elif cmd == "create":
                algorithm = command[1] if len(command) > 1 else None
                session_id = await client.create_session(algorithm)
                if session_id:
                    client.current_session_id = session_id
            
            elif cmd == "join":
                if len(command) < 2:
                    print("❌ Usage: join <session_id>")
                    continue
                session_id = command[1]
                await client.join_session(session_id)
                client.current_session_id = session_id
            
            elif cmd == "send":
                if len(command) < 3:
                    print("❌ Usage: send <session_id> <message>")
                    continue
                session_id = command[1]
                message = " ".join(command[2:])
                await client.send_message(session_id, message)
            
            elif cmd == "info":
                if len(command) < 2:
                    print("❌ Usage: info <session_id>")
                    continue
                session_id = command[1]
                info = await client.get_session_info(session_id)
                if info:
                    print(f"📊 Session Info:")
                    print(f"  ID: {info['session_id']}")
                    print(f"  State: {info['state']}")
                    print(f"  Algorithm: {info['algorithm']}")
                    print(f"  Participants: {len(info['participants'])}")
                    print(f"  Messages: {info['message_count']}")
            
            elif cmd == "list":
                sessions = await client.list_sessions()
                if sessions:
                    print(f"📋 Your Sessions:")
                    for session in sessions:
                        print(f"  • {session['session_id']} ({session['state']}) - {session['algorithm']}")
                else:
                    print("📋 No sessions found")
            
            elif cmd == "algorithms":
                algorithms = await client.get_algorithms()
                if algorithms:
                    print(f"🔧 Supported Algorithms:")
                    for alg_name, alg_info in algorithms["algorithms"].items():
                        print(f"  • {alg_info['name']}: {alg_info['description']}")
            
            elif cmd == "health":
                health = await client.get_health()
                if health:
                    print(f"🏥 Server Health:")
                    print(f"  Status: {health.get('status', 'unknown')}")
                    print(f"  Active Sessions: {health.get('active_sessions', 0)}")
                    print(f"  Total Users: {health.get('total_users', 0)}")
                    print(f"  Timestamp: {health.get('timestamp', 'unknown')}")
            
            else:
                print(f"❌ Unknown command: {cmd}")
        
        except KeyboardInterrupt:
            print(f"\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Cleanup
    await client.disconnect_websocket()


def main():
    parser = argparse.ArgumentParser(description="Secure Messaging Client")
    parser.add_argument("--server", default="http://localhost:8000", help="Server URL")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    
    args = parser.parse_args()
    
    # Run interactive client
    asyncio.run(interactive_client(args.server, args.username, args.password))


if __name__ == "__main__":
    main()