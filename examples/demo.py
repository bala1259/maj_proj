#!/usr/bin/env python3
"""
Secure Messaging System Demo
Demonstrates the multi-algorithm encryption system with multiple clients
"""

import asyncio
import json
import time
from typing import List
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from messaging.server import SecureMessagingServer
from messaging.client import SecureMessagingClient
from crypto.algorithms import AlgorithmType


class DemoClient:
    """Demo client with enhanced functionality"""
    
    def __init__(self, user_id: str, server_url: str = "ws://localhost:8765"):
        self.user_id = user_id
        self.client = SecureMessagingClient(server_url)
        self.messages_received = []
        self.messages_sent = []
        
        # Register callbacks
        self.client.on_message_received(self._on_message_received)
        self.client.on_message_sent(self._on_message_sent)
        self.client.on_message_decrypted(self._on_message_decrypted)
        self.client.on_algorithm_rotated(self._on_algorithm_rotated)
        self.client.on_error(self._on_error)
    
    async def start(self, algorithm_type: str = "aes_256_gcm"):
        """Start the client"""
        print(f"[{self.user_id}] Connecting to server...")
        success = await self.client.connect(self.user_id, algorithm_type)
        if success:
            print(f"[{self.user_id}] Connected successfully!")
            return True
        else:
            print(f"[{self.user_id}] Failed to connect!")
            return False
    
    async def stop(self):
        """Stop the client"""
        await self.client.disconnect()
        print(f"[{self.user_id}] Disconnected")
    
    async def send_message(self, message: str, recipient_id: str = None, algorithm_type: str = None):
        """Send a message"""
        print(f"[{self.user_id}] Sending message: '{message}'")
        if recipient_id:
            print(f"[{self.user_id}] To: {recipient_id}")
        if algorithm_type:
            print(f"[{self.user_id}] Using algorithm: {algorithm_type}")
        
        await self.client.send_message(message, recipient_id, algorithm_type)
    
    async def rotate_algorithm(self, new_algorithm: str):
        """Rotate encryption algorithm"""
        print(f"[{self.user_id}] Rotating to algorithm: {new_algorithm}")
        await self.client.rotate_algorithm(new_algorithm)
    
    async def get_session_info(self):
        """Get session information"""
        print(f"[{self.user_id}] Getting session info...")
        await self.client.get_session_info()
    
    def _on_message_received(self, data):
        """Handle received message"""
        sender_id = data.get('sender_id')
        print(f"[{self.user_id}] Received message from {sender_id}")
        self.messages_received.append(data)
        
        # Automatically decrypt received messages
        asyncio.create_task(self.client.receive_message(data.get('encrypted_message')))
    
    def _on_message_sent(self, data):
        """Handle sent message confirmation"""
        message_id = data.get('message_id')
        print(f"[{self.user_id}] Message sent successfully (ID: {message_id})")
        self.messages_sent.append(data)
    
    def _on_message_decrypted(self, data):
        """Handle decrypted message"""
        message = data.get('message')
        print(f"[{self.user_id}] Decrypted message: '{message}'")
    
    def _on_algorithm_rotated(self, data):
        """Handle algorithm rotation"""
        algorithm_type = data.get('algorithm_type')
        print(f"[{self.user_id}] Algorithm rotated to: {algorithm_type}")
    
    def _on_error(self, data):
        """Handle error"""
        error_message = data.get('message')
        print(f"[{self.user_id}] Error: {error_message}")


async def run_server():
    """Run the messaging server"""
    print("Starting secure messaging server...")
    server = SecureMessagingServer()
    await server.start()


async def demo_basic_encryption():
    """Demo basic encryption functionality"""
    print("\n" + "="*60)
    print("DEMO 1: Basic Encryption")
    print("="*60)
    
    # Start server
    server_task = asyncio.create_task(run_server())
    await asyncio.sleep(1)  # Give server time to start
    
    # Create clients
    alice = DemoClient("alice")
    bob = DemoClient("bob")
    
    # Start clients
    await alice.start("aes_256_gcm")
    await bob.start("aes_256_gcm")
    
    await asyncio.sleep(1)
    
    # Send messages
    await alice.send_message("Hello Bob! This is a secret message.", "bob")
    await asyncio.sleep(1)
    
    await bob.send_message("Hi Alice! I received your encrypted message.", "alice")
    await asyncio.sleep(1)
    
    # Stop clients
    await alice.stop()
    await bob.stop()
    
    # Stop server
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass


async def demo_algorithm_rotation():
    """Demo algorithm rotation"""
    print("\n" + "="*60)
    print("DEMO 2: Algorithm Rotation")
    print("="*60)
    
    # Start server
    server_task = asyncio.create_task(run_server())
    await asyncio.sleep(1)
    
    # Create clients
    charlie = DemoClient("charlie")
    diana = DemoClient("diana")
    
    # Start clients
    await charlie.start("aes_256_gcm")
    await diana.start("aes_256_gcm")
    
    await asyncio.sleep(1)
    
    # Send initial message
    await charlie.send_message("Starting with AES-256-GCM", "diana")
    await asyncio.sleep(1)
    
    # Rotate to ChaCha20
    await charlie.rotate_algorithm("chacha20_poly1305")
    await asyncio.sleep(1)
    
    await charlie.send_message("Now using ChaCha20-Poly1305", "diana")
    await asyncio.sleep(1)
    
    # Rotate to AES-CBC
    await charlie.rotate_algorithm("aes_256_cbc")
    await asyncio.sleep(1)
    
    await charlie.send_message("Finally using AES-256-CBC", "diana")
    await asyncio.sleep(1)
    
    # Stop clients
    await charlie.stop()
    await diana.stop()
    
    # Stop server
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass


async def demo_multi_client():
    """Demo multi-client scenario"""
    print("\n" + "="*60)
    print("DEMO 3: Multi-Client Scenario")
    print("="*60)
    
    # Start server
    server_task = asyncio.create_task(run_server())
    await asyncio.sleep(1)
    
    # Create multiple clients
    clients = []
    user_names = ["alice", "bob", "charlie", "diana", "eve"]
    
    for i, name in enumerate(user_names):
        client = DemoClient(name)
        algorithm = list(AlgorithmType)[i % len(AlgorithmType)].value
        await client.start(algorithm)
        clients.append(client)
        await asyncio.sleep(0.5)
    
    await asyncio.sleep(1)
    
    # Send messages in a chain
    for i in range(len(clients)):
        sender = clients[i]
        recipient = clients[(i + 1) % len(clients)]
        
        message = f"Message {i+1} from {sender.user_id} to {recipient.user_id}"
        await sender.send_message(message, recipient.user_id)
        await asyncio.sleep(1)
    
    # Get session info for all clients
    for client in clients:
        await client.get_session_info()
        await asyncio.sleep(0.5)
    
    await asyncio.sleep(2)
    
    # Stop all clients
    for client in clients:
        await client.stop()
    
    # Stop server
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass


async def demo_performance():
    """Demo performance with multiple messages"""
    print("\n" + "="*60)
    print("DEMO 4: Performance Test")
    print("="*60)
    
    # Start server
    server_task = asyncio.create_task(run_server())
    await asyncio.sleep(1)
    
    # Create clients
    sender = DemoClient("sender")
    receiver = DemoClient("receiver")
    
    await sender.start("aes_256_gcm")
    await receiver.start("aes_256_gcm")
    
    await asyncio.sleep(1)
    
    # Send multiple messages
    num_messages = 10
    start_time = time.time()
    
    for i in range(num_messages):
        message = f"Performance test message {i+1}/{num_messages}"
        await sender.send_message(message, "receiver")
        await asyncio.sleep(0.1)
    
    # Wait for all messages to be processed
    await asyncio.sleep(2)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\nPerformance Results:")
    print(f"Messages sent: {num_messages}")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Messages per second: {num_messages/total_time:.2f}")
    print(f"Average time per message: {total_time/num_messages*1000:.2f} ms")
    
    # Stop clients
    await sender.stop()
    await receiver.stop()
    
    # Stop server
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass


async def main():
    """Main demo function"""
    print("Secure Messaging System - Multi-Algorithm Encryption Demo")
    print("="*60)
    
    try:
        # Run all demos
        await demo_basic_encryption()
        await asyncio.sleep(2)
        
        await demo_algorithm_rotation()
        await asyncio.sleep(2)
        
        await demo_multi_client()
        await asyncio.sleep(2)
        
        await demo_performance()
        
        print("\n" + "="*60)
        print("All demos completed successfully!")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())