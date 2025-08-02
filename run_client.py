#!/usr/bin/env python3
"""
Simple script to run a secure messaging client
"""

import asyncio
import sys
import os
import json

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from messaging.client import SecureMessagingClient


class InteractiveClient:
    """Interactive messaging client"""
    
    def __init__(self, server_url: str = "ws://localhost:8765"):
        self.client = SecureMessagingClient(server_url)
        self.user_id = None
        self.connected = False
        
        # Register callbacks
        self.client.on_message_received(self._on_message_received)
        self.client.on_message_sent(self._on_message_sent)
        self.client.on_message_decrypted(self._on_message_decrypted)
        self.client.on_algorithm_rotated(self._on_algorithm_rotated)
        self.client.on_error(self._on_error)
    
    async def start(self):
        """Start the interactive client"""
        print("Secure Messaging Client")
        print("=" * 40)
        
        # Get user ID
        self.user_id = input("Enter your user ID: ").strip()
        if not self.user_id:
            print("Invalid user ID")
            return
        
        # Get algorithm preference
        print("\nAvailable algorithms:")
        print("1. AES-256-GCM (default)")
        print("2. ChaCha20-Poly1305")
        print("3. AES-256-CBC")
        
        choice = input("Choose algorithm (1-3, default=1): ").strip()
        algorithm_map = {
            "1": "aes_256_gcm",
            "2": "chacha20_poly1305", 
            "3": "aes_256_cbc"
        }
        algorithm = algorithm_map.get(choice, "aes_256_gcm")
        
        # Connect to server
        print(f"\nConnecting to server as {self.user_id}...")
        success = await self.client.connect(self.user_id, algorithm)
        
        if success:
            self.connected = True
            print("Connected successfully!")
            await self._show_help()
            await self._interactive_loop()
        else:
            print("Failed to connect to server")
    
    async def _interactive_loop(self):
        """Main interactive loop"""
        while self.connected:
            try:
                command = input(f"[{self.user_id}]> ").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == "send":
                    await self._handle_send(parts[1:])
                elif cmd == "rotate":
                    await self._handle_rotate(parts[1:])
                elif cmd == "info":
                    await self._handle_info()
                elif cmd == "help":
                    await self._show_help()
                elif cmd == "quit":
                    break
                else:
                    print("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        await self.client.disconnect()
        print("Disconnected from server")
    
    async def _handle_send(self, args):
        """Handle send command"""
        if len(args) < 2:
            print("Usage: send <recipient> <message>")
            return
        
        recipient = args[0]
        message = " ".join(args[1:])
        
        await self.client.send_message(message, recipient)
    
    async def _handle_rotate(self, args):
        """Handle rotate command"""
        if len(args) < 1:
            print("Usage: rotate <algorithm>")
            print("Available algorithms: aes_256_gcm, chacha20_poly1305, aes_256_cbc")
            return
        
        algorithm = args[0]
        await self.client.rotate_algorithm(algorithm)
    
    async def _handle_info(self):
        """Handle info command"""
        await self.client.get_session_info()
    
    async def _show_help(self):
        """Show help information"""
        print("\nAvailable commands:")
        print("  send <recipient> <message>  - Send encrypted message")
        print("  rotate <algorithm>          - Rotate encryption algorithm")
        print("  info                        - Show session information")
        print("  help                        - Show this help")
        print("  quit                        - Disconnect and exit")
        print("\nExample:")
        print("  send bob Hello, this is a secret message!")
        print("  rotate chacha20_poly1305")
        print()
    
    def _on_message_received(self, data):
        """Handle received message"""
        sender_id = data.get('sender_id')
        print(f"\n[RECEIVED] Message from {sender_id}")
        
        # Automatically decrypt received messages
        asyncio.create_task(self.client.receive_message(data.get('encrypted_message')))
    
    def _on_message_sent(self, data):
        """Handle sent message confirmation"""
        message_id = data.get('message_id')
        print(f"[SENT] Message sent successfully (ID: {message_id})")
    
    def _on_message_decrypted(self, data):
        """Handle decrypted message"""
        message = data.get('message')
        print(f"[DECRYPTED] {message}")
    
    def _on_algorithm_rotated(self, data):
        """Handle algorithm rotation"""
        algorithm_type = data.get('algorithm_type')
        print(f"[ROTATED] Algorithm changed to: {algorithm_type}")
    
    def _on_error(self, data):
        """Handle error"""
        error_message = data.get('message')
        print(f"[ERROR] {error_message}")


async def main():
    """Main function"""
    client = InteractiveClient()
    await client.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient stopped by user")