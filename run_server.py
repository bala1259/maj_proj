#!/usr/bin/env python3
"""
Simple script to run the secure messaging server
"""

import asyncio
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from messaging.server import SecureMessagingServer


async def main():
    """Main function to run the server"""
    print("Starting Secure Messaging Server...")
    print("Server will be available at ws://localhost:8765")
    print("Press Ctrl+C to stop the server")
    
    try:
        server = SecureMessagingServer(host="0.0.0.0", port=8765)
        await server.start()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    asyncio.run(main())