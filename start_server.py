#!/usr/bin/env python3
"""
Startup script for the Secure Multi-Algorithm Messaging Server
"""

import os
import sys
import uvicorn
from dotenv import load_dotenv

def main():
    """Start the secure messaging server"""
    
    # Load environment variables
    load_dotenv()
    
    # Get configuration from environment
    host = os.getenv("SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_PORT", "8000"))
    debug = os.getenv("DEBUG", "true").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "info")
    
    print("🔐 Starting Secure Multi-Algorithm Messaging Server")
    print(f"📡 Host: {host}")
    print(f"🔌 Port: {port}")
    print(f"🐛 Debug: {debug}")
    print(f"📝 Log Level: {log_level}")
    print("=" * 50)
    
    try:
        # Start the server
        uvicorn.run(
            "server:app",
            host=host,
            port=port,
            reload=debug,
            log_level=log_level,
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()