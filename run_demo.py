#!/usr/bin/env python3
"""
Run the Secure Messaging System Demo
"""

import asyncio
import sys
from demo import demo_secure_messaging

def main():
    """Run the demo"""
    print("🚀 Starting Secure Messaging System Demo")
    print("=" * 50)
    
    try:
        asyncio.run(demo_secure_messaging())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"❌ Error running demo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()