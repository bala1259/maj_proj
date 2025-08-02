#!/usr/bin/env python3
"""
Setup script for the Secure Multi-Algorithm Messaging System
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)

def create_env_file():
    """Create .env file if it doesn't exist"""
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if not env_file.exists():
        if env_example.exists():
            shutil.copy(env_example, env_file)
            print("✅ Created .env file from .env.example")
        else:
            print("⚠️  No .env.example found, creating basic .env file")
            with open(env_file, "w") as f:
                f.write("# Secure Messaging System Configuration\n")
                f.write("SERVER_HOST=0.0.0.0\n")
                f.write("SERVER_PORT=8000\n")
                f.write("DEBUG=true\n")
                f.write("JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production\n")
                f.write("JWT_ALGORITHM=HS256\n")
                f.write("ACCESS_TOKEN_EXPIRE_MINUTES=30\n")
                f.write("REFRESH_TOKEN_EXPIRE_DAYS=7\n")
                f.write("DEFAULT_ALGORITHM=aes-256-gcm\n")
                f.write("SESSION_CLEANUP_INTERVAL=3600\n")
                f.write("MAX_SESSION_AGE=86400\n")
                f.write("LOG_LEVEL=INFO\n")
            print("✅ Created basic .env file")
    else:
        print("✅ .env file already exists")

def run_tests():
    """Run the test suite"""
    print("🧪 Running tests...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pytest", "test_system.py", "-v"
        ])
        print("✅ All tests passed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Some tests failed: {e}")
        response = input("Continue with setup anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = ["logs", "data", "keys"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    print("✅ Created necessary directories")

def main():
    """Main setup function"""
    print("🔐 Secure Multi-Algorithm Messaging System Setup")
    print("=" * 50)
    
    # Check Python version
    check_python_version()
    
    # Create directories
    create_directories()
    
    # Install dependencies
    install_dependencies()
    
    # Create environment file
    create_env_file()
    
    # Run tests
    run_tests()
    
    print("\n🎉 Setup completed successfully!")
    print("=" * 50)
    print("📋 Next steps:")
    print("   1. Edit .env file with your configuration")
    print("   2. Run the demo: python run_demo.py")
    print("   3. Start the server: python start_server.py")
    print("   4. Use the client: python client.py --username alice --password password123")
    print("\n📚 Documentation:")
    print("   • README.md - System overview and usage")
    print("   • API documentation available at http://localhost:8000/docs when server is running")

if __name__ == "__main__":
    main()