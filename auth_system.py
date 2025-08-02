"""
Authentication System for Secure Messaging
Handles user registration, login, and JWT token management
"""

import os
import time
import hashlib
import secrets
from typing import Dict, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@dataclass
class User:
    """User information"""
    user_id: str
    username: str
    email: str
    password_hash: str
    created_at: float
    last_login: float
    is_active: bool = True
    public_key: Optional[bytes] = None


class AuthSystem:
    """Authentication system for secure messaging"""
    
    def __init__(self, secret_key: str = None, algorithm: str = "HS256"):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7
        
        # Password hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # User storage (in production, use a database)
        self.users: Dict[str, User] = {}
        self.username_to_id: Dict[str, str] = {}
        self.email_to_id: Dict[str, str] = {}
        
        # Token blacklist (in production, use Redis)
        self.blacklisted_tokens: set = set()
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return self.pwd_context.hash(password)
    
    def create_access_token(self, data: dict, expires_delta: timedelta = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, data: dict) -> str:
        """Create a JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify and decode a JWT token"""
        try:
            if token in self.blacklisted_tokens:
                return None
            
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None
    
    def blacklist_token(self, token: str):
        """Add a token to the blacklist"""
        self.blacklisted_tokens.add(token)
    
    def register_user(self, username: str, email: str, password: str) -> Optional[str]:
        """Register a new user"""
        # Check if username or email already exists
        if username in self.username_to_id:
            return None
        
        if email in self.email_to_id:
            return None
        
        # Validate input
        if len(username) < 3 or len(username) > 20:
            return None
        
        if len(password) < 8:
            return None
        
        # Generate user ID
        user_id = secrets.token_urlsafe(16)
        
        # Hash password
        password_hash = self.get_password_hash(password)
        
        # Create user
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            created_at=time.time(),
            last_login=time.time()
        )
        
        # Store user
        self.users[user_id] = user
        self.username_to_id[username] = user_id
        self.email_to_id[email] = user_id
        
        return user_id
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user"""
        # Find user by username or email
        user_id = self.username_to_id.get(username)
        if not user_id:
            user_id = self.email_to_id.get(username)
        
        if not user_id:
            return None
        
        user = self.users.get(user_id)
        if not user or not user.is_active:
            return None
        
        if not self.verify_password(password, user.password_hash):
            return None
        
        # Update last login
        user.last_login = time.time()
        
        return user
    
    def login_user(self, username: str, password: str) -> Optional[Dict]:
        """Login a user and return tokens"""
        user = self.authenticate_user(username, password)
        if not user:
            return None
        
        # Create tokens
        access_token = self.create_access_token(
            data={"sub": user.user_id, "username": user.username}
        )
        refresh_token = self.create_refresh_token(
            data={"sub": user.user_id}
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": user.user_id,
            "username": user.username
        }
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Refresh an access token using a refresh token"""
        payload = self.verify_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            return None
        
        user_id = payload.get("sub")
        user = self.users.get(user_id)
        if not user or not user.is_active:
            return None
        
        # Create new access token
        access_token = self.create_access_token(
            data={"sub": user.user_id, "username": user.username}
        )
        
        return access_token
    
    def logout_user(self, access_token: str, refresh_token: str = None):
        """Logout a user by blacklisting tokens"""
        self.blacklist_token(access_token)
        if refresh_token:
            self.blacklist_token(refresh_token)
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        user_id = self.username_to_id.get(username)
        if user_id:
            return self.users.get(user_id)
        return None
    
    def update_user_public_key(self, user_id: str, public_key: bytes) -> bool:
        """Update user's public key"""
        user = self.users.get(user_id)
        if not user:
            return False
        
        user.public_key = public_key
        return True
    
    def get_user_public_key(self, user_id: str) -> Optional[bytes]:
        """Get user's public key"""
        user = self.users.get(user_id)
        if user:
            return user.public_key
        return None
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password"""
        user = self.users.get(user_id)
        if not user:
            return False
        
        # Verify old password
        if not self.verify_password(old_password, user.password_hash):
            return False
        
        # Validate new password
        if len(new_password) < 8:
            return False
        
        # Update password
        user.password_hash = self.get_password_hash(new_password)
        return True
    
    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate a user account"""
        user = self.users.get(user_id)
        if not user:
            return False
        
        user.is_active = False
        return True
    
    def activate_user(self, user_id: str) -> bool:
        """Activate a user account"""
        user = self.users.get(user_id)
        if not user:
            return False
        
        user.is_active = True
        return True
    
    def get_user_statistics(self) -> Dict:
        """Get user statistics"""
        total_users = len(self.users)
        active_users = len([u for u in self.users.values() if u.is_active])
        inactive_users = total_users - active_users
        
        # Users created in last 30 days
        thirty_days_ago = time.time() - (30 * 24 * 60 * 60)
        recent_users = len([u for u in self.users.values() if u.created_at > thirty_days_ago])
        
        # Users with public keys
        users_with_keys = len([u for u in self.users.values() if u.public_key])
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "recent_users": recent_users,
            "users_with_keys": users_with_keys
        }
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List users with pagination"""
        user_list = []
        sorted_users = sorted(self.users.values(), key=lambda u: u.created_at, reverse=True)
        
        for user in sorted_users[offset:offset + limit]:
            user_list.append({
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at,
                "last_login": user.last_login,
                "is_active": user.is_active,
                "has_public_key": user.public_key is not None
            })
        
        return user_list
    
    def search_users(self, query: str, limit: int = 50) -> List[Dict]:
        """Search users by username or email"""
        results = []
        query_lower = query.lower()
        
        for user in self.users.values():
            if (query_lower in user.username.lower() or 
                query_lower in user.email.lower()):
                results.append({
                    "user_id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                    "is_active": user.is_active
                })
                
                if len(results) >= limit:
                    break
        
        return results
    
    def cleanup_expired_tokens(self):
        """Clean up expired tokens from blacklist"""
        # In a production system, you'd implement proper token expiration tracking
        # For now, we'll just clear the blacklist periodically
        if len(self.blacklisted_tokens) > 10000:  # Arbitrary limit
            self.blacklisted_tokens.clear()
    
    def validate_password_strength(self, password: str) -> Dict:
        """Validate password strength"""
        errors = []
        warnings = []
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        elif len(password) < 12:
            warnings.append("Consider using a longer password")
        
        if not any(c.isupper() for c in password):
            warnings.append("Consider using uppercase letters")
        
        if not any(c.islower() for c in password):
            warnings.append("Consider using lowercase letters")
        
        if not any(c.isdigit() for c in password):
            warnings.append("Consider using numbers")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            warnings.append("Consider using special characters")
        
        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "strength_score": max(0, len(password) - 8 + len([w for w in warnings if "Consider" not in w]))
        }