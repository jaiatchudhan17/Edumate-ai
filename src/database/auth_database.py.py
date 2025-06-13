

import sqlite3
import hashlib
import secrets
import datetime
from pathlib import Path
import os

class AuthDatabase:
    def __init__(self, db_path="edumate_auth.db"):
        """Initialize the authentication database"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create database tables if they don't exist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        full_name VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        profile_picture TEXT,
                        study_level VARCHAR(50),
                        preferred_subjects TEXT
                    )
                ''')
                
                # Remember me tokens table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS remember_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        token_hash VARCHAR(255) NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_used TIMESTAMP,
                        device_info TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # User sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_token VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # User preferences table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_preferences (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        preference_key VARCHAR(100) NOT NULL,
                        preference_value TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        UNIQUE(user_id, preference_key)
                    )
                ''')
                
                # Study progress table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS study_progress (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        topic VARCHAR(200) NOT NULL,
                        progress_type VARCHAR(50) NOT NULL,
                        progress_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                conn.commit()
                print("✅ Database tables created successfully")
                
        except sqlite3.Error as e:
            print(f"❌ Database initialization error: {e}")
            raise
    
    def hash_password(self, password):
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
    
    def verify_password(self, password, password_hash):
        """Verify password against hash"""
        try:
            salt, hash_value = password_hash.split(':')
            return hashlib.sha256((password + salt).encode()).hexdigest() == hash_value
        except ValueError:
            return False
    
    def create_user(self, username, email, password, full_name=None, study_level=None):
        """Create a new user account"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if username or email already exists
                cursor.execute(
                    "SELECT id FROM users WHERE username = ? OR email = ?",
                    (username, email)
                )
                
                if cursor.fetchone():
                    return {"success": False, "message": "Username or email already exists"}
                
                # Hash password
                password_hash = self.hash_password(password)
                
                # Insert new user
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, study_level)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, email, password_hash, full_name, study_level))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                return {
                    "success": True,
                    "message": "Account created successfully",
                    "user_id": user_id
                }
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def authenticate_user(self, username_or_email, password):
        """Authenticate user login"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find user by username or email
                cursor.execute('''
                    SELECT id, username, email, password_hash, full_name, is_active
                    FROM users 
                    WHERE (username = ? OR email = ?) AND is_active = 1
                ''', (username_or_email, username_or_email))
                
                user = cursor.fetchone()
                
                if not user:
                    return {"success": False, "message": "Invalid credentials"}
                
                user_id, username, email, password_hash, full_name, is_active = user
                
                # Verify password
                if not self.verify_password(password, password_hash):
                    return {"success": False, "message": "Invalid credentials"}
                
                # Update last login
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id,)
                )
                conn.commit()
                
                return {
                    "success": True,
                    "user": {
                        "id": user_id,
                        "username": username,
                        "email": email,
                        "full_name": full_name
                    }
                }
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def create_remember_token(self, user_id, device_info=None, days=30):
        """Create a remember me token"""
        try:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            expires_at = datetime.datetime.now() + datetime.timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert remember token
                cursor.execute('''
                    INSERT INTO remember_tokens (user_id, token_hash, expires_at, device_info)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, token_hash, expires_at, device_info))
                
                conn.commit()
                
                return {"success": True, "token": token}
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def verify_remember_token(self, token):
        """Verify remember me token and return user info"""
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find valid token
                cursor.execute('''
                    SELECT rt.user_id, u.username, u.email, u.full_name
                    FROM remember_tokens rt
                    JOIN users u ON rt.user_id = u.id
                    WHERE rt.token_hash = ? AND rt.expires_at > CURRENT_TIMESTAMP
                    AND u.is_active = 1
                ''', (token_hash,))
                
                result = cursor.fetchone()
                
                if not result:
                    return {"success": False, "message": "Invalid or expired token"}
                
                user_id, username, email, full_name = result
                
                # Update last used timestamp
                cursor.execute(
                    "UPDATE remember_tokens SET last_used = CURRENT_TIMESTAMP WHERE token_hash = ?",
                    (token_hash,)
                )
                conn.commit()
                
                return {
                    "success": True,
                    "user": {
                        "id": user_id,
                        "username": username,
                        "email": email,
                        "full_name": full_name
                    }
                }
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def revoke_remember_token(self, token):
        """Revoke a specific remember me token"""
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM remember_tokens WHERE token_hash = ?", (token_hash,))
                conn.commit()
                
                return {"success": True}
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def revoke_all_user_tokens(self, user_id):
        """Revoke all remember me tokens for a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM remember_tokens WHERE user_id = ?", (user_id,))
                conn.commit()
                
                return {"success": True}
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM remember_tokens WHERE expires_at <= CURRENT_TIMESTAMP")
                cursor.execute("DELETE FROM user_sessions WHERE expires_at <= CURRENT_TIMESTAMP")
                conn.commit()
                
                return {"success": True}
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def get_user_profile(self, user_id):
        """Get complete user profile"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT username, email, full_name, created_at, last_login,
                           profile_picture, study_level, preferred_subjects
                    FROM users WHERE id = ? AND is_active = 1
                ''', (user_id,))
                
                user = cursor.fetchone()
                
                if not user:
                    return {"success": False, "message": "User not found"}
                
                return {
                    "success": True,
                    "profile": {
                        "username": user[0],
                        "email": user[1],
                        "full_name": user[2],
                        "created_at": user[3],
                        "last_login": user[4],
                        "profile_picture": user[5],
                        "study_level": user[6],
                        "preferred_subjects": user[7]
                    }
                }
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def update_user_profile(self, user_id, **kwargs):
        """Update user profile information"""
        try:
            allowed_fields = ['full_name', 'study_level', 'preferred_subjects', 'profile_picture']
            updates = {k: v for k, v in kwargs.items() if k in allowed_fields and v is not None}
            
            if not updates:
                return {"success": False, "message": "No valid fields to update"}
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Build dynamic update query
                set_clause = ", ".join([f"{field} = ?" for field in updates.keys()])
                values = list(updates.values()) + [user_id]
                
                cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
                conn.commit()
                
                return {"success": True, "message": "Profile updated successfully"}
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def save_user_preference(self, user_id, key, value):
        """Save user preference"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_preferences (user_id, preference_key, preference_value)
                    VALUES (?, ?, ?)
                ''', (user_id, key, value))
                
                conn.commit()
                return {"success": True}
                
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {e}"}
    
    def get_user_preference(self, user_id, key, default=None):
        """Get user preference"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    "SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = ?",
                    (user_id, key)
                )
                
                result = cursor.fetchone()
                return result[0] if result else default
                
        except sqlite3.Error as e:
            return default