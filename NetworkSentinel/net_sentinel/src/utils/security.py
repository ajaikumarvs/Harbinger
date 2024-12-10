"""
Security Utilities Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides security-related utilities, validation functions,
and secure defaults for network operations.
"""

import logging
import hashlib
import hmac
import secrets
import re
from typing import Optional, List, Dict, Any, Union
import ipaddress
from pathlib import Path
import json
import os
from datetime import datetime
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class SecurityConfig:
    """Security configuration settings."""
    MIN_KEY_LENGTH = 32
    MIN_PASSWORD_LENGTH = 12
    SALT_LENGTH = 32
    ITERATIONS = 100000
    RESTRICTED_NETWORKS = [
        "127.0.0.0/8",    # Loopback
        "169.254.0.0/16", # Link-local
        "0.0.0.0/8",      # Invalid
        "::1/128",        # IPv6 loopback
        "fc00::/7"        # IPv6 unique local
    ]

class SecurityValidator:
    """
    Validates security-related configurations and inputs.
    """
    
    @staticmethod
    def is_safe_target(target: str) -> bool:
        """
        Check if target is safe to scan.
        
        Args:
            target: Target specification
            
        Returns:
            bool indicating if target is safe
        """
        try:
            # Parse target as network or IP
            network = ipaddress.ip_network(target, strict=False)
            
            # Check against restricted networks
            for restricted in SecurityConfig.RESTRICTED_NETWORKS:
                if network.overlaps(ipaddress.ip_network(restricted)):
                    return False
            
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_safe_command(command: str) -> bool:
        """
        Check if shell command is safe.
        
        Args:
            command: Command to validate
            
        Returns:
            bool indicating if command is safe
        """
        # List of dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n']
        return not any(char in command for char in dangerous_chars)
    
    @staticmethod
    def is_strong_password(password: str) -> bool:
        """
        Check if password meets security requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            bool indicating if password is strong
        """
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            return False
        
        # Check for complexity requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        return all([has_upper, has_lower, has_digit, has_special])

class Encryption:
    """
    Handles data encryption and decryption.
    """
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize encryption handler.
        
        Args:
            key: Optional encryption key
        """
        self.key = key or self.generate_key()
        self.fernet = Fernet(self.key)
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Generate secure encryption key.
        
        Returns:
            Generated key
        """
        return base64.urlsafe_b64encode(os.urandom(32))
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt binary data.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
        """
        return self.fernet.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt binary data.
        
        Args:
            encrypted_data: Data to decrypt
            
        Returns:
            Decrypted data
        """
        return self.fernet.decrypt(encrypted_data)
    
    def encrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path]
    ) -> None:
        """
        Encrypt file.
        
        Args:
            input_path: Path to input file
            output_path: Path to save encrypted file
        """
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt_data(data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
    
    def decrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path]
    ) -> None:
        """
        Decrypt file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file
        """
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        
        decrypted = self.decrypt_data(encrypted)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)

class Hashing:
    """
    Provides secure hashing functionality.
    """
    
    @staticmethod
    def hash_password(
        password: str,
        salt: Optional[bytes] = None
    ) -> tuple[bytes, bytes]:
        """
        Securely hash password.
        
        Args:
            password: Password to hash
            salt: Optional salt value
            
        Returns:
            Tuple of (hash, salt)
        """
        if salt is None:
            salt = os.urandom(SecurityConfig.SALT_LENGTH)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SecurityConfig.ITERATIONS,
            backend=default_backend()
        )
        
        hash_value = kdf.derive(password.encode())
        return hash_value, salt
    
    @staticmethod
    def verify_password(
        password: str,
        hash_value: bytes,
        salt: bytes
    ) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Password to verify
            hash_value: Stored hash
            salt: Salt value
            
        Returns:
            bool indicating if password matches
        """
        new_hash, _ = Hashing.hash_password(password, salt)
        return hmac.compare_digest(new_hash, hash_value)
    
    @staticmethod
    def file_hash(
        file_path: Union[str, Path],
        algorithm: str = 'sha256'
    ) -> str:
        """
        Calculate file hash.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm to use
            
        Returns:
            Hex digest of file hash
        """
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

def generate_token(length: int = 32) -> str:
    """
    Generate secure random token.
    
    Args:
        length: Token length
        
    Returns:
        Generated token
    """
    if length < SecurityConfig.MIN_KEY_LENGTH:
        raise ValueError(f"Token length must be at least {SecurityConfig.MIN_KEY_LENGTH}")
    return secrets.token_urlsafe(length)

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage.
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[^\w\-_\.]', '', filename)
    
    # Ensure no double extensions
    parts = sanitized.split('.')
    if len(parts) > 2:
        sanitized = f"{parts[0]}.{parts[-1]}"
    
    return sanitized

def secure_temporary_file(
    prefix: str = 'net_sentinel_',
    suffix: str = '.tmp'
) -> Path:
    """
    Create secure temporary file.
    
    Args:
        prefix: File prefix
        suffix: File suffix
        
    Returns:
        Path to temporary file
    """
    temp_dir = Path(os.getenv('TMPDIR', '/tmp'))
    while True:
        temp_path = temp_dir / f"{prefix}{secrets.token_hex(16)}{suffix}"
        if not temp_path.exists():
            temp_path.touch(mode=0o600)  # Secure permissions
            return temp_path

def is_path_secure(path: Union[str, Path]) -> bool:
    """
    Check if file path is secure.
    
    Args:
        path: Path to check
        
    Returns:
        bool indicating if path is secure
    """
    path = Path(path).resolve()
    try:
        # Check for directory traversal
        if '..' in path.parts:
            return False
        
        # Check permissions if file exists
        if path.exists():
            mode = path.stat().st_mode
            # Ensure file is not world-writable
            if mode & 0o002:
                return False
            
        return True
    except Exception:
        return False