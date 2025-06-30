"""
Comprehensive Security Hardening Module
Addresses critical vulnerabilities and authentication weaknesses
"""

import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
import logging
import jwt
from cryptography.fernet import Fernet
import bcrypt

class SecurityHardening:
    """Enhanced security measures for cybersecurity tool"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.failed_attempts = {}  # Track failed login attempts
        self.session_tokens = {}   # Active session tracking
        self.encryption_key = self._get_encryption_key()
        
    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key for sensitive data"""
        # In production, this should be stored securely (env variable, key management service)
        key = secrets.token_bytes(32)
        return key
    
    def hash_password_secure(self, password: str, salt: Optional[bytes] = None) -> tuple:
        """
        Secure password hashing using bcrypt
        Returns (hashed_password, salt)
        """
        if salt is None:
            salt = bcrypt.gensalt(rounds=12)  # High cost factor for security
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        self.logger.info("Password hashed successfully")
        return hashed, salt
    
    def verify_password_secure(self, password: str, hashed_password: bytes) -> bool:
        """Verify password against secure hash"""
        try:
            result = bcrypt.checkpw(password.encode('utf-8'), hashed_password)
            if result:
                self.logger.info("Password verification successful")
            else:
                self.logger.warning("Password verification failed")
            return result
        except Exception as e:
            self.logger.error(f"Password verification error: {e}")
            return False
    
    def generate_secure_token(self, user_id: str, expires_in_hours: int = 24) -> str:
        """Generate secure JWT token for authentication"""
        try:
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
                'iat': datetime.utcnow(),
                'token_type': 'access'
            }
            
            # In production, use a secure secret key from environment
            secret_key = secrets.token_urlsafe(32)
            token = jwt.encode(payload, secret_key, algorithm='HS256')
            
            # Store token for session management
            self.session_tokens[token] = {
                'user_id': user_id,
                'created': datetime.utcnow(),
                'expires': payload['exp']
            }
            
            self.logger.info(f"Secure token generated for user: {user_id}")
            return token
            
        except Exception as e:
            self.logger.error(f"Token generation error: {e}")
            raise
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate JWT token and return user info if valid"""
        try:
            # Check if token exists in active sessions
            if token not in self.session_tokens:
                self.logger.warning("Token not found in active sessions")
                return None
            
            session_info = self.session_tokens[token]
            
            # Check if token has expired
            if datetime.utcnow() > session_info['expires']:
                self.logger.warning("Token has expired")
                del self.session_tokens[token]
                return None
            
            self.logger.info(f"Token validated for user: {session_info['user_id']}")
            return session_info
            
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            return None
    
    def rate_limit_check(self, identifier: str, max_attempts: int = 5, 
                        window_minutes: int = 15) -> bool:
        """
        Check if request should be rate limited
        Returns True if request is allowed, False if rate limited
        """
        current_time = datetime.utcnow()
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        # Remove old attempts outside the window
        window_start = current_time - timedelta(minutes=window_minutes)
        self.failed_attempts[identifier] = [
            attempt for attempt in self.failed_attempts[identifier]
            if attempt > window_start
        ]
        
        # Check if under limit
        if len(self.failed_attempts[identifier]) >= max_attempts:
            self.logger.warning(f"Rate limit exceeded for: {identifier}")
            return False
        
        return True
    
    def record_failed_attempt(self, identifier: str):
        """Record a failed authentication attempt"""
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append(datetime.utcnow())
        self.logger.warning(f"Failed attempt recorded for: {identifier}")
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data using Fernet symmetric encryption"""
        try:
            f = Fernet(Fernet.generate_key())  # In production, use persistent key
            encrypted = f.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt_sensitive_data(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt sensitive data"""
        try:
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise
    
    def sanitize_input_advanced(self, user_input: str, input_type: str = 'general') -> str:
        """Advanced input sanitization based on input type"""
        if not user_input:
            return ""
        
        # Base sanitization
        sanitized = str(user_input).strip()
        
        if input_type == 'ip':
            # IP address validation
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if not re.match(ip_pattern, sanitized):
                self.logger.warning(f"Invalid IP format: {sanitized}")
                return ""
        
        elif input_type == 'domain':
            # Domain name validation
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, sanitized):
                self.logger.warning(f"Invalid domain format: {sanitized}")
                return ""
        
        elif input_type == 'email':
            # Email validation
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, sanitized):
                self.logger.warning(f"Invalid email format: {sanitized}")
                return ""
        
        elif input_type == 'url':
            # URL validation
            url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
            if not re.match(url_pattern, sanitized, re.IGNORECASE):
                self.logger.warning(f"Invalid URL format: {sanitized}")
                return ""
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '%', ';', '(', ')', '{', '}']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length to prevent buffer overflow attacks
        max_lengths = {
            'general': 1000,
            'ip': 45,
            'domain': 253,
            'email': 320,
            'url': 2048
        }
        
        max_length = max_lengths.get(input_type, 1000)
        sanitized = sanitized[:max_length]
        
        return sanitized
    
    def check_sql_injection_patterns(self, user_input: str) -> bool:
        """
        Check for common SQL injection patterns
        Returns True if potential injection detected
        """
        if not user_input:
            return False
        
        # Common SQL injection patterns
        sql_patterns = [
            r"(\s|^)(union|select|insert|delete|update|drop|create|alter)\s",
            r"(\s|^)(or|and)\s+\d+\s*=\s*\d+",
            r"[\'\"];?\s*(--|/\*)",
            r"[\'\"];\s*(drop|delete|update|insert)",
            r"exec\s*\(",
            r"script\s*:",
            r"javascript\s*:",
            r"vbscript\s*:",
        ]
        
        user_input_lower = user_input.lower()
        
        for pattern in sql_patterns:
            if re.search(pattern, user_input_lower, re.IGNORECASE):
                self.logger.critical(f"SQL injection pattern detected: {pattern} in input: {user_input[:100]}")
                return True
        
        return False
    
    def check_xss_patterns(self, user_input: str) -> bool:
        """
        Check for XSS (Cross-Site Scripting) patterns
        Returns True if potential XSS detected
        """
        if not user_input:
            return False
        
        # Common XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript\s*:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<form[^>]*>",
            r"<img[^>]*onerror",
            r"eval\s*\(",
            r"expression\s*\(",
        ]
        
        user_input_lower = user_input.lower()
        
        for pattern in xss_patterns:
            if re.search(pattern, user_input_lower, re.IGNORECASE):
                self.logger.critical(f"XSS pattern detected: {pattern} in input: {user_input[:100]}")
                return True
        
        return False
    
    def comprehensive_input_validation(self, user_input: str, input_type: str = 'general') -> Dict[str, Any]:
        """
        Comprehensive input validation returning detailed results
        """
        result = {
            'is_valid': True,
            'sanitized_input': '',
            'threats_detected': [],
            'risk_level': 'low'
        }
        
        if not user_input:
            result['sanitized_input'] = ''
            return result
        
        # Check for injection attacks
        if self.check_sql_injection_patterns(user_input):
            result['threats_detected'].append('sql_injection')
            result['risk_level'] = 'critical'
            result['is_valid'] = False
        
        if self.check_xss_patterns(user_input):
            result['threats_detected'].append('xss')
            result['risk_level'] = 'high'
            result['is_valid'] = False
        
        # If threats detected, don't sanitize - reject input
        if result['threats_detected']:
            result['sanitized_input'] = ''
            self.logger.critical(f"Input rejected due to security threats: {result['threats_detected']}")
            return result
        
        # If no threats, sanitize the input
        result['sanitized_input'] = self.sanitize_input_advanced(user_input, input_type)
        
        # Additional risk assessment
        suspicious_indicators = [
            'eval', 'exec', 'system', 'shell', 'cmd', 'powershell',
            'wget', 'curl', 'nc', 'netcat', 'telnet'
        ]
        
        for indicator in suspicious_indicators:
            if indicator.lower() in user_input.lower():
                result['threats_detected'].append('suspicious_command')
                result['risk_level'] = 'medium'
        
        return result
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate security status report"""
        current_time = datetime.utcnow()
        
        # Count recent failed attempts
        recent_failures = 0
        for attempts in self.failed_attempts.values():
            recent_failures += len([
                attempt for attempt in attempts
                if attempt > current_time - timedelta(hours=1)
            ])
        
        # Count active sessions
        active_sessions = len([
            session for session in self.session_tokens.values()
            if session['expires'] > current_time
        ])
        
        report = {
            'timestamp': current_time.isoformat(),
            'security_status': 'active',
            'recent_failed_attempts': recent_failures,
            'active_sessions': active_sessions,
            'rate_limited_ips': len(self.failed_attempts),
            'security_features': [
                'bcrypt_password_hashing',
                'jwt_token_authentication',
                'rate_limiting',
                'input_validation',
                'sql_injection_protection',
                'xss_protection',
                'data_encryption'
            ]
        }
        
        return report