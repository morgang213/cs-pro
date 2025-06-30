"""
Secure Middleware for Streamlit Application
Provides comprehensive input validation and security checks
"""

import streamlit as st
import functools
import logging
from typing import Any, Callable, Dict, Optional
from .security_hardening import SecurityHardening

class SecureMiddleware:
    """Middleware for securing Streamlit inputs and operations"""
    
    def __init__(self):
        self.security = SecurityHardening()
        self.logger = logging.getLogger(__name__)
        
        # Initialize session state for security tracking
        if 'security_violations' not in st.session_state:
            st.session_state.security_violations = []
        
        if 'security_alerts' not in st.session_state:
            st.session_state.security_alerts = []
            
        if 'failed_attempts' not in st.session_state:
            st.session_state.failed_attempts = {}
    
    def secure_input_decorator(self, input_type: str = 'general'):
        """Decorator to secure user inputs"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Check for user inputs in kwargs
                for key, value in kwargs.items():
                    if isinstance(value, str) and value:
                        validation_result = self.security.comprehensive_input_validation(value, input_type)
                        
                        if not validation_result['is_valid']:
                            # Log security violation
                            violation = {
                                'timestamp': st.session_state.get('current_time', 'unknown'),
                                'function': func.__name__,
                                'input_type': input_type,
                                'threats': validation_result['threats_detected'],
                                'risk_level': validation_result['risk_level']
                            }
                            
                            st.session_state.security_violations.append(violation)
                            
                            # Show security alert to user
                            st.error(f"🚨 Security Alert: Invalid input detected. Input has been blocked for security reasons.")
                            st.warning(f"Detected threats: {', '.join(validation_result['threats_detected'])}")
                            
                            return None
                        
                        # Replace with sanitized input
                        kwargs[key] = validation_result['sanitized_input']
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def validate_ip_input(self, ip_address: str) -> Optional[str]:
        """Validate IP address input with security checks"""
        if not ip_address:
            return None
        
        validation_result = self.security.comprehensive_input_validation(ip_address, 'ip')
        
        if not validation_result['is_valid']:
            st.error("🚨 Invalid IP address format detected")
            return None
        
        return validation_result['sanitized_input']
    
    def validate_domain_input(self, domain: str) -> Optional[str]:
        """Validate domain input with security checks"""
        if not domain:
            return None
        
        validation_result = self.security.comprehensive_input_validation(domain, 'domain')
        
        if not validation_result['is_valid']:
            st.error("🚨 Invalid domain format detected")
            return None
        
        return validation_result['sanitized_input']
    
    def validate_url_input(self, url: str) -> Optional[str]:
        """Validate URL input with security checks"""
        if not url:
            return None
        
        validation_result = self.security.comprehensive_input_validation(url, 'url')
        
        if not validation_result['is_valid']:
            st.error("🚨 Invalid or potentially malicious URL detected")
            return None
        
        return validation_result['sanitized_input']
    
    def validate_email_input(self, email: str) -> Optional[str]:
        """Validate email input with security checks"""
        if not email:
            return None
        
        validation_result = self.security.comprehensive_input_validation(email, 'email')
        
        if not validation_result['is_valid']:
            st.error("🚨 Invalid email format detected")
            return None
        
        return validation_result['sanitized_input']
    
    def validate_general_input(self, user_input: str, max_length: int = 1000) -> Optional[str]:
        """Validate general text input with security checks"""
        if not user_input:
            return None
        
        # Check length first
        if len(user_input) > max_length:
            st.error(f"🚨 Input too long. Maximum {max_length} characters allowed.")
            return None
        
        validation_result = self.security.comprehensive_input_validation(user_input, 'general')
        
        if not validation_result['is_valid']:
            st.error("🚨 Potentially malicious input detected and blocked")
            if validation_result['threats_detected']:
                st.warning(f"Threats detected: {', '.join(validation_result['threats_detected'])}")
            return None
        
        return validation_result['sanitized_input']
    
    def rate_limit_check(self, identifier: str) -> bool:
        """Check rate limiting for operations"""
        client_ip = st.session_state.get('client_ip', 'unknown')
        full_identifier = f"{client_ip}_{identifier}"
        
        if not self.security.rate_limit_check(full_identifier):
            st.error("🚨 Rate limit exceeded. Please wait before trying again.")
            return False
        
        return True
    
    def record_security_event(self, event_type: str, details: Dict[str, Any]):
        """Record security events for monitoring"""
        event = {
            'timestamp': st.session_state.get('current_time', 'unknown'),
            'type': event_type,
            'details': details,
            'session_id': st.session_state.get('session_id', 'unknown')
        }
        
        st.session_state.security_alerts.append(event)
        self.logger.warning(f"Security event recorded: {event_type}")
    
    def show_security_status(self):
        """Display security status in sidebar"""
        # Initialize session state variables if they don't exist
        if 'security_violations' not in st.session_state:
            st.session_state.security_violations = []
        if 'security_alerts' not in st.session_state:
            st.session_state.security_alerts = []
        if 'failed_attempts' not in st.session_state:
            st.session_state.failed_attempts = {}
            
        with st.sidebar:
            st.markdown("---")
            st.subheader("🔒 Security Status")
            
            # Show violation count
            violation_count = len(st.session_state.security_violations)
            if violation_count > 0:
                st.error(f"⚠️ {violation_count} security violations detected")
            else:
                st.success("✅ No security violations")
            
            # Show recent alerts
            alert_count = len(st.session_state.security_alerts)
            if alert_count > 0:
                st.info(f"📊 {alert_count} security events logged")
            
            # Security features indicator
            with st.expander("🛡️ Active Security Features"):
                st.write("""
                ✅ Input validation and sanitization
                ✅ SQL injection protection
                ✅ XSS attack prevention
                ✅ Rate limiting protection
                ✅ Secure password hashing
                ✅ Data encryption for sensitive information
                """)
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        return {
            'security_violations': st.session_state.security_violations,
            'security_alerts': st.session_state.security_alerts,
            'hardening_report': self.security.generate_security_report()
        }

# Global middleware instance
secure_middleware = SecureMiddleware()

# Convenience functions for common validations
def secure_text_input(label: str, value: str = "", max_chars: int = None, 
                     input_type: str = 'general', key: Optional[str] = None) -> Optional[str]:
    """Secure text input with validation"""
    user_input = st.text_input(label, value=value, max_chars=max_chars, key=key)
    
    if user_input:
        if input_type == 'ip':
            return secure_middleware.validate_ip_input(user_input)
        elif input_type == 'domain':
            return secure_middleware.validate_domain_input(user_input)
        elif input_type == 'url':
            return secure_middleware.validate_url_input(user_input)
        elif input_type == 'email':
            return secure_middleware.validate_email_input(user_input)
        else:
            return secure_middleware.validate_general_input(user_input, max_chars or 1000)
    
    return user_input

def secure_text_area(label: str, value: str = "", height: int = None, 
                    max_chars: int = None, key: Optional[str] = None) -> Optional[str]:
    """Secure text area with validation"""
    user_input = st.text_area(label, value=value, height=height, max_chars=max_chars, key=key)
    
    if user_input:
        return secure_middleware.validate_general_input(user_input, max_chars or 5000)
    
    return user_input

def secure_file_uploader(label: str, type: Optional[list] = None, 
                        key: Optional[str] = None) -> Any:
    """Secure file uploader with validation"""
    uploaded_file = st.file_uploader(label, type=type, key=key)
    
    if uploaded_file is not None:
        # Basic file validation
        if uploaded_file.size > 10 * 1024 * 1024:  # 10MB limit
            st.error("🚨 File too large. Maximum 10MB allowed.")
            return None
        
        # Check file extension
        if type and uploaded_file.name:
            file_ext = uploaded_file.name.split('.')[-1].lower()
            if file_ext not in [t.lower() for t in type]:
                st.error(f"🚨 Invalid file type. Allowed types: {', '.join(type)}")
                return None
        
        secure_middleware.record_security_event('file_upload', {
            'filename': uploaded_file.name,
            'size': uploaded_file.size,
            'type': uploaded_file.type
        })
    
    return uploaded_file