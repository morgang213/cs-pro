"""
Advanced Security Enhancements for SOC Platform
Enhanced input validation, rate limiting, and security monitoring
"""

import re
import ipaddress
import hashlib
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse
import dns.resolver
import validators

class AdvancedSecurityValidator:
    """Advanced security validation for SOC tools"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_patterns = self._load_threat_patterns()
        self.request_tracker = {}
        
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load comprehensive threat detection patterns"""
        return {
            'sql_injection': [
                r"(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table)",
                r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
                r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
                r"(?i)(load_file\s*\(|into\s+outfile|into\s+dumpfile)",
                r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
                r"(?i)(information_schema|sysobjects|sys\.tables)"
            ],
            'xss_injection': [
                r"(?i)<script[^>]*>.*?</script>",
                r"(?i)javascript:",
                r"(?i)on\w+\s*=",
                r"(?i)<iframe[^>]*>",
                r"(?i)eval\s*\(",
                r"(?i)document\.(cookie|domain|location)",
                r"(?i)<object[^>]*>",
                r"(?i)<embed[^>]*>",
                r"(?i)vbscript:",
                r"(?i)expression\s*\("
            ],
            'command_injection': [
                r"(?i)(;|&&|\|\||\|)",
                r"(?i)(rm\s+-rf|del\s+/|format\s+c:)",
                r"(?i)(wget|curl|nc\s|netcat)",
                r"(?i)(powershell|cmd\.exe|/bin/sh)",
                r"(?i)(\$\(.*\)|`.*`)",
                r"(?i)(chmod|chown|sudo|su\s)",
                r"(?i)(cat\s+/etc|ls\s+/etc|find\s+/)",
                r"(?i)(ping\s+-c|nslookup|dig\s)"
            ],
            'path_traversal': [
                r"\.\.\/",
                r"\.\.\\"
            ],
            'ldap_injection': [
                r"(?i)(\*|\)|\(|\||&)",
                r"(?i)(objectclass=|cn=|uid=)"
            ]
        }
    
    def validate_input_secure(self, input_data: str, data_type: str = 'generic', 
                             max_length: int = 1000) -> Dict[str, Any]:
        """Enhanced input validation with threat detection"""
        validation_result = {
            'is_valid': True,
            'sanitized_data': input_data,
            'threats_detected': [],
            'risk_score': 0
        }
        
        if not input_data or len(input_data.strip()) == 0:
            validation_result['is_valid'] = False
            validation_result['threats_detected'].append("Empty input")
            return validation_result
        
        # Length validation
        if len(input_data) > max_length:
            validation_result['is_valid'] = False
            validation_result['threats_detected'].append(f"Input exceeds {max_length} characters")
            return validation_result
        
        # Threat pattern detection
        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, input_data):
                    validation_result['threats_detected'].append(threat_type)
                    validation_result['risk_score'] += 10
                    validation_result['is_valid'] = False
        
        # Type-specific validation
        if data_type == 'ip_address':
            validation_result = self._validate_ip_address(input_data, validation_result)
        elif data_type == 'domain':
            validation_result = self._validate_domain(input_data, validation_result)
        elif data_type == 'email':
            validation_result = self._validate_email(input_data, validation_result)
        elif data_type == 'url':
            validation_result = self._validate_url(input_data, validation_result)
        elif data_type == 'hash':
            validation_result = self._validate_hash(input_data, validation_result)
        
        # Sanitize input if valid
        if validation_result['is_valid']:
            validation_result['sanitized_data'] = self._sanitize_input(input_data)
        
        return validation_result
    
    def _validate_ip_address(self, ip_str: str, result: Dict) -> Dict:
        """Validate IP address format and check for suspicious IPs"""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            
            # Check for private/reserved IPs in certain contexts
            if ip.is_private:
                result['threats_detected'].append("private_ip")
            if ip.is_reserved:
                result['threats_detected'].append("reserved_ip")
            if ip.is_loopback:
                result['threats_detected'].append("loopback_ip")
                
        except ValueError:
            result['is_valid'] = False
            result['threats_detected'].append("invalid_ip_format")
            result['risk_score'] += 5
        
        return result
    
    def _validate_domain(self, domain_str: str, result: Dict) -> Dict:
        """Validate domain name format and check for suspicious domains"""
        domain = domain_str.strip().lower()
        
        # Basic format validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain):
            result['is_valid'] = False
            result['threats_detected'].append("invalid_domain_format")
            result['risk_score'] += 5
            return result
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                result['threats_detected'].append("suspicious_tld")
                result['risk_score'] += 3
        
        # Check for domain generation algorithm patterns
        if self._detect_dga_domain(domain):
            result['threats_detected'].append("potential_dga")
            result['risk_score'] += 7
        
        return result
    
    def _validate_email(self, email_str: str, result: Dict) -> Dict:
        """Validate email address format"""
        if not validators.email(email_str.strip()):
            result['is_valid'] = False
            result['threats_detected'].append("invalid_email_format")
            result['risk_score'] += 5
        
        return result
    
    def _validate_url(self, url_str: str, result: Dict) -> Dict:
        """Validate URL format and check for suspicious URLs"""
        try:
            parsed = urlparse(url_str.strip())
            
            if not parsed.scheme or not parsed.netloc:
                result['is_valid'] = False
                result['threats_detected'].append("invalid_url_format")
                result['risk_score'] += 5
                return result
            
            # Check for suspicious schemes
            if parsed.scheme not in ['http', 'https', 'ftp']:
                result['threats_detected'].append("suspicious_url_scheme")
                result['risk_score'] += 3
            
            # Check for IP addresses in URLs (often suspicious)
            try:
                if parsed.hostname:
                    ipaddress.ip_address(parsed.hostname)
                    result['threats_detected'].append("ip_in_url")
                    result['risk_score'] += 2
            except:
                pass
            
        except Exception:
            result['is_valid'] = False
            result['threats_detected'].append("url_parsing_error")
            result['risk_score'] += 5
        
        return result
    
    def _validate_hash(self, hash_str: str, result: Dict) -> Dict:
        """Validate hash format (MD5, SHA1, SHA256, etc.)"""
        hash_patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$',
            'sha512': r'^[a-fA-F0-9]{128}$'
        }
        
        hash_clean = hash_str.strip()
        valid_hash = False
        
        for hash_type, pattern in hash_patterns.items():
            if re.match(pattern, hash_clean):
                valid_hash = True
                break
        
        if not valid_hash:
            result['is_valid'] = False
            result['threats_detected'].append("invalid_hash_format")
            result['risk_score'] += 5
        
        return result
    
    def _detect_dga_domain(self, domain: str) -> bool:
        """Detect potential Domain Generation Algorithm (DGA) domains"""
        # Simple heuristics for DGA detection
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        subdomain = parts[0]
        
        # Check for random-looking strings
        if len(subdomain) > 12:
            vowels = sum(1 for c in subdomain if c in 'aeiou')
            consonants = len(subdomain) - vowels
            
            # High consonant to vowel ratio
            if consonants > vowels * 3:
                return True
        
        # Check for entropy (randomness)
        entropy = self._calculate_entropy(subdomain)
        if entropy > 3.5:  # High entropy threshold
            return True
        
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        frequency = {}
        for char in text:
            frequency[char] = frequency.get(char, 0) + 1
        
        entropy = 0
        text_len = len(text)
        for count in frequency.values():
            probability = count / text_len
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _sanitize_input(self, input_str: str) -> str:
        """Sanitize input by removing/escaping dangerous characters"""
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        # Escape HTML entities
        html_escape_table = {
            '&': '&amp;',
            '"': '&quot;',
            "'": '&#x27;',
            '>': '&gt;',
            '<': '&lt;',
        }
        
        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized.strip()
    
    def rate_limit_check(self, identifier: str, max_requests: int = 100, 
                        window_seconds: int = 3600) -> bool:
        """Advanced rate limiting with sliding window"""
        current_time = time.time()
        
        if identifier not in self.request_tracker:
            self.request_tracker[identifier] = []
        
        # Remove old requests outside the window
        window_start = current_time - window_seconds
        self.request_tracker[identifier] = [
            req_time for req_time in self.request_tracker[identifier]
            if req_time > window_start
        ]
        
        # Check if under limit
        if len(self.request_tracker[identifier]) >= max_requests:
            self.logger.warning(f"Rate limit exceeded for: {identifier}")
            return False
        
        # Add current request
        self.request_tracker[identifier].append(current_time)
        return True
    
    def detect_anomalous_behavior(self, user_activity: List[Dict]) -> Dict[str, Any]:
        """Detect anomalous user behavior patterns"""
        anomaly_score = 0
        anomalies_detected = []
        
        if not user_activity:
            return {'anomaly_score': 0, 'anomalies': []}
        
        # Check for rapid requests
        timestamps = [activity.get('timestamp', time.time()) for activity in user_activity]
        timestamps.sort()
        
        rapid_requests = 0
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i-1] < 1:  # Less than 1 second between requests
                rapid_requests += 1
        
        if rapid_requests > 10:
            anomalies_detected.append("rapid_requests")
            anomaly_score += 5
        
        # Check for unusual activity patterns
        activity_types = [activity.get('type', 'unknown') for activity in user_activity]
        unique_activities = len(set(activity_types))
        
        if unique_activities > 10:  # Using many different tools rapidly
            anomalies_detected.append("diverse_tool_usage")
            anomaly_score += 3
        
        # Check for suspicious input patterns
        suspicious_inputs = 0
        for activity in user_activity:
            if 'input' in activity:
                validation = self.validate_input_secure(str(activity['input']))
                if validation['risk_score'] > 5:
                    suspicious_inputs += 1
        
        if suspicious_inputs > 3:
            anomalies_detected.append("suspicious_inputs")
            anomaly_score += 7
        
        return {
            'anomaly_score': anomaly_score,
            'anomalies': anomalies_detected,
            'risk_level': self._get_risk_level(anomaly_score)
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Convert anomaly score to risk level"""
        if score >= 15:
            return "HIGH"
        elif score >= 8:
            return "MEDIUM"
        elif score >= 3:
            return "LOW"
        else:
            return "MINIMAL"

class SecureLogger:
    """Secure logging for SOC platform with threat detection"""
    
    def __init__(self):
        self.logger = logging.getLogger('SOC_Security')
        self.security_events = []
        
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          severity: str = 'INFO'):
        """Log security events with structured data"""
        security_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details,
            'event_id': hashlib.md5(f"{event_type}_{time.time()}".encode()).hexdigest()[:8]
        }
        
        self.security_events.append(security_event)
        
        # Log to standard logger
        self.logger.log(
            getattr(logging, severity.upper(), logging.INFO),
            f"Security Event: {event_type} - {details}"
        )
        
        # Keep only last 1000 events in memory
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
    
    def get_recent_security_events(self, hours: int = 24) -> List[Dict]:
        """Get security events from last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        return [
            event for event in self.security_events
            if event['timestamp'] >= cutoff_str
        ]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get summary of security events"""
        recent_events = self.get_recent_security_events()
        
        summary = {
            'total_events': len(recent_events),
            'by_severity': {},
            'by_type': {},
            'critical_events': []
        }
        
        for event in recent_events:
            severity = event['severity']
            event_type = event['event_type']
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][event_type] = summary['by_type'].get(event_type, 0) + 1
            
            if severity in ['CRITICAL', 'ERROR']:
                summary['critical_events'].append(event)
        
        return summary

# Global instances for use across SOC platform
security_validator = AdvancedSecurityValidator()
security_logger = SecureLogger()