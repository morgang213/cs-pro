"""
Performance Optimization and Security Enhancement Module
Improves SOC platform performance, memory usage, and security
"""

import time
import threading
import functools
import re
from typing import Dict, List, Any, Callable
from datetime import datetime, timedelta
import logging
import gc
import psutil
import json

class PerformanceOptimizer:
    """Performance optimization and monitoring for SOC tools"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.performance_metrics = {}
        self.cache = {}
        self.cache_ttl = {}
        self.max_cache_size = 1000
        
    def timed_execution(self, func: Callable) -> Callable:
        """Decorator to measure function execution time"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                func_name = f"{func.__module__}.{func.__name__}"
                if func_name not in self.performance_metrics:
                    self.performance_metrics[func_name] = []
                
                self.performance_metrics[func_name].append({
                    'execution_time': execution_time,
                    'timestamp': datetime.now().isoformat(),
                    'success': True
                })
                
                # Keep only last 100 measurements per function
                if len(self.performance_metrics[func_name]) > 100:
                    self.performance_metrics[func_name] = self.performance_metrics[func_name][-100:]
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                func_name = f"{func.__module__}.{func.__name__}"
                
                if func_name not in self.performance_metrics:
                    self.performance_metrics[func_name] = []
                
                self.performance_metrics[func_name].append({
                    'execution_time': execution_time,
                    'timestamp': datetime.now().isoformat(),
                    'success': False,
                    'error': str(e)
                })
                
                self.logger.error(f"Function {func_name} failed: {e}")
                raise
                
        return wrapper
    
    def cached_result(self, ttl_seconds: int = 300):
        """Decorator to cache function results with TTL"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Create cache key from function name and arguments
                cache_key = f"{func.__name__}_{hash(str(args) + str(sorted(kwargs.items())))}"
                
                # Check if result is cached and not expired
                if cache_key in self.cache:
                    if cache_key in self.cache_ttl:
                        if time.time() < self.cache_ttl[cache_key]:
                            return self.cache[cache_key]
                        else:
                            # Expired, remove from cache
                            del self.cache[cache_key]
                            del self.cache_ttl[cache_key]
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                
                # Manage cache size
                if len(self.cache) >= self.max_cache_size:
                    # Remove oldest entries
                    oldest_keys = sorted(self.cache_ttl.keys(), 
                                       key=lambda k: self.cache_ttl[k])[:10]
                    for key in oldest_keys:
                        if key in self.cache:
                            del self.cache[key]
                        if key in self.cache_ttl:
                            del self.cache_ttl[key]
                
                self.cache[cache_key] = result
                self.cache_ttl[cache_key] = time.time() + ttl_seconds
                
                return result
                
            return wrapper
        return decorator
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance report for all monitored functions"""
        report = {
            'functions_monitored': len(self.performance_metrics),
            'total_executions': sum(len(metrics) for metrics in self.performance_metrics.values()),
            'cache_size': len(self.cache),
            'cache_hit_potential': 0,
            'function_statistics': {}
        }
        
        for func_name, metrics in self.performance_metrics.items():
            if not metrics:
                continue
                
            execution_times = [m['execution_time'] for m in metrics if m['success']]
            error_count = sum(1 for m in metrics if not m['success'])
            
            if execution_times:
                func_stats = {
                    'total_calls': len(metrics),
                    'successful_calls': len(execution_times),
                    'error_count': error_count,
                    'avg_execution_time': sum(execution_times) / len(execution_times),
                    'min_execution_time': min(execution_times),
                    'max_execution_time': max(execution_times),
                    'error_rate': error_count / len(metrics) if metrics else 0
                }
                
                report['function_statistics'][func_name] = func_stats
        
        return report
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system performance metrics"""
        try:
            memory_info = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            disk_usage = psutil.disk_usage('/')
            
            return {
                'memory': {
                    'total': memory_info.total,
                    'available': memory_info.available,
                    'percent_used': memory_info.percent,
                    'used': memory_info.used
                },
                'cpu': {
                    'percent_used': cpu_percent,
                    'core_count': psutil.cpu_count()
                },
                'disk': {
                    'total': disk_usage.total,
                    'used': disk_usage.used,
                    'free': disk_usage.free,
                    'percent_used': (disk_usage.used / disk_usage.total) * 100
                },
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting system metrics: {e}")
            return {'error': str(e)}
    
    def optimize_memory(self):
        """Perform memory optimization"""
        # Clear expired cache entries
        current_time = time.time()
        expired_keys = [
            key for key, expiry in self.cache_ttl.items()
            if current_time > expiry
        ]
        
        for key in expired_keys:
            if key in self.cache:
                del self.cache[key]
            del self.cache_ttl[key]
        
        # Force garbage collection
        gc.collect()
        
        self.logger.info(f"Memory optimization completed. Removed {len(expired_keys)} expired cache entries.")
    
    def batch_process(self, items: List[Any], batch_size: int = 100, 
                     processor_func: Callable[[List[Any]], Any] = None) -> List[Any]:
        """Process large datasets in batches to prevent memory issues"""
        if not processor_func:
            return items
        
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            try:
                batch_results = processor_func(batch)
                if isinstance(batch_results, list):
                    results.extend(batch_results)
                else:
                    results.append(batch_results)
            except Exception as e:
                self.logger.error(f"Error processing batch {i//batch_size}: {e}")
                continue
        
        return results

class SecurityMonitor:
    """Enhanced security monitoring for SOC platform"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_events = []
        self.suspicious_activities = []
        self.rate_limits = {}
        
    def monitor_input_security(self, input_data: str, source: str) -> Dict[str, Any]:
        """Monitor input for security threats"""
        security_score = 0
        threats_detected = []
        
        # Check for various attack patterns
        attack_patterns = {
            'sql_injection': [
                r'(?i)(union\s+select|drop\s+table|delete\s+from)',
                r'(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)',
                r'(?i)(information_schema|sysobjects)'
            ],
            'xss': [
                r'(?i)<script[^>]*>',
                r'(?i)javascript:',
                r'(?i)on\w+\s*='
            ],
            'command_injection': [
                r'(?i)(;|&&|\|\|)',
                r'(?i)(rm\s+-rf|del\s+/)',
                r'(?i)(wget|curl|nc\s)'
            ]
        }
        
        for threat_type, patterns in attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, input_data):
                    threats_detected.append(threat_type)
                    security_score += 10
                    break
        
        # Check for suspicious characteristics
        if len(input_data) > 1000:
            security_score += 2
            threats_detected.append('oversized_input')
        
        if input_data.count('%') > 10:  # Potential encoding attack
            security_score += 5
            threats_detected.append('excessive_encoding')
        
        # Log security event if threats detected
        if threats_detected:
            security_event = {
                'timestamp': datetime.now().isoformat(),
                'source': source,
                'threats': threats_detected,
                'security_score': security_score,
                'input_sample': input_data[:100]  # Store only first 100 chars
            }
            
            self.security_events.append(security_event)
            self.logger.warning(f"Security threats detected from {source}: {threats_detected}")
        
        return {
            'is_safe': security_score < 5,
            'security_score': security_score,
            'threats_detected': threats_detected
        }
    
    def check_rate_limit(self, identifier: str, max_requests: int = 100, 
                        window_minutes: int = 60) -> bool:
        """Check if request should be rate limited"""
        current_time = datetime.now()
        
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []
        
        # Remove old requests outside the window
        window_start = current_time - timedelta(minutes=window_minutes)
        self.rate_limits[identifier] = [
            req_time for req_time in self.rate_limits[identifier]
            if req_time > window_start
        ]
        
        # Check if under limit
        if len(self.rate_limits[identifier]) >= max_requests:
            self.logger.warning(f"Rate limit exceeded for: {identifier}")
            return False
        
        # Add current request
        self.rate_limits[identifier].append(current_time)
        return True
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security monitoring summary"""
        recent_events = [
            event for event in self.security_events
            if datetime.fromisoformat(event['timestamp']) > 
               datetime.now() - timedelta(hours=24)
        ]
        
        threat_counts = {}
        for event in recent_events:
            for threat in event['threats']:
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        return {
            'total_security_events': len(recent_events),
            'threat_breakdown': threat_counts,
            'active_rate_limits': len([
                id for id, requests in self.rate_limits.items()
                if len(requests) > 0
            ]),
            'high_risk_events': len([
                event for event in recent_events
                if event['security_score'] >= 20
            ])
        }

class DataValidator:
    """Enhanced data validation for SOC tools"""
    
    @staticmethod
    def validate_ip_address(ip_str: str) -> Dict[str, Any]:
        """Validate IP address with enhanced checks"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_str.strip())
            
            return {
                'is_valid': True,
                'ip_type': 'IPv4' if ip.version == 4 else 'IPv6',
                'is_private': ip.is_private,
                'is_reserved': ip.is_reserved,
                'is_multicast': ip.is_multicast,
                'is_loopback': ip.is_loopback
            }
        except ValueError as e:
            return {
                'is_valid': False,
                'error': str(e)
            }
    
    @staticmethod
    def validate_domain(domain_str: str) -> Dict[str, Any]:
        """Validate domain name with security checks"""
        domain = domain_str.strip().lower()
        
        # Basic format validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, domain):
            return {'is_valid': False, 'error': 'Invalid domain format'}
        
        # Check for suspicious characteristics
        warnings = []
        
        if len(domain) > 253:
            warnings.append('Domain name too long')
        
        if domain.count('.') > 10:
            warnings.append('Excessive subdomains')
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                warnings.append(f'Suspicious TLD: {tld}')
        
        return {
            'is_valid': True,
            'domain': domain,
            'warnings': warnings,
            'risk_score': len(warnings) * 2
        }
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize input string for safe processing"""
        if not input_str:
            return ""
        
        # Truncate if too long
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        
        # Remove control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in '\t\n\r')
        
        # Escape potentially dangerous characters
        sanitized = sanitized.replace('<', '&lt;')
        sanitized = sanitized.replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        
        return sanitized.strip()

# Global instances for use across SOC platform
performance_optimizer = PerformanceOptimizer()
security_monitor = SecurityMonitor()
data_validator = DataValidator()