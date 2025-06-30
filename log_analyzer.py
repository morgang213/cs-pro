import re
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import ipaddress

class LogAnalyzer:
    def __init__(self):
        # Common log patterns
        self.patterns = {
            'apache_common': r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)',
            'apache_combined': r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"',
            'nginx': r'(\S+) - \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"',
            'ssh': r'(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) sshd\[\d+\]: (.+)',
            'fail2ban': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (.+?) \[(.+?)\] (.+)',
            'syslog': r'(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) ([^:]+): (.+)',
            'windows_event': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (\d+) (.+)',
            'firewall': r'(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) kernel: (.+) SRC=(\S+) DST=(\S+) (?:.*PROTO=(\S+))?'
        }
        
        # Security indicators
        self.security_indicators = {
            'failed_login': [
                r'failed login', r'authentication failure', r'invalid user',
                r'failed password', r'login incorrect', r'auth failure'
            ],
            'brute_force': [
                r'repeated login failures', r'too many authentication failures',
                r'brute.?force', r'dictionary attack'
            ],
            'sql_injection': [
                r'union.*select', r'drop\s+table', r'or\s+1\s*=\s*1',
                r'script.*alert', r'<script', r'javascript:'
            ],
            'xss_attempt': [
                r'<script.*>', r'javascript:', r'onerror\s*=', r'onload\s*='
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c'
            ],
            'privilege_escalation': [
                r'sudo', r'su\s+root', r'privilege.*escalat', r'root.*access'
            ],
            'malware': [
                r'virus', r'trojan', r'malware', r'backdoor', r'rootkit'
            ],
            'suspicious_activity': [
                r'port.*scan', r'nmap', r'vulnerability.*scan', r'exploit'
            ]
        }
        
        # Common attack IPs and patterns
        self.suspicious_ips = set()
        self.failed_login_threshold = 5
        self.time_window_minutes = 60
    
    def analyze_logs(self, log_content, log_type=None):
        """
        Comprehensive log analysis with optional log type specification
        """
        try:
            lines = log_content.strip().split('\n')
            
            # Parse log entries with log type hint
            parsed_entries = self._parse_log_entries(lines, log_type)
            
            # Analyze for security events
            security_events = self._analyze_security_events(parsed_entries)
            
            # Generate statistics
            stats = self._generate_statistics(parsed_entries, security_events)
            
            # Create timeline
            timeline = self._create_timeline(security_events)
            
            # Identify top threats
            top_threats = self._identify_top_threats(security_events)
            
            # Analyze IP addresses
            ip_analysis = self._analyze_ip_addresses(parsed_entries)
            
            return {
                'total_entries': len(parsed_entries),
                'security_events': len(security_events),
                'events': security_events[:50],  # Limit for display
                'threats': top_threats,
                'top_ips': ip_analysis.get('top_ips', []),
                'failed_logins': stats.get('failed_logins', 0),
                'suspicious_ips': len(self.suspicious_ips),
                'timeline': timeline,
                'statistics': stats,
                'recommendations': self._generate_recommendations(security_events, stats)
            }
            
        except Exception as e:
            return {'error': f'Log analysis failed: {str(e)}'}
    
    def _parse_log_entries(self, lines, log_type_hint=None):
        """
        Parse log entries using various patterns, with optional log type hint
        """
        parsed_entries = []
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            entry = {
                'line_number': line_num,
                'raw_line': line,
                'timestamp': None,
                'ip_address': None,
                'log_type': 'unknown',
                'parsed': False
            }
            
            # If log type hint is provided, try that pattern first
            if log_type_hint and log_type_hint.lower() in self.patterns:
                pattern_key = log_type_hint.lower().replace(' ', '_').replace('/', '_')
                if pattern_key in self.patterns:
                    pattern = self.patterns[pattern_key]
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        entry.update(self._extract_from_match(match, pattern_key))
                        entry['log_type'] = pattern_key
                        entry['parsed'] = True
                        parsed_entries.append(entry)
                        continue
            
            # Try to match against known patterns
            for pattern_name, pattern in self.patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    entry.update(self._extract_from_match(match, pattern_name))
                    entry['log_type'] = pattern_name
                    entry['parsed'] = True
                    break
            
            # Extract IP addresses if not already found
            if not entry.get('ip_address'):
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if ip_match:
                    entry['ip_address'] = ip_match.group()
            
            # Extract timestamp if not already found
            if not entry.get('timestamp'):
                timestamp_patterns = [
                    r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
                    r'\w+ \d{1,2} \d{2}:\d{2}:\d{2}',
                    r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]'
                ]
                
                for pattern in timestamp_patterns:
                    timestamp_match = re.search(pattern, line)
                    if timestamp_match:
                        entry['timestamp'] = timestamp_match.group()
                        break
            
            parsed_entries.append(entry)
        
        return parsed_entries
    
    def _extract_from_match(self, match, log_type):
        """
        Extract relevant information from regex match based on log type
        """
        data = {}
        groups = match.groups()
        
        if log_type in ['apache_common', 'apache_combined', 'nginx']:
            data.update({
                'ip_address': groups[0] if len(groups) > 0 else None,
                'timestamp': groups[1] if len(groups) > 1 else None,
                'method': groups[2] if len(groups) > 2 else None,
                'url': groups[3] if len(groups) > 3 else None,
                'protocol': groups[4] if len(groups) > 4 else None,
                'status_code': groups[5] if len(groups) > 5 else None,
                'response_size': groups[6] if len(groups) > 6 else None
            })
            
            if log_type in ['apache_combined', 'nginx'] and len(groups) > 8:
                data.update({
                    'referer': groups[7],
                    'user_agent': groups[8]
                })
        
        elif log_type == 'ssh':
            data.update({
                'timestamp': groups[0] if len(groups) > 0 else None,
                'hostname': groups[1] if len(groups) > 1 else None,
                'message': groups[2] if len(groups) > 2 else None
            })
        
        elif log_type == 'firewall':
            data.update({
                'timestamp': groups[0] if len(groups) > 0 else None,
                'hostname': groups[1] if len(groups) > 1 else None,
                'message': groups[2] if len(groups) > 2 else None,
                'src_ip': groups[3] if len(groups) > 3 else None,
                'dst_ip': groups[4] if len(groups) > 4 else None,
                'protocol': groups[5] if len(groups) > 5 else None
            })
        
        return data
    
    def _analyze_security_events(self, parsed_entries):
        """
        Analyze parsed entries for security events
        """
        security_events = []
        ip_failed_logins = defaultdict(list)
        
        for entry in parsed_entries:
            line = entry['raw_line'].lower()
            
            # Check for security indicators
            for threat_type, patterns in self.security_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        event = {
                            'type': threat_type,
                            'timestamp': entry.get('timestamp'),
                            'ip_address': entry.get('ip_address'),
                            'line_number': entry['line_number'],
                            'message': entry['raw_line'],
                            'severity': self._calculate_severity(threat_type),
                            'description': self._get_threat_description(threat_type)
                        }
                        security_events.append(event)
                        
                        # Track failed logins for brute force detection
                        if threat_type == 'failed_login' and entry.get('ip_address'):
                            ip_failed_logins[entry['ip_address']].append(entry)
                        
                        break
        
        # Detect brute force attacks
        brute_force_events = self._detect_brute_force(ip_failed_logins)
        security_events.extend(brute_force_events)
        
        return security_events
    
    def _detect_brute_force(self, ip_failed_logins):
        """
        Detect brute force attacks based on failed login patterns
        """
        brute_force_events = []
        
        for ip, failed_attempts in ip_failed_logins.items():
            if len(failed_attempts) >= self.failed_login_threshold:
                self.suspicious_ips.add(ip)
                
                event = {
                    'type': 'brute_force_detected',
                    'ip_address': ip,
                    'timestamp': failed_attempts[-1].get('timestamp'),
                    'severity': 'High',
                    'message': f'Brute force attack detected from {ip}: {len(failed_attempts)} failed attempts',
                    'description': f'Multiple failed login attempts ({len(failed_attempts)}) from single IP',
                    'failed_attempts': len(failed_attempts)
                }
                brute_force_events.append(event)
        
        return brute_force_events
    
    def _calculate_severity(self, threat_type):
        """
        Calculate severity level for different threat types
        """
        severity_map = {
            'failed_login': 'Low',
            'brute_force': 'High',
            'sql_injection': 'Critical',
            'xss_attempt': 'High',
            'directory_traversal': 'High',
            'privilege_escalation': 'Critical',
            'malware': 'Critical',
            'suspicious_activity': 'Medium'
        }
        
        return severity_map.get(threat_type, 'Medium')
    
    def _get_threat_description(self, threat_type):
        """
        Get description for threat types
        """
        descriptions = {
            'failed_login': 'Authentication failure detected',
            'brute_force': 'Brute force attack pattern identified',
            'sql_injection': 'SQL injection attack attempt',
            'xss_attempt': 'Cross-site scripting (XSS) attempt',
            'directory_traversal': 'Directory traversal attack attempt',
            'privilege_escalation': 'Privilege escalation attempt',
            'malware': 'Malware-related activity detected',
            'suspicious_activity': 'Suspicious network activity'
        }
        
        return descriptions.get(threat_type, 'Security event detected')
    
    def _generate_statistics(self, parsed_entries, security_events):
        """
        Generate comprehensive statistics
        """
        stats = {
            'total_lines': len(parsed_entries),
            'parsed_lines': sum(1 for entry in parsed_entries if entry['parsed']),
            'unique_ips': len(set(entry.get('ip_address') for entry in parsed_entries if entry.get('ip_address'))),
            'log_types': Counter(entry['log_type'] for entry in parsed_entries),
            'threat_types': Counter(event['type'] for event in security_events),
            'severity_levels': Counter(event.get('severity', 'Unknown') for event in security_events),
            'failed_logins': sum(1 for event in security_events if event['type'] == 'failed_login'),
            'top_source_ips': Counter(entry.get('ip_address') for entry in parsed_entries if entry.get('ip_address')).most_common(10)
        }
        
        # HTTP status code analysis (for web logs)
        status_codes = []
        for entry in parsed_entries:
            if entry.get('status_code'):
                status_codes.append(entry['status_code'])
        
        if status_codes:
            stats['status_codes'] = Counter(status_codes)
            stats['error_codes'] = Counter(code for code in status_codes if code.startswith(('4', '5')))
        
        return stats
    
    def _create_timeline(self, security_events):
        """
        Create timeline of security events
        """
        timeline = []
        
        # Group events by hour (simplified)
        hourly_events = defaultdict(int)
        
        for event in security_events:
            timestamp = event.get('timestamp')
            if timestamp:
                # Try to parse timestamp (simplified)
                try:
                    # This is a simplified timestamp parsing
                    # In practice, you'd need more robust parsing
                    hour_key = timestamp[:13] if len(timestamp) > 13 else timestamp
                    hourly_events[hour_key] += 1
                except:
                    continue
        
        # Convert to timeline format
        for hour, count in sorted(hourly_events.items()):
            timeline.append({
                'timestamp': hour,
                'count': count
            })
        
        return timeline
    
    def _identify_top_threats(self, security_events):
        """
        Identify top security threats
        """
        threat_analysis = defaultdict(lambda: {
            'count': 0,
            'severity': 'Low',
            'ips': set(),
            'description': ''
        })
        
        for event in security_events:
            threat_type = event['type']
            threat_analysis[threat_type]['count'] += 1
            threat_analysis[threat_type]['severity'] = event.get('severity', 'Low')
            threat_analysis[threat_type]['description'] = event.get('description', '')
            
            if event.get('ip_address'):
                threat_analysis[threat_type]['ips'].add(event['ip_address'])
        
        # Convert to list and sort by count
        top_threats = []
        for threat_type, data in threat_analysis.items():
            top_threats.append({
                'type': threat_type,
                'count': data['count'],
                'severity': data['severity'],
                'unique_ips': len(data['ips']),
                'description': data['description']
            })
        
        # Sort by count descending
        top_threats.sort(key=lambda x: x['count'], reverse=True)
        
        return top_threats[:10]  # Return top 10
    
    def _analyze_ip_addresses(self, parsed_entries):
        """
        Analyze IP address patterns
        """
        ip_analysis = {
            'total_unique_ips': 0,
            'private_ips': 0,
            'public_ips': 0,
            'suspicious_ips': len(self.suspicious_ips),
            'top_countries': {},
            'ip_types': {}
        }
        
        unique_ips = set()
        
        for entry in parsed_entries:
            ip = entry.get('ip_address')
            if ip:
                unique_ips.add(ip)
                
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        ip_analysis['private_ips'] += 1
                    else:
                        ip_analysis['public_ips'] += 1
                except:
                    continue
        
        ip_analysis['total_unique_ips'] = len(unique_ips)
        
        return ip_analysis
    
    def _generate_recommendations(self, security_events, stats):
        """
        Generate security recommendations based on analysis
        """
        recommendations = []
        
        # Check for high number of failed logins
        if stats.get('failed_logins', 0) > 10:
            recommendations.append({
                'priority': 'High',
                'category': 'Authentication',
                'recommendation': 'Implement account lockout policies and consider fail2ban',
                'reason': f"{stats['failed_logins']} failed login attempts detected"
            })
        
        # Check for SQL injection attempts
        sql_injection_count = sum(1 for event in security_events if event['type'] == 'sql_injection')
        if sql_injection_count > 0:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Web Security',
                'recommendation': 'Review and strengthen input validation, use parameterized queries',
                'reason': f"{sql_injection_count} SQL injection attempts detected"
            })
        
        # Check for XSS attempts
        xss_count = sum(1 for event in security_events if event['type'] == 'xss_attempt')
        if xss_count > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Web Security',
                'recommendation': 'Implement Content Security Policy (CSP) and output encoding',
                'reason': f"{xss_count} XSS attempts detected"
            })
        
        # Check for brute force attacks
        if len(self.suspicious_ips) > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Network Security',
                'recommendation': 'Block suspicious IP addresses and implement rate limiting',
                'reason': f"{len(self.suspicious_ips)} suspicious IPs identified"
            })
        
        # General recommendations
        if len(security_events) > 50:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Monitoring',
                'recommendation': 'Enhance security monitoring and alerting systems',
                'reason': f"{len(security_events)} security events detected"
            })
        
        return recommendations
    
    def export_analysis_report(self, analysis_result, format='json'):
        """
        Export analysis results in different formats
        """
        if format == 'json':
            return json.dumps(analysis_result, indent=2, default=str)
        elif format == 'csv':
            # Convert to CSV format (simplified)
            import io
            output = io.StringIO()
            
            # Write security events as CSV
            output.write("Type,Severity,IP Address,Timestamp,Description\n")
            for event in analysis_result.get('security_events', []):
                output.write(f"{event.get('type', '')},{event.get('severity', '')},{event.get('ip_address', '')},{event.get('timestamp', '')},{event.get('description', '')}\n")
            
            return output.getvalue()
        else:
            return str(analysis_result)
