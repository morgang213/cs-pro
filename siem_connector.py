"""
SIEM Connector - Integration with Security Information and Event Management systems
Supports log aggregation, correlation, and threat detection
"""

import json
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from loguru import logger
import re
from collections import defaultdict, Counter
import hashlib
import os

class SIEMConnector:
    def __init__(self):
        # Enhanced security and error handling
        self.max_log_size = 10000  # Maximum characters per log entry
        self.max_logs_per_analysis = 1000  # Maximum logs to process at once
        
        self.log_patterns = {
            'failed_login': [
                r'authentication failure',
                r'failed login',
                r'invalid user',
                r'authentication failed',
                r'login failed'
            ],
            'brute_force': [
                r'repeated failed login attempts',
                r'multiple authentication failures',
                r'brute force attack detected'
            ],
            'privilege_escalation': [
                r'sudo.*root',
                r'privilege escalation',
                r'unauthorized access attempt',
                r'permission denied.*root'
            ],
            'malware': [
                r'virus detected',
                r'malware identified',
                r'trojan found',
                r'suspicious file detected'
            ],
            'network_anomaly': [
                r'unusual network activity',
                r'port scan detected',
                r'ddos attack',
                r'network flooding'
            ],
            'data_exfiltration': [
                r'large data transfer',
                r'unusual file access',
                r'data breach detected',
                r'unauthorized download'
            ],
            'system_compromise': [
                r'rootkit detected',
                r'system file modified',
                r'backdoor access',
                r'unauthorized system change'
            ]
        }
        
        self.severity_levels = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1
        }
        
        self.threat_intelligence = {}
        self.correlation_rules = self._load_correlation_rules()
        
    def _load_correlation_rules(self) -> Dict:
        """Load correlation rules for threat detection"""
        return {
            'brute_force_detection': {
                'pattern': 'failed_login',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': 'HIGH'
            },
            'privilege_escalation_chain': {
                'pattern': ['failed_login', 'privilege_escalation'],
                'threshold': 3,
                'timeframe': 600,  # 10 minutes
                'severity': 'CRITICAL'
            },
            'lateral_movement': {
                'pattern': 'network_anomaly',
                'threshold': 10,
                'timeframe': 900,  # 15 minutes
                'severity': 'HIGH'
            },
            'data_breach_indicators': {
                'pattern': ['privilege_escalation', 'data_exfiltration'],
                'threshold': 2,
                'timeframe': 1800,  # 30 minutes
                'severity': 'CRITICAL'
            }
        }
    
    def analyze_logs(self, log_entries: List[str]) -> Dict[str, Any]:
        """Analyze log entries for security events"""
        results = {
            'total_logs': len(log_entries),
            'security_events': [],
            'threat_indicators': defaultdict(int),
            'severity_distribution': defaultdict(int),
            'timeline': [],
            'correlations': [],
            'recommendations': []
        }
        
        security_events = []
        
        for i, log_entry in enumerate(log_entries):
            event = self._parse_log_entry(log_entry, i)
            if event:
                security_events.append(event)
                results['threat_indicators'][event['category']] += 1
                results['severity_distribution'][event['severity']] += 1
        
        results['security_events'] = security_events
        results['correlations'] = self._correlate_events(security_events)
        results['timeline'] = self._create_timeline(security_events)
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _parse_log_entry(self, log_entry: str, index: int) -> Optional[Dict]:
        """Parse individual log entry for security indicators"""
        for category, patterns in self.log_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_entry, re.IGNORECASE):
                    return {
                        'id': f'event_{index}',
                        'timestamp': datetime.now().isoformat(),
                        'category': category,
                        'severity': self._determine_severity(category),
                        'description': log_entry.strip(),
                        'pattern_matched': pattern,
                        'source': 'log_analysis'
                    }
        return None
    
    def _determine_severity(self, category: str) -> str:
        """Determine severity based on event category"""
        severity_map = {
            'system_compromise': 'CRITICAL',
            'data_exfiltration': 'CRITICAL',
            'privilege_escalation': 'HIGH',
            'brute_force': 'HIGH',
            'malware': 'HIGH',
            'network_anomaly': 'MEDIUM',
            'failed_login': 'LOW'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _correlate_events(self, events: List[Dict]) -> List[Dict]:
        """Correlate security events to identify attack patterns"""
        correlations = []
        
        for rule_name, rule in self.correlation_rules.items():
            correlation = self._apply_correlation_rule(events, rule_name, rule)
            if correlation:
                correlations.append(correlation)
        
        return correlations
    
    def _apply_correlation_rule(self, events: List[Dict], rule_name: str, rule: Dict) -> Optional[Dict]:
        """Apply correlation rule to detect attack patterns"""
        pattern = rule['pattern']
        threshold = rule['threshold']
        timeframe = rule['timeframe']
        
        if isinstance(pattern, str):
            # Single pattern correlation
            matching_events = [e for e in events if e['category'] == pattern]
            if len(matching_events) >= threshold:
                return {
                    'rule': rule_name,
                    'severity': rule['severity'],
                    'event_count': len(matching_events),
                    'description': f'Detected {rule_name}: {len(matching_events)} events matching pattern {pattern}',
                    'events': matching_events[:5]  # First 5 events
                }
        
        elif isinstance(pattern, list):
            # Multi-pattern correlation
            pattern_matches = {}
            for p in pattern:
                pattern_matches[p] = [e for e in events if e['category'] == p]
            
            if all(len(matches) > 0 for matches in pattern_matches.values()):
                total_events = sum(len(matches) for matches in pattern_matches.values())
                if total_events >= threshold:
                    return {
                        'rule': rule_name,
                        'severity': rule['severity'],
                        'event_count': total_events,
                        'description': f'Detected {rule_name}: correlated events across {len(pattern)} categories',
                        'pattern_breakdown': {p: len(matches) for p, matches in pattern_matches.items()}
                    }
        
        return None
    
    def _create_timeline(self, events: List[Dict]) -> List[Dict]:
        """Create timeline of security events"""
        timeline = []
        
        # Group events by hour
        hourly_events = defaultdict(list)
        for event in events:
            # For demo purposes, using current time
            hour = datetime.now().strftime('%Y-%m-%d %H:00:00')
            hourly_events[hour].append(event)
        
        for hour, hour_events in sorted(hourly_events.items()):
            timeline.append({
                'timestamp': hour,
                'event_count': len(hour_events),
                'severity_breakdown': Counter(e['severity'] for e in hour_events),
                'category_breakdown': Counter(e['category'] for e in hour_events)
            })
        
        return timeline
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        threat_indicators = results['threat_indicators']
        correlations = results['correlations']
        
        # Check for high-risk patterns
        if threat_indicators.get('brute_force', 0) > 3:
            recommendations.append('Implement account lockout policies and multi-factor authentication')
        
        if threat_indicators.get('privilege_escalation', 0) > 1:
            recommendations.append('Review and restrict sudo access, implement privilege escalation monitoring')
        
        if threat_indicators.get('data_exfiltration', 0) > 0:
            recommendations.append('Enable data loss prevention (DLP) controls and audit file access')
        
        if threat_indicators.get('network_anomaly', 0) > 5:
            recommendations.append('Deploy network segmentation and intrusion detection systems')
        
        # Check correlations
        critical_correlations = [c for c in correlations if c['severity'] == 'CRITICAL']
        if critical_correlations:
            recommendations.append('Immediate incident response required - critical attack patterns detected')
        
        high_correlations = [c for c in correlations if c['severity'] == 'HIGH']
        if high_correlations:
            recommendations.append('Enhanced monitoring and security controls recommended')
        
        if not recommendations:
            recommendations.append('Continue monitoring - no immediate threats detected')
        
        return recommendations
    
    def generate_siem_report(self, analysis_results: Dict) -> Dict:
        """Generate comprehensive SIEM report"""
        report = {
            'report_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_logs_analyzed': analysis_results['total_logs'],
                'security_events_detected': len(analysis_results['security_events']),
                'correlations_found': len(analysis_results['correlations']),
                'highest_severity': self._get_highest_severity(analysis_results)
            },
            'threat_landscape': analysis_results['threat_indicators'],
            'severity_distribution': analysis_results['severity_distribution'],
            'timeline': analysis_results['timeline'],
            'correlations': analysis_results['correlations'],
            'recommendations': analysis_results['recommendations'],
            'next_steps': self._generate_next_steps(analysis_results)
        }
        
        return report
    
    def _get_highest_severity(self, results: Dict) -> str:
        """Get the highest severity level detected"""
        severity_dist = results['severity_distribution']
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity_dist.get(severity, 0) > 0:
                return severity
        return 'INFO'
    
    def _generate_next_steps(self, results: Dict) -> List[str]:
        """Generate actionable next steps"""
        next_steps = []
        
        correlations = results['correlations']
        critical_correlations = [c for c in correlations if c['severity'] == 'CRITICAL']
        
        if critical_correlations:
            next_steps.extend([
                'Activate incident response team immediately',
                'Isolate affected systems from network',
                'Collect forensic evidence',
                'Notify relevant stakeholders and authorities'
            ])
        
        elif any(c['severity'] == 'HIGH' for c in correlations):
            next_steps.extend([
                'Increase monitoring frequency',
                'Review and update security policies',
                'Conduct security awareness training',
                'Implement additional access controls'
            ])
        
        else:
            next_steps.extend([
                'Continue regular monitoring',
                'Review security logs weekly',
                'Update threat intelligence feeds',
                'Conduct periodic security assessments'
            ])
        
        return next_steps

class ThreatIntelligenceIntegrator:
    def __init__(self):
        self.threat_feeds = {
            'internal_iocs': [],
            'malware_hashes': [],
            'malicious_ips': [],
            'suspicious_domains': [],
            'attack_patterns': []
        }
        
        self.stix_objects = []
        self.mitre_techniques = {}
        
    def add_threat_indicator(self, indicator_type: str, value: str, confidence: int = 50, 
                           source: str = 'manual', description: str = '') -> Dict:
        """Add threat indicator to intelligence database"""
        indicator = {
            'id': hashlib.md5(f"{indicator_type}_{value}".encode()).hexdigest()[:8],
            'type': indicator_type,
            'value': value,
            'confidence': confidence,
            'source': source,
            'description': description,
            'created': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }
        
        if indicator_type in self.threat_feeds:
            self.threat_feeds[indicator_type].append(indicator)
        
        return indicator
    
    def check_indicators(self, data: str) -> List[Dict]:
        """Check data against threat intelligence indicators"""
        matches = []
        
        for feed_type, indicators in self.threat_feeds.items():
            for indicator in indicators:
                if indicator['value'].lower() in data.lower():
                    matches.append({
                        'indicator': indicator,
                        'match_type': feed_type,
                        'confidence': indicator['confidence'],
                        'description': indicator['description']
                    })
        
        return matches
    
    def generate_threat_report(self) -> Dict:
        """Generate threat intelligence report"""
        report = {
            'report_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_indicators': sum(len(feed) for feed in self.threat_feeds.values()),
                'feed_breakdown': {feed: len(indicators) for feed, indicators in self.threat_feeds.items()},
                'high_confidence_indicators': sum(1 for feed in self.threat_feeds.values() 
                                               for indicator in feed if indicator['confidence'] > 80)
            },
            'recent_indicators': self._get_recent_indicators(),
            'threat_landscape': self._analyze_threat_landscape(),
            'recommendations': self._generate_threat_recommendations()
        }
        
        return report
    
    def _get_recent_indicators(self, days: int = 7) -> List[Dict]:
        """Get indicators added in recent days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        recent = []
        
        for feed in self.threat_feeds.values():
            for indicator in feed:
                created_date = datetime.fromisoformat(indicator['created'])
                if created_date > cutoff_date:
                    recent.append(indicator)
        
        return sorted(recent, key=lambda x: x['created'], reverse=True)
    
    def _analyze_threat_landscape(self) -> Dict:
        """Analyze current threat landscape"""
        analysis = {
            'top_threat_types': Counter(),
            'source_distribution': Counter(),
            'confidence_levels': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        for feed_type, indicators in self.threat_feeds.items():
            analysis['top_threat_types'][feed_type] = len(indicators)
            
            for indicator in indicators:
                analysis['source_distribution'][indicator['source']] += 1
                
                if indicator['confidence'] > 70:
                    analysis['confidence_levels']['high'] += 1
                elif indicator['confidence'] > 40:
                    analysis['confidence_levels']['medium'] += 1
                else:
                    analysis['confidence_levels']['low'] += 1
        
        return analysis
    
    def _generate_threat_recommendations(self) -> List[str]:
        """Generate threat intelligence recommendations"""
        recommendations = []
        
        total_indicators = sum(len(feed) for feed in self.threat_feeds.values())
        
        if total_indicators == 0:
            recommendations.append('Initialize threat intelligence feeds with known indicators')
        
        if len(self.threat_feeds['malicious_ips']) < 10:
            recommendations.append('Expand malicious IP address database')
        
        if len(self.threat_feeds['malware_hashes']) < 5:
            recommendations.append('Add known malware hash signatures')
        
        recommendations.extend([
            'Regularly update threat intelligence feeds',
            'Integrate with external threat intelligence sources',
            'Implement automated indicator matching',
            'Establish threat intelligence sharing protocols'
        ])
        
        return recommendations