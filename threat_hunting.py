"""
Advanced Threat Hunting Platform
Behavioral analytics, anomaly detection, and proactive threat hunting capabilities
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import re
import hashlib
import statistics
from loguru import logger
import math

class ThreatHunter:
    def __init__(self):
        self.hunting_rules = self._load_hunting_rules()
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        self.behavioral_patterns = {}
        self.ioc_patterns = self._load_ioc_patterns()
        
    def _load_hunting_rules(self) -> Dict:
        """Load threat hunting rules and signatures"""
        return {
            'living_off_the_land': {
                'description': 'Detect legitimate tools used maliciously',
                'indicators': [
                    'powershell.*-encoded',
                    'wmic.*process.*create',
                    'net.*user.*add',
                    'reg.*add.*run',
                    'schtasks.*create',
                    'bitsadmin.*transfer',
                    'certutil.*-decode',
                    'rundll32.*javascript',
                    'mshta.*http'
                ],
                'severity': 'HIGH',
                'mitre_technique': 'T1059'
            },
            'lateral_movement': {
                'description': 'Detect lateral movement activities',
                'indicators': [
                    'psexec.*-s',
                    'winrm.*invoke-command',
                    'wmiexec.*remote',
                    'rdp.*multiple.*connections',
                    'smb.*admin.*share',
                    'net.*use.*admin',
                    'sc.*create.*remote'
                ],
                'severity': 'HIGH',
                'mitre_technique': 'T1021'
            },
            'persistence_mechanisms': {
                'description': 'Detect persistence establishment',
                'indicators': [
                    'startup.*folder.*write',
                    'registry.*run.*key',
                    'service.*creation',
                    'task.*scheduler.*create',
                    'wmi.*event.*subscription',
                    'dll.*hijacking',
                    'autostart.*registry'
                ],
                'severity': 'MEDIUM',
                'mitre_technique': 'T1547'
            },
            'data_staging': {
                'description': 'Detect data collection and staging',
                'indicators': [
                    'compress.*archive.*create',
                    'copy.*sensitive.*files',
                    'database.*dump',
                    'email.*export',
                    'browser.*credential.*access',
                    'temp.*folder.*large.*files',
                    'usb.*device.*write'
                ],
                'severity': 'HIGH',
                'mitre_technique': 'T1074'
            },
            'evasion_techniques': {
                'description': 'Detect evasion and defense evasion',
                'indicators': [
                    'process.*hollowing',
                    'dll.*injection',
                    'reflective.*loading',
                    'obfuscated.*code',
                    'anti.*debug',
                    'vm.*detection',
                    'log.*deletion',
                    'event.*log.*clear'
                ],
                'severity': 'HIGH',
                'mitre_technique': 'T1055'
            },
            'command_and_control': {
                'description': 'Detect C2 communications',
                'indicators': [
                    'beacon.*regular.*intervals',
                    'dns.*tunneling',
                    'http.*post.*base64',
                    'encrypted.*traffic.*unusual',
                    'tor.*proxy.*usage',
                    'domain.*generation.*algorithm',
                    'covert.*channel'
                ],
                'severity': 'CRITICAL',
                'mitre_technique': 'T1071'
            }
        }
    
    def _load_ioc_patterns(self) -> Dict:
        """Load Indicators of Compromise patterns"""
        return {
            'file_hashes': {
                'md5': r'\b[a-f0-9]{32}\b',
                'sha1': r'\b[a-f0-9]{40}\b',
                'sha256': r'\b[a-f0-9]{64}\b'
            },
            'network_indicators': {
                'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
                'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            },
            'file_indicators': {
                'file_path': r'[A-Za-z]:\\[^<>:"|?*\r\n]+',
                'registry_key': r'HKEY_[A-Z_]+\\[^\r\n]+',
                'mutex': r'Global\\[A-Za-z0-9_-]+',
                'service_name': r'[A-Za-z0-9_-]+\.exe'
            }
        }
    
    def hunt_threats(self, data_sources: Dict[str, List[str]]) -> Dict[str, Any]:
        """Perform comprehensive threat hunting across data sources"""
        results = {
            'hunt_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'timestamp': datetime.now().isoformat(),
            'data_sources': list(data_sources.keys()),
            'total_events': sum(len(events) for events in data_sources.values()),
            'hunting_results': {},
            'anomalies': {},
            'ioc_extractions': {},
            'behavioral_analysis': {},
            'recommendations': []
        }
        
        # Apply hunting rules
        for source_name, events in data_sources.items():
            hunting_matches = self._apply_hunting_rules(events, source_name)
            results['hunting_results'][source_name] = hunting_matches
            
            # Detect anomalies
            anomalies = self._detect_anomalies(events, source_name)
            results['anomalies'][source_name] = anomalies
            
            # Extract IOCs
            iocs = self._extract_iocs(events)
            results['ioc_extractions'][source_name] = iocs
            
            # Behavioral analysis
            behavior = self._analyze_behavior(events, source_name)
            results['behavioral_analysis'][source_name] = behavior
        
        # Generate recommendations
        results['recommendations'] = self._generate_hunting_recommendations(results)
        
        return results
    
    def _apply_hunting_rules(self, events: List[str], source_name: str) -> List[Dict]:
        """Apply threat hunting rules to events"""
        matches = []
        
        for rule_name, rule in self.hunting_rules.items():
            rule_matches = []
            
            for event in events:
                for indicator in rule['indicators']:
                    if re.search(indicator, event, re.IGNORECASE):
                        rule_matches.append({
                            'event': event,
                            'indicator': indicator,
                            'rule': rule_name,
                            'severity': rule['severity'],
                            'mitre_technique': rule['mitre_technique'],
                            'description': rule['description']
                        })
            
            if rule_matches:
                matches.append({
                    'rule_name': rule_name,
                    'matches': rule_matches,
                    'match_count': len(rule_matches),
                    'severity': rule['severity']
                })
        
        return matches
    
    def _detect_anomalies(self, events: List[str], source_name: str) -> Dict[str, Any]:
        """Detect statistical anomalies in event patterns"""
        anomalies = {
            'volume_anomalies': [],
            'pattern_anomalies': [],
            'timing_anomalies': [],
            'content_anomalies': []
        }
        
        # Volume anomaly detection
        baseline_volume = self.baseline_metrics.get(f'{source_name}_volume', len(events))
        if abs(len(events) - baseline_volume) > (baseline_volume * 0.3):
            anomalies['volume_anomalies'].append({
                'type': 'volume_spike' if len(events) > baseline_volume else 'volume_drop',
                'current_volume': len(events),
                'baseline_volume': baseline_volume,
                'deviation_percentage': ((len(events) - baseline_volume) / baseline_volume) * 100
            })
        
        # Pattern anomaly detection
        event_patterns = Counter()
        for event in events:
            # Extract patterns (first 20 characters)
            pattern = event[:20].strip()
            event_patterns[pattern] += 1
        
        # Detect unusual patterns
        total_events = len(events)
        for pattern, count in event_patterns.items():
            frequency = count / total_events
            if frequency > 0.1 and count > 5:  # Pattern appears in >10% of events
                anomalies['pattern_anomalies'].append({
                    'pattern': pattern,
                    'frequency': frequency,
                    'count': count,
                    'anomaly_type': 'high_frequency_pattern'
                })
        
        # Content anomaly detection
        unusual_content = []
        for event in events:
            # Check for encoded content
            if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', event):  # Base64 pattern
                unusual_content.append({
                    'type': 'base64_encoding',
                    'event': event[:100]
                })
            
            # Check for obfuscated content
            if len(re.findall(r'[^a-zA-Z0-9\s]', event)) > len(event) * 0.3:
                unusual_content.append({
                    'type': 'obfuscated_content',
                    'event': event[:100]
                })
        
        anomalies['content_anomalies'] = unusual_content[:10]  # Limit to first 10
        
        return anomalies
    
    def _extract_iocs(self, events: List[str]) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from events"""
        extracted_iocs = defaultdict(list)
        
        for event in events:
            for category, patterns in self.ioc_patterns.items():
                for ioc_type, pattern in patterns.items():
                    matches = re.findall(pattern, event, re.IGNORECASE)
                    for match in matches:
                        if match not in extracted_iocs[ioc_type]:
                            extracted_iocs[ioc_type].append(match)
        
        return dict(extracted_iocs)
    
    def _analyze_behavior(self, events: List[str], source_name: str) -> Dict[str, Any]:
        """Analyze behavioral patterns in events"""
        behavior_analysis = {
            'command_frequency': Counter(),
            'user_activity': Counter(),
            'time_patterns': defaultdict(int),
            'process_chains': [],
            'network_behavior': {}
        }
        
        # Analyze command frequency
        for event in events:
            # Extract commands (simplified)
            words = event.split()
            if words:
                command = words[0].lower()
                behavior_analysis['command_frequency'][command] += 1
        
        # Analyze time patterns (simplified - using event order)
        for i, event in enumerate(events):
            hour = i % 24  # Simulate hours
            behavior_analysis['time_patterns'][hour] += 1
        
        # Detect unusual behavioral patterns
        unusual_behaviors = []
        
        # Check for command anomalies
        total_commands = sum(behavior_analysis['command_frequency'].values())
        for command, count in behavior_analysis['command_frequency'].items():
            frequency = count / total_commands
            if frequency > 0.15:  # Command appears in >15% of events
                unusual_behaviors.append({
                    'type': 'high_frequency_command',
                    'command': command,
                    'frequency': frequency,
                    'count': count
                })
        
        behavior_analysis['unusual_behaviors'] = unusual_behaviors
        
        return behavior_analysis
    
    def _generate_hunting_recommendations(self, results: Dict) -> List[str]:
        """Generate threat hunting recommendations"""
        recommendations = []
        
        # Check for critical findings
        critical_findings = 0
        high_findings = 0
        
        for source_results in results['hunting_results'].values():
            for match in source_results:
                if match['severity'] == 'CRITICAL':
                    critical_findings += 1
                elif match['severity'] == 'HIGH':
                    high_findings += 1
        
        if critical_findings > 0:
            recommendations.extend([
                'URGENT: Critical threat indicators detected - activate incident response',
                'Isolate affected systems immediately',
                'Collect forensic evidence from compromised systems',
                'Review all network traffic for the past 48 hours'
            ])
        
        elif high_findings > 0:
            recommendations.extend([
                'High-priority threats detected - investigate immediately',
                'Increase monitoring on affected systems',
                'Review user account activities',
                'Check for lateral movement indicators'
            ])
        
        # Check for anomalies
        anomaly_count = 0
        for source_anomalies in results['anomalies'].values():
            anomaly_count += len(source_anomalies.get('volume_anomalies', []))
            anomaly_count += len(source_anomalies.get('pattern_anomalies', []))
            anomaly_count += len(source_anomalies.get('content_anomalies', []))
        
        if anomaly_count > 5:
            recommendations.append('Multiple anomalies detected - conduct deeper investigation')
        
        # Check for IOCs
        total_iocs = sum(len(iocs) for source_iocs in results['ioc_extractions'].values() 
                        for iocs in source_iocs.values())
        
        if total_iocs > 10:
            recommendations.append('Significant IOC activity - cross-reference with threat intelligence')
        
        # General recommendations
        recommendations.extend([
            'Update threat hunting rules based on findings',
            'Enhance monitoring for detected patterns',
            'Conduct regular threat hunting exercises',
            'Improve detection capabilities for identified gaps'
        ])
        
        return recommendations
    
    def generate_hunt_report(self, hunt_results: Dict) -> Dict:
        """Generate comprehensive threat hunting report"""
        report = {
            'report_id': hunt_results['hunt_id'],
            'generated_at': datetime.now().isoformat(),
            'hunt_summary': {
                'data_sources_analyzed': len(hunt_results['data_sources']),
                'total_events_processed': hunt_results['total_events'],
                'threats_detected': self._count_threats(hunt_results),
                'anomalies_found': self._count_anomalies(hunt_results),
                'iocs_extracted': self._count_iocs(hunt_results)
            },
            'executive_summary': self._generate_executive_summary(hunt_results),
            'detailed_findings': hunt_results['hunting_results'],
            'anomaly_analysis': hunt_results['anomalies'],
            'ioc_analysis': hunt_results['ioc_extractions'],
            'behavioral_insights': hunt_results['behavioral_analysis'],
            'recommendations': hunt_results['recommendations'],
            'next_steps': self._generate_next_steps(hunt_results),
            'mitre_attack_mapping': self._map_to_mitre(hunt_results)
        }
        
        return report
    
    def _count_threats(self, results: Dict) -> int:
        """Count total threats detected"""
        count = 0
        for source_results in results['hunting_results'].values():
            count += len(source_results)
        return count
    
    def _count_anomalies(self, results: Dict) -> int:
        """Count total anomalies found"""
        count = 0
        for source_anomalies in results['anomalies'].values():
            count += len(source_anomalies.get('volume_anomalies', []))
            count += len(source_anomalies.get('pattern_anomalies', []))
            count += len(source_anomalies.get('content_anomalies', []))
        return count
    
    def _count_iocs(self, results: Dict) -> int:
        """Count total IOCs extracted"""
        count = 0
        for source_iocs in results['ioc_extractions'].values():
            count += sum(len(iocs) for iocs in source_iocs.values())
        return count
    
    def _generate_executive_summary(self, results: Dict) -> str:
        """Generate executive summary"""
        threat_count = self._count_threats(results)
        anomaly_count = self._count_anomalies(results)
        ioc_count = self._count_iocs(results)
        
        if threat_count == 0 and anomaly_count == 0:
            return "Threat hunting analysis completed with no immediate threats detected. Regular monitoring recommended."
        
        elif threat_count > 0:
            return f"Threat hunting identified {threat_count} potential threats requiring investigation. Immediate action recommended."
        
        else:
            return f"Analysis detected {anomaly_count} anomalies and {ioc_count} indicators of compromise. Enhanced monitoring recommended."
    
    def _generate_next_steps(self, results: Dict) -> List[str]:
        """Generate actionable next steps"""
        next_steps = []
        
        threat_count = self._count_threats(results)
        
        if threat_count > 0:
            next_steps.extend([
                'Prioritize investigation of high-severity threats',
                'Correlate findings with existing security alerts',
                'Expand hunting to related systems and timeframes',
                'Update detection rules based on findings'
            ])
        
        next_steps.extend([
            'Schedule follow-up hunting exercise in 2 weeks',
            'Review and update hunting methodology',
            'Share findings with threat intelligence team',
            'Document lessons learned for future hunts'
        ])
        
        return next_steps
    
    def _map_to_mitre(self, results: Dict) -> Dict:
        """Map findings to MITRE ATT&CK framework"""
        mitre_mapping = defaultdict(list)
        
        for source_results in results['hunting_results'].values():
            for match in source_results:
                technique = match.get('mitre_technique')
                if technique:
                    mitre_mapping[technique].append({
                        'rule_name': match['rule_name'],
                        'match_count': match['match_count'],
                        'severity': match['severity']
                    })
        
        return dict(mitre_mapping)

class BehavioralAnalyzer:
    def __init__(self):
        self.user_baselines = {}
        self.system_baselines = {}
        self.anomaly_models = {}
        
    def establish_baseline(self, entity_type: str, entity_id: str, 
                          behavioral_data: List[Dict]) -> Dict:
        """Establish behavioral baseline for user or system"""
        baseline = {
            'entity_type': entity_type,
            'entity_id': entity_id,
            'established_at': datetime.now().isoformat(),
            'metrics': self._calculate_baseline_metrics(behavioral_data),
            'patterns': self._identify_patterns(behavioral_data),
            'thresholds': self._calculate_thresholds(behavioral_data)
        }
        
        if entity_type == 'user':
            self.user_baselines[entity_id] = baseline
        elif entity_type == 'system':
            self.system_baselines[entity_id] = baseline
        
        return baseline
    
    def _calculate_baseline_metrics(self, data: List[Dict]) -> Dict:
        """Calculate baseline metrics from behavioral data"""
        metrics = {
            'activity_volume': {
                'mean': 0,
                'std': 0,
                'min': 0,
                'max': 0
            },
            'time_patterns': {},
            'resource_usage': {},
            'command_frequency': Counter()
        }
        
        if not data:
            return metrics
        
        # Calculate activity volume statistics
        volumes = [len(str(item).split()) for item in data]
        if volumes:
            metrics['activity_volume'] = {
                'mean': statistics.mean(volumes),
                'std': statistics.stdev(volumes) if len(volumes) > 1 else 0,
                'min': min(volumes),
                'max': max(volumes)
            }
        
        return metrics
    
    def _identify_patterns(self, data: List[Dict]) -> Dict:
        """Identify behavioral patterns"""
        patterns = {
            'temporal_patterns': [],
            'sequence_patterns': [],
            'frequency_patterns': []
        }
        
        # Simplified pattern identification
        for item in data:
            if isinstance(item, dict):
                for key, value in item.items():
                    patterns['frequency_patterns'].append(f"{key}:{value}")
        
        return patterns
    
    def _calculate_thresholds(self, data: List[Dict]) -> Dict:
        """Calculate anomaly detection thresholds"""
        thresholds = {
            'volume_threshold': 2.0,  # Standard deviations
            'frequency_threshold': 0.1,  # 10% of normal
            'pattern_threshold': 0.05  # 5% deviation
        }
        
        return thresholds
    
    def detect_behavioral_anomalies(self, entity_type: str, entity_id: str, 
                                  current_behavior: List[Dict]) -> Dict:
        """Detect behavioral anomalies against established baseline"""
        baseline = None
        
        if entity_type == 'user' and entity_id in self.user_baselines:
            baseline = self.user_baselines[entity_id]
        elif entity_type == 'system' and entity_id in self.system_baselines:
            baseline = self.system_baselines[entity_id]
        
        if not baseline:
            return {'error': f'No baseline established for {entity_type} {entity_id}'}
        
        anomalies = {
            'entity_type': entity_type,
            'entity_id': entity_id,
            'analysis_time': datetime.now().isoformat(),
            'anomalies_detected': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        # Compare current behavior to baseline
        current_metrics = self._calculate_baseline_metrics(current_behavior)
        baseline_metrics = baseline['metrics']
        
        # Volume anomaly detection
        current_volume = current_metrics['activity_volume']['mean']
        baseline_volume = baseline_metrics['activity_volume']['mean']
        baseline_std = baseline_metrics['activity_volume']['std']
        
        if baseline_std > 0:
            z_score = abs(current_volume - baseline_volume) / baseline_std
            if z_score > baseline['thresholds']['volume_threshold']:
                anomalies['anomalies_detected'].append({
                    'type': 'volume_anomaly',
                    'severity': 'HIGH' if z_score > 3 else 'MEDIUM',
                    'z_score': z_score,
                    'description': f'Activity volume deviates {z_score:.2f} standard deviations from baseline'
                })
                anomalies['risk_score'] += min(z_score * 10, 50)
        
        # Pattern deviation detection
        # Simplified pattern comparison
        if len(current_behavior) > 0 and len(baseline['patterns']['frequency_patterns']) > 0:
            pattern_similarity = self._calculate_pattern_similarity(
                current_behavior, baseline['patterns']['frequency_patterns']
            )
            
            if pattern_similarity < 0.7:  # Less than 70% similarity
                anomalies['anomalies_detected'].append({
                    'type': 'pattern_deviation',
                    'severity': 'MEDIUM',
                    'similarity_score': pattern_similarity,
                    'description': 'Behavioral patterns deviate significantly from baseline'
                })
                anomalies['risk_score'] += (1 - pattern_similarity) * 30
        
        # Generate recommendations
        if anomalies['risk_score'] > 70:
            anomalies['recommendations'].extend([
                'Immediate investigation required',
                'Validate user/system identity',
                'Review recent access logs'
            ])
        elif anomalies['risk_score'] > 40:
            anomalies['recommendations'].extend([
                'Enhanced monitoring recommended',
                'Verify normal business activity',
                'Update baseline if behavior is legitimate'
            ])
        
        return anomalies
    
    def _calculate_pattern_similarity(self, current_data: List[Dict], 
                                    baseline_patterns: List[str]) -> float:
        """Calculate similarity between current and baseline patterns"""
        if not baseline_patterns or not current_data:
            return 0.0
        
        # Simplified similarity calculation
        current_patterns = []
        for item in current_data:
            if isinstance(item, dict):
                for key, value in item.items():
                    current_patterns.append(f"{key}:{value}")
        
        if not current_patterns:
            return 0.0
        
        # Calculate Jaccard similarity
        set_current = set(current_patterns)
        set_baseline = set(baseline_patterns)
        
        intersection = len(set_current.intersection(set_baseline))
        union = len(set_current.union(set_baseline))
        
        return intersection / union if union > 0 else 0.0