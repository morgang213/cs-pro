"""
Incident Response and Digital Forensics Platform
Automated incident handling, evidence collection, and forensic analysis
"""

import json
import os
import hashlib
import shutil
import subprocess
import tempfile
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
import zipfile
import tarfile
from pathlib import Path
from loguru import logger
import psutil
from collections import defaultdict, Counter

class IncidentSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class IncidentStatus(Enum):
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    CLOSED = "CLOSED"

class EvidenceType(Enum):
    MEMORY_DUMP = "MEMORY_DUMP"
    DISK_IMAGE = "DISK_IMAGE"
    NETWORK_CAPTURE = "NETWORK_CAPTURE"
    LOG_FILES = "LOG_FILES"
    FILE_SYSTEM = "FILE_SYSTEM"
    REGISTRY = "REGISTRY"
    VOLATILE_DATA = "VOLATILE_DATA"

@dataclass
class IncidentTicket:
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: str = ""
    affected_systems: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    response_actions: List[Dict] = field(default_factory=list)
    
    def __post_init__(self):
        # Fields are now initialized with default_factory, no need for None checks
        pass

class IncidentResponseManager:
    def __init__(self):
        self.incidents = {}
        self.playbooks = self._load_playbooks()
        self.evidence_storage = tempfile.mkdtemp(prefix="ir_evidence_")
        self.forensic_tools = self._initialize_forensic_tools()
        
    def _load_playbooks(self) -> Dict:
        """Load incident response playbooks"""
        return {
            'malware_infection': {
                'description': 'Response to malware infections',
                'phases': [
                    'Identify affected systems',
                    'Isolate compromised systems',
                    'Collect volatile evidence',
                    'Analyze malware samples',
                    'Eradicate malware',
                    'Restore systems',
                    'Monitor for reinfection'
                ],
                'automated_actions': [
                    'disable_network_access',
                    'collect_memory_dump',
                    'quarantine_files',
                    'update_antivirus'
                ]
            },
            'data_breach': {
                'description': 'Response to data breaches',
                'phases': [
                    'Assess scope of breach',
                    'Contain data exposure',
                    'Preserve evidence',
                    'Notify stakeholders',
                    'Investigate attack vector',
                    'Remediate vulnerabilities',
                    'Monitor for further activity'
                ],
                'automated_actions': [
                    'disable_compromised_accounts',
                    'collect_access_logs',
                    'backup_affected_data',
                    'enable_enhanced_monitoring'
                ]
            },
            'ransomware': {
                'description': 'Response to ransomware attacks',
                'phases': [
                    'Immediate isolation',
                    'Assess encryption scope',
                    'Preserve evidence',
                    'Activate backup recovery',
                    'Analyze ransomware variant',
                    'Implement decryption if possible',
                    'Rebuild affected systems'
                ],
                'automated_actions': [
                    'isolate_all_systems',
                    'collect_ransom_note',
                    'backup_encrypted_files',
                    'attempt_decryption'
                ]
            },
            'insider_threat': {
                'description': 'Response to insider threats',
                'phases': [
                    'Covert investigation initiation',
                    'Evidence preservation',
                    'User activity analysis',
                    'Access rights review',
                    'Interview preparations',
                    'Account suspension',
                    'Asset recovery'
                ],
                'automated_actions': [
                    'monitor_user_activity',
                    'collect_access_logs',
                    'backup_user_data',
                    'review_permissions'
                ]
            },
            'network_intrusion': {
                'description': 'Response to network intrusions',
                'phases': [
                    'Network traffic analysis',
                    'Identify entry point',
                    'Map attacker movement',
                    'Isolate compromised segments',
                    'Collect network evidence',
                    'Patch vulnerabilities',
                    'Restore network security'
                ],
                'automated_actions': [
                    'collect_network_logs',
                    'analyze_traffic_patterns',
                    'block_malicious_ips',
                    'update_firewall_rules'
                ]
            }
        }
    
    def _initialize_forensic_tools(self) -> Dict:
        """Initialize forensic analysis tools"""
        return {
            'file_analysis': {
                'hash_calculator': self._calculate_file_hash,
                'metadata_extractor': self._extract_file_metadata,
                'signature_analyzer': self._analyze_file_signature
            },
            'memory_analysis': {
                'process_analyzer': self._analyze_processes,
                'network_connections': self._get_network_connections,
                'loaded_modules': self._get_loaded_modules
            },
            'network_analysis': {
                'traffic_analyzer': self._analyze_network_traffic,
                'connection_tracker': self._track_connections,
                'protocol_analyzer': self._analyze_protocols
            },
            'timeline_analysis': {
                'event_correlator': self._correlate_events,
                'timeline_builder': self._build_timeline,
                'activity_analyzer': self._analyze_activity_patterns
            }
        }
    
    def create_incident(self, title: str, description: str, severity: str, 
                       affected_systems: Optional[List[str]] = None) -> str:
        """Create new incident ticket"""
        incident_id = hashlib.md5(f"{title}_{datetime.now()}".encode()).hexdigest()[:8]
        
        incident = IncidentTicket(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=IncidentSeverity(severity.upper()),
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            affected_systems=affected_systems if affected_systems else []
        )
        
        self.incidents[incident_id] = incident
        
        # Auto-assign playbook based on incident type
        self._assign_playbook(incident)
        
        # Log incident creation
        logger.info(f"Incident {incident_id} created: {title}")
        
        return incident_id
    
    def _assign_playbook(self, incident: IncidentTicket):
        """Automatically assign appropriate playbook"""
        title_lower = incident.title.lower()
        description_lower = incident.description.lower()
        
        playbook_keywords = {
            'malware_infection': ['malware', 'virus', 'trojan', 'infection'],
            'data_breach': ['data breach', 'leak', 'exposure', 'unauthorized access'],
            'ransomware': ['ransomware', 'encrypted', 'ransom', 'crypto'],
            'insider_threat': ['insider', 'employee', 'internal', 'privilege abuse'],
            'network_intrusion': ['intrusion', 'breach', 'unauthorized network', 'lateral movement']
        }
        
        for playbook_name, keywords in playbook_keywords.items():
            if any(keyword in title_lower or keyword in description_lower for keyword in keywords):
                incident.response_actions.append({
                    'action': 'playbook_assigned',
                    'playbook': playbook_name,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'assigned'
                })
                break
    
    def collect_evidence(self, incident_id: str, evidence_type: str, 
                        source_path: Optional[str] = None, description: str = "") -> Dict:
        """Collect digital evidence for incident"""
        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}
        
        evidence_id = hashlib.md5(f"{incident_id}_{evidence_type}_{datetime.now()}".encode()).hexdigest()[:8]
        evidence_path = os.path.join(self.evidence_storage, incident_id, evidence_id)
        os.makedirs(evidence_path, exist_ok=True)
        
        evidence_record = {
            'evidence_id': evidence_id,
            'type': evidence_type,
            'collected_at': datetime.now().isoformat(),
            'collector': 'automated_system',
            'source_path': source_path,
            'storage_path': evidence_path,
            'description': description,
            'hash': '',
            'size': 0,
            'chain_of_custody': [
                {
                    'action': 'collected',
                    'timestamp': datetime.now().isoformat(),
                    'person': 'ir_system',
                    'location': evidence_path
                }
            ]
        }
        
        try:
            if evidence_type == EvidenceType.VOLATILE_DATA.value:
                self._collect_volatile_data(evidence_path)
            elif evidence_type == EvidenceType.LOG_FILES.value:
                self._collect_log_files(evidence_path, source_path or "/var/log")
            elif evidence_type == EvidenceType.FILE_SYSTEM.value:
                self._collect_file_system_evidence(evidence_path, source_path or "/")
            elif evidence_type == EvidenceType.NETWORK_CAPTURE.value:
                self._collect_network_evidence(evidence_path)
            elif evidence_type == EvidenceType.MEMORY_DUMP.value:
                self._collect_memory_dump(evidence_path)
            
            # Calculate evidence hash
            evidence_record['hash'] = self._calculate_evidence_hash(evidence_path)
            evidence_record['size'] = self._get_directory_size(evidence_path)
            
            # Add to incident
            self.incidents[incident_id].evidence.append(evidence_record)
            
            logger.info(f"Evidence {evidence_id} collected for incident {incident_id}")
            
            return evidence_record
            
        except Exception as e:
            logger.error(f"Evidence collection failed: {e}")
            return {'error': f'Evidence collection failed: {str(e)}'}
    
    def _collect_volatile_data(self, evidence_path: str):
        """Collect volatile system data"""
        volatile_data = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self._get_system_info(),
            'running_processes': self._get_running_processes(),
            'network_connections': self._get_network_connections(),
            'logged_in_users': self._get_logged_in_users(),
            'system_uptime': self._get_system_uptime(),
            'environment_variables': dict(os.environ),
            'open_files': self._get_open_files()
        }
        
        with open(os.path.join(evidence_path, 'volatile_data.json'), 'w') as f:
            json.dump(volatile_data, f, indent=2, default=str)
    
    def _collect_log_files(self, evidence_path: str, source_path: Optional[str] = None):
        """Collect system and application log files"""
        log_paths = [
            '/var/log/',
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/kern.log',
            '/var/log/apache2/',
            '/var/log/nginx/',
            source_path
        ]
        
        collected_logs = []
        for log_path in log_paths:
            if log_path and os.path.exists(log_path):
                try:
                    if os.path.isfile(log_path):
                        dest_file = os.path.join(evidence_path, os.path.basename(log_path))
                        shutil.copy2(log_path, dest_file)
                        collected_logs.append(dest_file)
                    elif os.path.isdir(log_path):
                        dest_dir = os.path.join(evidence_path, os.path.basename(log_path))
                        shutil.copytree(log_path, dest_dir, dirs_exist_ok=True)
                        collected_logs.append(dest_dir)
                except Exception as e:
                    logger.warning(f"Could not collect log from {log_path}: {e}")
        
        # Create log collection summary
        with open(os.path.join(evidence_path, 'log_collection_summary.json'), 'w') as f:
            json.dump({
                'collected_logs': collected_logs,
                'collection_time': datetime.now().isoformat(),
                'total_files': len(collected_logs)
            }, f, indent=2)
    
    def _collect_file_system_evidence(self, evidence_path: str, source_path: Optional[str]):
        """Collect file system evidence"""
        if not source_path or not os.path.exists(source_path):
            raise ValueError("Invalid source path for file system evidence")
        
        # Create compressed archive of source path
        archive_path = os.path.join(evidence_path, 'filesystem_evidence.tar.gz')
        
        with tarfile.open(archive_path, 'w:gz') as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        
        # Create file listing
        file_listing = []
        for root, dirs, files in os.walk(source_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    stat_info = os.stat(file_path)
                    file_listing.append({
                        'path': file_path,
                        'size': stat_info.st_size,
                        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                        'hash': self._calculate_file_hash(file_path)
                    })
                except Exception as e:
                    logger.warning(f"Could not process file {file_path}: {e}")
        
        with open(os.path.join(evidence_path, 'file_listing.json'), 'w') as f:
            json.dump(file_listing, f, indent=2)
    
    def _collect_network_evidence(self, evidence_path: str):
        """Collect network-related evidence"""
        network_data = {
            'timestamp': datetime.now().isoformat(),
            'active_connections': self._get_network_connections(),
            'routing_table': self._get_routing_table(),
            'arp_table': self._get_arp_table(),
            'network_interfaces': self._get_network_interfaces(),
            'dns_cache': self._get_dns_cache(),
            'firewall_rules': self._get_firewall_rules()
        }
        
        with open(os.path.join(evidence_path, 'network_evidence.json'), 'w') as f:
            json.dump(network_data, f, indent=2, default=str)
    
    def _collect_memory_dump(self, evidence_path: str):
        """Collect memory dump (simplified implementation)"""
        # In a real implementation, this would use tools like volatility
        memory_info = {
            'timestamp': datetime.now().isoformat(),
            'system_memory': self._get_memory_info(),
            'process_memory': self._get_process_memory_info(),
            'note': 'Full memory dump requires specialized tools and elevated privileges'
        }
        
        with open(os.path.join(evidence_path, 'memory_info.json'), 'w') as f:
            json.dump(memory_info, f, indent=2, default=str)
    
    def analyze_evidence(self, incident_id: str, evidence_id: str) -> Dict:
        """Perform forensic analysis on collected evidence"""
        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}
        
        incident = self.incidents[incident_id]
        evidence = None
        
        for ev in incident.evidence:
            if ev['evidence_id'] == evidence_id:
                evidence = ev
                break
        
        if not evidence:
            return {'error': 'Evidence not found'}
        
        analysis_results = {
            'evidence_id': evidence_id,
            'analysis_timestamp': datetime.now().isoformat(),
            'evidence_type': evidence['type'],
            'findings': [],
            'indicators': [],
            'timeline_events': [],
            'recommendations': []
        }
        
        # Perform analysis based on evidence type
        try:
            if evidence['type'] == EvidenceType.VOLATILE_DATA.value:
                analysis_results.update(self._analyze_volatile_data(evidence['storage_path']))
            elif evidence['type'] == EvidenceType.LOG_FILES.value:
                analysis_results.update(self._analyze_log_files(evidence['storage_path']))
            elif evidence['type'] == EvidenceType.FILE_SYSTEM.value:
                analysis_results.update(self._analyze_file_system(evidence['storage_path']))
            elif evidence['type'] == EvidenceType.NETWORK_CAPTURE.value:
                analysis_results.update(self._analyze_network_evidence(evidence['storage_path']))
            
        except Exception as e:
            analysis_results['error'] = f"Analysis failed: {str(e)}"
        
        return analysis_results
    
    def _analyze_volatile_data(self, evidence_path: str) -> Dict:
        """Analyze volatile data evidence"""
        volatile_file = os.path.join(evidence_path, 'volatile_data.json')
        
        if not os.path.exists(volatile_file):
            return {'error': 'Volatile data file not found'}
        
        with open(volatile_file, 'r') as f:
            volatile_data = json.load(f)
        
        findings = []
        indicators = []
        
        # Analyze running processes
        processes = volatile_data.get('running_processes', [])
        suspicious_processes = []
        
        for process in processes:
            if isinstance(process, dict):
                name = process.get('name', '').lower()
                # Look for suspicious process names
                if any(sus in name for sus in ['cmd', 'powershell', 'rundll32', 'regsvr32']):
                    suspicious_processes.append(process)
                    indicators.append(f"Suspicious process: {process.get('name', 'Unknown')}")
        
        if suspicious_processes:
            findings.append({
                'category': 'Suspicious Processes',
                'severity': 'MEDIUM',
                'details': f"Found {len(suspicious_processes)} potentially suspicious processes",
                'processes': suspicious_processes[:5]  # Limit to first 5
            })
        
        # Analyze network connections
        connections = volatile_data.get('network_connections', [])
        external_connections = [conn for conn in connections 
                              if isinstance(conn, dict) and 
                              not self._is_internal_ip(conn.get('remote_address', ''))]
        
        if len(external_connections) > 10:
            findings.append({
                'category': 'Network Activity',
                'severity': 'MEDIUM',
                'details': f"High number of external connections: {len(external_connections)}",
                'connections': external_connections[:10]
            })
        
        return {
            'findings': findings,
            'indicators': indicators,
            'process_count': len(processes),
            'connection_count': len(connections),
            'external_connections': len(external_connections)
        }
    
    def _analyze_log_files(self, evidence_path: str) -> Dict:
        """Analyze log file evidence"""
        findings = []
        indicators = []
        timeline_events = []
        
        # Look for log files
        log_files = []
        for root, dirs, files in os.walk(evidence_path):
            for file in files:
                if file.endswith(('.log', '.txt')) or 'log' in file.lower():
                    log_files.append(os.path.join(root, file))
        
        # Analyze each log file
        for log_file in log_files[:10]:  # Limit to first 10 files
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Look for authentication failures
                auth_failures = len(re.findall(r'authentication failure|failed login|invalid user', content, re.IGNORECASE))
                if auth_failures > 10:
                    findings.append({
                        'category': 'Authentication',
                        'severity': 'HIGH' if auth_failures > 50 else 'MEDIUM',
                        'details': f"Found {auth_failures} authentication failures in {os.path.basename(log_file)}",
                        'file': log_file
                    })
                    indicators.append(f"High authentication failure rate: {auth_failures}")
                
                # Look for error patterns
                errors = len(re.findall(r'error|exception|critical|fatal', content, re.IGNORECASE))
                if errors > 20:
                    findings.append({
                        'category': 'System Errors',
                        'severity': 'MEDIUM',
                        'details': f"Found {errors} error messages in {os.path.basename(log_file)}",
                        'file': log_file
                    })
                
            except Exception as e:
                logger.warning(f"Could not analyze log file {log_file}: {e}")
        
        return {
            'findings': findings,
            'indicators': indicators,
            'timeline_events': timeline_events,
            'log_files_analyzed': len(log_files)
        }
    
    def _analyze_file_system(self, evidence_path: str) -> Dict:
        """Analyze file system evidence"""
        findings = []
        indicators = []
        file_listing = []
        
        # Check for file listing
        file_listing_path = os.path.join(evidence_path, 'file_listing.json')
        
        if os.path.exists(file_listing_path):
            with open(file_listing_path, 'r') as f:
                file_listing = json.load(f)
            
            # Analyze file patterns
            executable_files = [f for f in file_listing if f['path'].lower().endswith(('.exe', '.bat', '.cmd', '.ps1'))]
            recent_files = [f for f in file_listing 
                          if datetime.fromisoformat(f['modified']) > datetime.now() - timedelta(days=1)]
            
            if len(executable_files) > 0:
                findings.append({
                    'category': 'Executable Files',
                    'severity': 'MEDIUM',
                    'details': f"Found {len(executable_files)} executable files",
                    'files': [f['path'] for f in executable_files[:10]]
                })
            
            if len(recent_files) > 0:
                findings.append({
                    'category': 'Recent File Activity',
                    'severity': 'INFO',
                    'details': f"Found {len(recent_files)} recently modified files",
                    'files': [f['path'] for f in recent_files[:10]]
                })
                indicators.extend([f"Recent file: {f['path']}" for f in recent_files[:5]])
        
        return {
            'findings': findings,
            'indicators': indicators,
            'total_files': len(file_listing) if file_listing else 0
        }
    
    def _analyze_network_evidence(self, evidence_path: str) -> Dict:
        """Analyze network evidence"""
        findings = []
        indicators = []
        connections = []
        
        network_file = os.path.join(evidence_path, 'network_evidence.json')
        
        if os.path.exists(network_file):
            with open(network_file, 'r') as f:
                network_data = json.load(f)
            
            connections = network_data.get('active_connections', [])
            external_connections = [conn for conn in connections 
                                  if not self._is_internal_ip(conn.get('remote_address', ''))]
            
            if len(external_connections) > 10:
                findings.append({
                    'category': 'External Network Activity',
                    'severity': 'MEDIUM',
                    'details': f"Found {len(external_connections)} external connections",
                    'connections': external_connections[:10]
                })
                indicators.extend([f"External connection: {conn.get('remote_address', 'Unknown')}" 
                                 for conn in external_connections[:5]])
        
        return {
            'findings': findings,
            'indicators': indicators,
            'connections_analyzed': len(connections) if connections else 0
        }
    
    def generate_incident_report(self, incident_id: str) -> Dict:
        """Generate comprehensive incident report"""
        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}
        
        incident = self.incidents[incident_id]
        
        # Compile all evidence analysis
        evidence_analysis = []
        total_indicators = []
        
        for evidence in incident.evidence:
            analysis = self.analyze_evidence(incident_id, evidence['evidence_id'])
            evidence_analysis.append(analysis)
            total_indicators.extend(analysis.get('indicators', []))
        
        report = {
            'incident_id': incident_id,
            'report_generated': datetime.now().isoformat(),
            'incident_summary': {
                'title': incident.title,
                'description': incident.description,
                'severity': incident.severity.value,
                'status': incident.status.value,
                'created_at': incident.created_at.isoformat(),
                'duration': str(datetime.now() - incident.created_at),
                'affected_systems': incident.affected_systems
            },
            'evidence_summary': {
                'total_evidence_items': len(incident.evidence),
                'evidence_types': list(set([ev['type'] for ev in incident.evidence])),
                'total_indicators': len(total_indicators),
                'unique_indicators': len(set(total_indicators))
            },
            'timeline': self._build_incident_timeline(incident),
            'evidence_analysis': evidence_analysis,
            'response_actions': incident.response_actions,
            'recommendations': self._generate_incident_recommendations(incident, evidence_analysis),
            'lessons_learned': self._extract_lessons_learned(incident, evidence_analysis)
        }
        
        return report
    
    def _build_incident_timeline(self, incident: IncidentTicket) -> List[Dict]:
        """Build incident timeline"""
        timeline = [
            {
                'timestamp': incident.created_at.isoformat(),
                'event': 'Incident Created',
                'description': incident.title,
                'type': 'administrative'
            }
        ]
        
        # Add evidence collection events
        for evidence in incident.evidence:
            timeline.append({
                'timestamp': evidence['collected_at'],
                'event': 'Evidence Collected',
                'description': f"{evidence['type']} evidence collected",
                'type': 'evidence'
            })
        
        # Add response actions
        for action in incident.response_actions:
            timeline.append({
                'timestamp': action.get('timestamp', datetime.now().isoformat()),
                'event': 'Response Action',
                'description': action.get('action', 'Unknown action'),
                'type': 'response'
            })
        
        return sorted(timeline, key=lambda x: x['timestamp'])
    
    def _generate_incident_recommendations(self, incident: IncidentTicket, 
                                         evidence_analysis: List[Dict]) -> List[str]:
        """Generate incident response recommendations"""
        recommendations = []
        
        # Analyze findings across all evidence
        all_findings = []
        for analysis in evidence_analysis:
            all_findings.extend(analysis.get('findings', []))
        
        critical_findings = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        high_findings = [f for f in all_findings if f.get('severity') == 'HIGH']
        
        if critical_findings:
            recommendations.extend([
                'Immediate containment required - critical threats detected',
                'Activate full incident response team',
                'Consider system isolation and network segmentation',
                'Notify executive leadership and legal team'
            ])
        
        elif high_findings:
            recommendations.extend([
                'Enhanced monitoring and investigation required',
                'Implement additional security controls',
                'Review and update security policies',
                'Conduct threat hunting activities'
            ])
        
        # Severity-based recommendations
        if incident.severity == IncidentSeverity.CRITICAL:
            recommendations.extend([
                'Prepare for potential business continuity activation',
                'Consider external forensic assistance',
                'Document all actions for legal proceedings'
            ])
        
        # General recommendations
        recommendations.extend([
            'Update incident response procedures based on lessons learned',
            'Conduct post-incident review meeting',
            'Implement preventive measures to avoid recurrence',
            'Provide additional security training to staff'
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _extract_lessons_learned(self, incident: IncidentTicket, 
                                evidence_analysis: List[Dict]) -> List[str]:
        """Extract lessons learned from incident"""
        lessons = []
        
        # Analyze response effectiveness
        if len(incident.response_actions) < 3:
            lessons.append('Response could be enhanced with more automated actions')
        
        # Evidence collection insights
        evidence_types = set([ev['type'] for ev in incident.evidence])
        if EvidenceType.VOLATILE_DATA.value not in evidence_types:
            lessons.append('Consider collecting volatile data earlier in response')
        
        # Timeline analysis
        response_time = datetime.now() - incident.created_at
        if response_time.total_seconds() > 3600:  # More than 1 hour
            lessons.append('Improve initial response time - consider automation')
        
        lessons.extend([
            'Regular incident response training needed',
            'Update playbooks based on current threat landscape',
            'Enhance evidence collection procedures',
            'Improve coordination between response teams'
        ])
        
        return lessons
    
    # Helper methods
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return ''
    
    def _calculate_evidence_hash(self, evidence_path: str) -> str:
        """Calculate hash of evidence directory"""
        hash_obj = hashlib.sha256()
        
        for root, dirs, files in os.walk(evidence_path):
            for file in sorted(files):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        hash_obj.update(f.read())
                except Exception:
                    continue
        
        return hash_obj.hexdigest()
    
    def _get_directory_size(self, path: str) -> int:
        """Get total size of directory"""
        total = 0
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    total += os.path.getsize(file_path)
                except Exception:
                    continue
        return total
    
    def _get_system_info(self) -> Dict:
        """Get system information"""
        return {
            'platform': os.name,
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total
        }
    
    def _get_running_processes(self) -> List[Dict]:
        """Get running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
    
    def _get_network_connections(self) -> List[Dict]:
        """Get network connections"""
        connections = []
        for conn in psutil.net_connections():
            connections.append({
                'fd': conn.fd,
                'family': str(conn.family),
                'type': str(conn.type),
                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                'status': conn.status,
                'pid': conn.pid
            })
        return connections
    
    def _get_logged_in_users(self) -> List[Dict]:
        """Get logged in users"""
        users = []
        for user in psutil.users():
            users.append({
                'name': user.name,
                'terminal': user.terminal,
                'host': user.host,
                'started': datetime.fromtimestamp(user.started).isoformat()
            })
        return users
    
    def _get_system_uptime(self) -> str:
        """Get system uptime"""
        boot_time = psutil.boot_time()
        uptime = datetime.now() - datetime.fromtimestamp(boot_time)
        return str(uptime)
    
    def _get_open_files(self) -> List[str]:
        """Get open files (simplified)"""
        open_files = []
        try:
            for proc in psutil.process_iter():
                try:
                    files = proc.open_files()
                    for file in files[:5]:  # Limit to 5 files per process
                        open_files.append(file.path)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if len(open_files) > 100:  # Limit total files
                    break
        except Exception:
            pass
        return open_files
    
    def _get_memory_info(self) -> Dict:
        """Get memory information"""
        memory = psutil.virtual_memory()
        return {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'percentage': memory.percent
        }
    
    def _get_process_memory_info(self) -> List[Dict]:
        """Get process memory information"""
        process_memory = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                process_memory.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'memory_rss': proc.info['memory_info'].rss,
                    'memory_vms': proc.info['memory_info'].vms
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(process_memory, key=lambda x: x['memory_rss'], reverse=True)[:20]
    
    def _get_routing_table(self) -> List[str]:
        """Get routing table (simplified)"""
        # In a real implementation, this would parse system routing table
        return ["Routing table collection requires system-specific implementation"]
    
    def _get_arp_table(self) -> List[str]:
        """Get ARP table (simplified)"""
        # In a real implementation, this would parse ARP table
        return ["ARP table collection requires system-specific implementation"]
    
    def _get_network_interfaces(self) -> Dict:
        """Get network interfaces"""
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = [
                {
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                }
                for addr in addrs
            ]
        return interfaces
    
    def _get_dns_cache(self) -> List[str]:
        """Get DNS cache (simplified)"""
        # DNS cache collection requires system-specific implementation
        return ["DNS cache collection requires system-specific implementation"]
    
    def _get_firewall_rules(self) -> List[str]:
        """Get firewall rules (simplified)"""
        # Firewall rules collection requires system-specific implementation
        return ["Firewall rules collection requires system-specific implementation"]
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal"""
        if not ip:
            return True
        
        internal_ranges = [
            '127.',  # Loopback
            '10.',   # Private Class A
            '172.16.', '172.17.', '172.18.', '172.19.',  # Private Class B (partial)
            '192.168.'  # Private Class C
        ]
        
        return any(ip.startswith(range_prefix) for range_prefix in internal_ranges)
    
    def _extract_file_metadata(self, file_path: str) -> Dict:
        """Extract file metadata"""
        try:
            stat_info = os.stat(file_path)
            return {
                'size': stat_info.st_size,
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'permissions': oct(stat_info.st_mode)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_file_signature(self, file_path: str) -> Dict:
        """Analyze file signature"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            signatures = {
                b'\x4D\x5A': 'PE Executable',
                b'\x7F\x45\x4C\x46': 'ELF Executable',
                b'\x89\x50\x4E\x47': 'PNG Image',
                b'\xFF\xD8\xFF': 'JPEG Image',
                b'\x50\x4B\x03\x04': 'ZIP Archive'
            }
            
            for sig, file_type in signatures.items():
                if header.startswith(sig):
                    return {'file_type': file_type, 'signature': sig.hex()}
            
            return {'file_type': 'Unknown', 'signature': header.hex()}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_processes(self) -> List[Dict]:
        """Analyze processes (already implemented as _get_running_processes)"""
        return self._get_running_processes()
    
    def _get_loaded_modules(self) -> List[str]:
        """Get loaded modules (simplified)"""
        # Module enumeration requires system-specific implementation
        return ["Module enumeration requires system-specific implementation"]
    
    def _analyze_network_traffic(self, evidence_path: str) -> Dict:
        """Analyze network traffic"""
        # Network traffic analysis requires packet capture tools
        return {
            'note': 'Network traffic analysis requires packet capture files',
            'recommendation': 'Use tools like Wireshark or tcpdump for traffic analysis'
        }
    
    def _track_connections(self, evidence_path: str) -> List[Dict]:
        """Track network connections"""
        return self._get_network_connections()
    
    def _analyze_protocols(self, evidence_path: str) -> Dict:
        """Analyze network protocols"""
        # Protocol analysis requires packet inspection
        return {
            'note': 'Protocol analysis requires packet capture data',
            'recommendation': 'Implement deep packet inspection for protocol analysis'
        }
    
    def _correlate_events(self, events: List[Dict]) -> List[Dict]:
        """Correlate events for timeline analysis"""
        # Event correlation logic
        correlations = []
        
        # Group events by time windows
        time_windows = defaultdict(list)
        for event in events:
            # Simplified time windowing
            timestamp = event.get('timestamp', datetime.now().isoformat())
            hour = timestamp[:13]  # Group by hour
            time_windows[hour].append(event)
        
        # Find correlations
        for window, window_events in time_windows.items():
            if len(window_events) > 5:  # High activity window
                correlations.append({
                    'time_window': window,
                    'event_count': len(window_events),
                    'correlation_type': 'high_activity',
                    'events': window_events[:10]  # First 10 events
                })
        
        return correlations
    
    def _build_timeline(self, events: List[Dict]) -> List[Dict]:
        """Build event timeline"""
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))
        
        timeline = []
        for i, event in enumerate(sorted_events):
            timeline.append({
                'sequence': i + 1,
                'timestamp': event.get('timestamp'),
                'event_type': event.get('type', 'unknown'),
                'description': event.get('description', ''),
                'source': event.get('source', 'unknown')
            })
        
        return timeline
    
    def _analyze_activity_patterns(self, events: List[Dict]) -> Dict:
        """Analyze activity patterns"""
        patterns = {
            'hourly_distribution': defaultdict(int),
            'event_types': Counter(),
            'activity_peaks': [],
            'anomalies': []
        }
        
        for event in events:
            # Extract hour from timestamp
            timestamp = event.get('timestamp', datetime.now().isoformat())
            try:
                hour = int(timestamp[11:13])
                patterns['hourly_distribution'][hour] += 1
            except (ValueError, IndexError):
                continue
            
            # Count event types
            event_type = event.get('type', 'unknown')
            patterns['event_types'][event_type] += 1
        
        # Identify activity peaks
        max_activity = max(patterns['hourly_distribution'].values()) if patterns['hourly_distribution'] else 0
        for hour, count in patterns['hourly_distribution'].items():
            if count > max_activity * 0.8:  # More than 80% of peak activity
                patterns['activity_peaks'].append({'hour': hour, 'count': count})
        
        return patterns