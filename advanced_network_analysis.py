"""
Advanced Network Analysis Platform
Deep packet inspection, traffic analysis, and network forensics capabilities
"""

import json
import re
import socket
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import hashlib
import ipaddress
from dataclasses import dataclass, field
import subprocess
import threading
from loguru import logger
import psutil
import netaddr

@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    flags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # flags is now initialized with default_factory, no need for None check
        pass

class AdvancedNetworkAnalyzer:
    def __init__(self):
        self.flows = {}
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.protocol_analyzers = self._initialize_protocol_analyzers()
        self.geo_db = None  # Would be initialized with GeoIP database
        self.threat_intel = {}
        self.baseline_traffic = {}
        
    def _load_suspicious_patterns(self) -> Dict:
        """Load patterns for detecting suspicious network activity"""
        return {
            'port_scanning': {
                'description': 'Detect port scanning activities',
                'indicators': [
                    'high_port_diversity',  # Many different destination ports
                    'rapid_connections',    # Many connections in short time
                    'low_data_volume',     # Little data transferred
                    'connection_failures'  # Many failed connections
                ],
                'thresholds': {
                    'ports_per_minute': 20,
                    'connections_per_minute': 50,
                    'avg_bytes_per_connection': 100
                }
            },
            'dns_tunneling': {
                'description': 'Detect DNS tunneling for data exfiltration',
                'indicators': [
                    'large_dns_queries',
                    'unusual_dns_patterns',
                    'high_dns_frequency',
                    'non_standard_record_types'
                ],
                'thresholds': {
                    'query_size_threshold': 100,
                    'queries_per_minute': 30,
                    'subdomain_length': 50
                }
            },
            'data_exfiltration': {
                'description': 'Detect potential data exfiltration',
                'indicators': [
                    'large_outbound_transfers',
                    'unusual_destinations',
                    'off_hours_activity',
                    'encrypted_channels'
                ],
                'thresholds': {
                    'bytes_threshold': 100000000,  # 100MB
                    'transfer_rate_threshold': 1000000,  # 1MB/s
                    'off_hours_start': 22,
                    'off_hours_end': 6
                }
            },
            'lateral_movement': {
                'description': 'Detect lateral movement within network',
                'indicators': [
                    'internal_scanning',
                    'service_enumeration',
                    'credential_spraying',
                    'admin_share_access'
                ],
                'thresholds': {
                    'internal_connections_threshold': 10,
                    'service_ports': [22, 23, 135, 139, 445, 3389, 5985, 5986]
                }
            },
            'c2_communication': {
                'description': 'Detect command and control communications',
                'indicators': [
                    'beacon_patterns',
                    'domain_generation',
                    'encrypted_traffic_anomalies',
                    'unusual_user_agents'
                ],
                'thresholds': {
                    'beacon_regularity_threshold': 0.8,
                    'connection_interval_variance': 0.1
                }
            }
        }
    
    def _initialize_protocol_analyzers(self) -> Dict:
        """Initialize protocol-specific analyzers"""
        return {
            'HTTP': self._analyze_http_traffic,
            'HTTPS': self._analyze_https_traffic,
            'DNS': self._analyze_dns_traffic,
            'SMB': self._analyze_smb_traffic,
            'FTP': self._analyze_ftp_traffic,
            'SSH': self._analyze_ssh_traffic,
            'TELNET': self._analyze_telnet_traffic,
            'ICMP': self._analyze_icmp_traffic
        }
    
    def analyze_network_traffic(self, traffic_data: List[Dict]) -> Dict[str, Any]:
        """Perform comprehensive network traffic analysis"""
        analysis_results = {
            'analysis_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'timestamp': datetime.now().isoformat(),
            'total_flows': len(traffic_data),
            'flow_analysis': {},
            'protocol_analysis': {},
            'threat_detection': {},
            'anomaly_detection': {},
            'geographic_analysis': {},
            'timeline_analysis': {},
            'recommendations': []
        }
        
        # Parse traffic data into flows
        flows = self._parse_traffic_to_flows(traffic_data)
        analysis_results['flow_analysis'] = self._analyze_flows(flows)
        
        # Protocol-specific analysis
        analysis_results['protocol_analysis'] = self._analyze_protocols(flows)
        
        # Threat detection
        analysis_results['threat_detection'] = self._detect_threats(flows)
        
        # Anomaly detection
        analysis_results['anomaly_detection'] = self._detect_anomalies(flows)
        
        # Geographic analysis
        analysis_results['geographic_analysis'] = self._analyze_geography(flows)
        
        # Timeline analysis
        analysis_results['timeline_analysis'] = self._analyze_timeline(flows)
        
        # Generate recommendations
        analysis_results['recommendations'] = self._generate_network_recommendations(analysis_results)
        
        return analysis_results
    
    def _parse_traffic_to_flows(self, traffic_data: List[Dict]) -> List[NetworkFlow]:
        """Parse raw traffic data into network flows"""
        flows = []
        flow_tracker = {}
        
        for packet in traffic_data:
            # Extract flow identifier
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            protocol = packet.get('protocol', 'TCP')
            
            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
            reverse_flow_id = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}:{protocol}"
            
            # Check if flow exists (in either direction)
            if flow_id in flow_tracker:
                flow = flow_tracker[flow_id]
                flow.packets_sent += 1
                flow.bytes_sent += packet.get('size', 0)
            elif reverse_flow_id in flow_tracker:
                flow = flow_tracker[reverse_flow_id]
                flow.packets_received += 1
                flow.bytes_received += packet.get('size', 0)
            else:
                # Create new flow
                flow = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=datetime.now(),
                    bytes_sent=packet.get('size', 0),
                    packets_sent=1
                )
                flow_tracker[flow_id] = flow
                flows.append(flow)
        
        return flows
    
    def _analyze_flows(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze network flows for patterns and statistics"""
        analysis = {
            'total_flows': len(flows),
            'protocol_distribution': Counter(),
            'port_analysis': {
                'top_destination_ports': Counter(),
                'top_source_ports': Counter(),
                'unusual_ports': []
            },
            'traffic_volume': {
                'total_bytes': 0,
                'total_packets': 0,
                'top_talkers': [],
                'top_destinations': []
            },
            'connection_patterns': {
                'short_lived_connections': 0,
                'long_lived_connections': 0,
                'failed_connections': 0
            }
        }
        
        # Protocol distribution
        for flow in flows:
            analysis['protocol_distribution'][flow.protocol] += 1
            analysis['port_analysis']['top_destination_ports'][flow.dst_port] += 1
            analysis['port_analysis']['top_source_ports'][flow.src_port] += 1
            
            total_bytes = flow.bytes_sent + flow.bytes_received
            total_packets = flow.packets_sent + flow.packets_received
            
            analysis['traffic_volume']['total_bytes'] += total_bytes
            analysis['traffic_volume']['total_packets'] += total_packets
        
        # Identify unusual ports
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
        for port, count in analysis['port_analysis']['top_destination_ports'].items():
            if port not in common_ports and count > 5:
                analysis['port_analysis']['unusual_ports'].append({
                    'port': port,
                    'connections': count,
                    'service': self._identify_service(port)
                })
        
        # Traffic volume analysis
        src_traffic = defaultdict(int)
        dst_traffic = defaultdict(int)
        
        for flow in flows:
            src_traffic[flow.src_ip] += flow.bytes_sent + flow.bytes_received
            dst_traffic[flow.dst_ip] += flow.bytes_sent + flow.bytes_received
        
        analysis['traffic_volume']['top_talkers'] = [
            {'ip': ip, 'bytes': bytes_count} 
            for ip, bytes_count in sorted(src_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        analysis['traffic_volume']['top_destinations'] = [
            {'ip': ip, 'bytes': bytes_count}
            for ip, bytes_count in sorted(dst_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        return analysis
    
    def _analyze_protocols(self, flows: List[NetworkFlow]) -> Dict:
        """Perform protocol-specific analysis"""
        protocol_analysis = {}
        
        # Group flows by protocol
        protocol_flows = defaultdict(list)
        for flow in flows:
            protocol_flows[flow.protocol].append(flow)
        
        # Analyze each protocol
        for protocol, protocol_flow_list in protocol_flows.items():
            if protocol in self.protocol_analyzers:
                protocol_analysis[protocol] = self.protocol_analyzers[protocol](protocol_flow_list)
            else:
                protocol_analysis[protocol] = self._analyze_generic_protocol(protocol_flow_list)
        
        return protocol_analysis
    
    def _analyze_http_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze HTTP traffic"""
        analysis = {
            'total_flows': len(flows),
            'web_servers': set(),
            'user_agents': Counter(),
            'methods': Counter(),
            'status_codes': Counter(),
            'suspicious_patterns': []
        }
        
        for flow in flows:
            analysis['web_servers'].add(flow.dst_ip)
            
            # Look for suspicious patterns
            if flow.dst_port not in [80, 8080, 8000]:
                analysis['suspicious_patterns'].append({
                    'type': 'unusual_http_port',
                    'flow': f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
                    'description': f'HTTP traffic on unusual port {flow.dst_port}'
                })
        
        analysis['web_servers'] = list(analysis['web_servers'])
        return analysis
    
    def _analyze_https_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze HTTPS traffic"""
        analysis = {
            'total_flows': len(flows),
            'ssl_servers': set(),
            'certificate_analysis': {},
            'encryption_strength': {},
            'suspicious_patterns': []
        }
        
        for flow in flows:
            analysis['ssl_servers'].add(flow.dst_ip)
            
            # Check for suspicious HTTPS patterns
            if flow.dst_port not in [443, 8443]:
                analysis['suspicious_patterns'].append({
                    'type': 'unusual_https_port',
                    'flow': f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
                    'description': f'HTTPS traffic on unusual port {flow.dst_port}'
                })
        
        analysis['ssl_servers'] = list(analysis['ssl_servers'])
        return analysis
    
    def _analyze_dns_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze DNS traffic for tunneling and suspicious activity"""
        analysis = {
            'total_flows': len(flows),
            'dns_servers': set(),
            'query_patterns': {},
            'suspicious_domains': [],
            'potential_tunneling': []
        }
        
        for flow in flows:
            if flow.dst_port == 53:
                analysis['dns_servers'].add(flow.dst_ip)
                
                # Check for potential DNS tunneling
                total_bytes = flow.bytes_sent + flow.bytes_received
                if total_bytes > self.suspicious_patterns['dns_tunneling']['thresholds']['query_size_threshold']:
                    analysis['potential_tunneling'].append({
                        'flow': f"{flow.src_ip}->{flow.dst_ip}",
                        'bytes': total_bytes,
                        'reason': 'Large DNS query/response'
                    })
        
        analysis['dns_servers'] = list(analysis['dns_servers'])
        return analysis
    
    def _analyze_smb_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze SMB traffic for lateral movement"""
        analysis = {
            'total_flows': len(flows),
            'smb_servers': set(),
            'smb_clients': set(),
            'suspicious_activity': []
        }
        
        for flow in flows:
            if flow.dst_port in [135, 139, 445]:
                analysis['smb_servers'].add(flow.dst_ip)
                analysis['smb_clients'].add(flow.src_ip)
                
                # Check for potential lateral movement
                if self._is_internal_ip(flow.src_ip) and self._is_internal_ip(flow.dst_ip):
                    analysis['suspicious_activity'].append({
                        'type': 'internal_smb_access',
                        'flow': f"{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}",
                        'description': 'Internal SMB access - potential lateral movement'
                    })
        
        analysis['smb_servers'] = list(analysis['smb_servers'])
        analysis['smb_clients'] = list(analysis['smb_clients'])
        return analysis
    
    def _analyze_ftp_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze FTP traffic"""
        analysis = {
            'total_flows': len(flows),
            'ftp_servers': set(),
            'data_transfers': [],
            'authentication_attempts': 0
        }
        
        for flow in flows:
            if flow.dst_port in [20, 21]:
                analysis['ftp_servers'].add(flow.dst_ip)
                
                if flow.dst_port == 20:  # FTP data
                    total_bytes = flow.bytes_sent + flow.bytes_received
                    analysis['data_transfers'].append({
                        'server': flow.dst_ip,
                        'client': flow.src_ip,
                        'bytes': total_bytes
                    })
        
        analysis['ftp_servers'] = list(analysis['ftp_servers'])
        return analysis
    
    def _analyze_ssh_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze SSH traffic"""
        analysis = {
            'total_flows': len(flows),
            'ssh_servers': set(),
            'ssh_clients': set(),
            'potential_brute_force': []
        }
        
        # Group by client-server pairs
        ssh_attempts = defaultdict(int)
        
        for flow in flows:
            if flow.dst_port == 22:
                analysis['ssh_servers'].add(flow.dst_ip)
                analysis['ssh_clients'].add(flow.src_ip)
                ssh_attempts[(flow.src_ip, flow.dst_ip)] += 1
        
        # Check for potential brute force
        for (client, server), attempts in ssh_attempts.items():
            if attempts > 10:  # More than 10 attempts
                analysis['potential_brute_force'].append({
                    'client': client,
                    'server': server,
                    'attempts': attempts,
                    'severity': 'HIGH' if attempts > 20 else 'MEDIUM'
                })
        
        analysis['ssh_servers'] = list(analysis['ssh_servers'])
        analysis['ssh_clients'] = list(analysis['ssh_clients'])
        return analysis
    
    def _analyze_telnet_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze Telnet traffic"""
        analysis = {
            'total_flows': len(flows),
            'telnet_servers': set(),
            'security_risk': 'HIGH',
            'recommendation': 'Replace Telnet with SSH for secure remote access'
        }
        
        for flow in flows:
            if flow.dst_port == 23:
                analysis['telnet_servers'].add(flow.dst_ip)
        
        analysis['telnet_servers'] = list(analysis['telnet_servers'])
        return analysis
    
    def _analyze_icmp_traffic(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze ICMP traffic"""
        analysis = {
            'total_flows': len(flows),
            'icmp_types': Counter(),
            'potential_scanning': [],
            'tunnel_detection': []
        }
        
        # Group ICMP by source
        icmp_by_source = defaultdict(list)
        
        for flow in flows:
            if flow.protocol.upper() == 'ICMP':
                icmp_by_source[flow.src_ip].append(flow)
        
        # Check for potential scanning
        for src_ip, src_flows in icmp_by_source.items():
            unique_destinations = set(flow.dst_ip for flow in src_flows)
            if len(unique_destinations) > 20:  # Pinging many destinations
                analysis['potential_scanning'].append({
                    'source': src_ip,
                    'destinations': len(unique_destinations),
                    'packets': len(src_flows)
                })
            
            # Check for potential ICMP tunneling
            total_bytes = sum(flow.bytes_sent + flow.bytes_received for flow in src_flows)
            if total_bytes > 10000:  # Large amount of ICMP data
                analysis['tunnel_detection'].append({
                    'source': src_ip,
                    'total_bytes': total_bytes,
                    'packet_count': len(src_flows)
                })
        
        return analysis
    
    def _analyze_generic_protocol(self, flows: List[NetworkFlow]) -> Dict:
        """Generic analysis for unknown protocols"""
        analysis = {
            'total_flows': len(flows),
            'unique_sources': len(set(flow.src_ip for flow in flows)),
            'unique_destinations': len(set(flow.dst_ip for flow in flows)),
            'total_bytes': sum(flow.bytes_sent + flow.bytes_received for flow in flows),
            'avg_flow_size': 0
        }
        
        if flows:
            analysis['avg_flow_size'] = int(analysis['total_bytes'] / len(flows))
        
        return analysis
    
    def _detect_threats(self, flows: List[NetworkFlow]) -> Dict:
        """Detect network threats using pattern matching"""
        threat_detection = {
            'threats_detected': [],
            'risk_score': 0,
            'threat_categories': Counter(),
            'affected_hosts': set()
        }
        
        # Port scanning detection
        port_scan_threats = self._detect_port_scanning(flows)
        threat_detection['threats_detected'].extend(port_scan_threats)
        
        # DNS tunneling detection
        dns_tunnel_threats = self._detect_dns_tunneling(flows)
        threat_detection['threats_detected'].extend(dns_tunnel_threats)
        
        # Data exfiltration detection
        exfiltration_threats = self._detect_data_exfiltration(flows)
        threat_detection['threats_detected'].extend(exfiltration_threats)
        
        # Lateral movement detection
        lateral_threats = self._detect_lateral_movement(flows)
        threat_detection['threats_detected'].extend(lateral_threats)
        
        # C2 communication detection
        c2_threats = self._detect_c2_communication(flows)
        threat_detection['threats_detected'].extend(c2_threats)
        
        # Calculate overall risk score
        for threat in threat_detection['threats_detected']:
            severity = threat.get('severity', 'LOW')
            if severity == 'CRITICAL':
                threat_detection['risk_score'] += 25
            elif severity == 'HIGH':
                threat_detection['risk_score'] += 15
            elif severity == 'MEDIUM':
                threat_detection['risk_score'] += 10
            else:
                threat_detection['risk_score'] += 5
            
            threat_detection['threat_categories'][threat['category']] += 1
            threat_detection['affected_hosts'].update(threat.get('affected_hosts', []))
        
        threat_detection['affected_hosts'] = list(threat_detection['affected_hosts'])
        return threat_detection
    
    def _detect_port_scanning(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Detect port scanning activities"""
        threats = []
        
        # Group flows by source IP
        source_flows = defaultdict(list)
        for flow in flows:
            source_flows[flow.src_ip].append(flow)
        
        for src_ip, src_flows in source_flows.items():
            # Count unique destination ports
            unique_ports = set(flow.dst_port for flow in src_flows)
            unique_hosts = set(flow.dst_ip for flow in src_flows)
            
            # Check against thresholds
            if len(unique_ports) > self.suspicious_patterns['port_scanning']['thresholds']['ports_per_minute']:
                threats.append({
                    'category': 'port_scanning',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Port scanning detected: {len(unique_ports)} unique ports scanned',
                    'unique_ports': len(unique_ports),
                    'unique_hosts': len(unique_hosts),
                    'affected_hosts': list(unique_hosts)[:10]  # Limit to first 10
                })
        
        return threats
    
    def _detect_dns_tunneling(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Detect DNS tunneling activities"""
        threats = []
        
        dns_flows = [flow for flow in flows if flow.dst_port == 53]
        if not dns_flows:
            return threats
        
        # Group by source IP
        source_dns = defaultdict(list)
        for flow in dns_flows:
            source_dns[flow.src_ip].append(flow)
        
        for src_ip, src_flows in source_dns.items():
            total_bytes = sum(flow.bytes_sent + flow.bytes_received for flow in src_flows)
            avg_query_size = total_bytes / len(src_flows) if src_flows else 0
            
            if avg_query_size > self.suspicious_patterns['dns_tunneling']['thresholds']['query_size_threshold']:
                threats.append({
                    'category': 'dns_tunneling',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'DNS tunneling detected: avg query size {avg_query_size:.0f} bytes',
                    'total_bytes': total_bytes,
                    'query_count': len(src_flows),
                    'affected_hosts': [src_ip]
                })
        
        return threats
    
    def _detect_data_exfiltration(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Detect potential data exfiltration"""
        threats = []
        
        # Group outbound flows by source
        outbound_flows = defaultdict(list)
        for flow in flows:
            if self._is_internal_ip(flow.src_ip) and not self._is_internal_ip(flow.dst_ip):
                outbound_flows[flow.src_ip].append(flow)
        
        for src_ip, src_flows in outbound_flows.items():
            total_bytes_sent = sum(flow.bytes_sent for flow in src_flows)
            
            if total_bytes_sent > self.suspicious_patterns['data_exfiltration']['thresholds']['bytes_threshold']:
                unique_destinations = set(flow.dst_ip for flow in src_flows)
                
                threats.append({
                    'category': 'data_exfiltration',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': f'Large outbound data transfer: {total_bytes_sent:,} bytes',
                    'bytes_sent': total_bytes_sent,
                    'destinations': list(unique_destinations),
                    'flow_count': len(src_flows),
                    'affected_hosts': [src_ip]
                })
        
        return threats
    
    def _detect_lateral_movement(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Detect lateral movement within network"""
        threats = []
        
        # Look for internal-to-internal connections on service ports
        service_ports = self.suspicious_patterns['lateral_movement']['thresholds']['service_ports']
        
        internal_flows = defaultdict(list)
        for flow in flows:
            if (self._is_internal_ip(flow.src_ip) and 
                self._is_internal_ip(flow.dst_ip) and 
                flow.dst_port in service_ports):
                internal_flows[flow.src_ip].append(flow)
        
        for src_ip, src_flows in internal_flows.items():
            unique_targets = set(flow.dst_ip for flow in src_flows)
            
            if len(unique_targets) > self.suspicious_patterns['lateral_movement']['thresholds']['internal_connections_threshold']:
                threats.append({
                    'category': 'lateral_movement',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Lateral movement detected: connections to {len(unique_targets)} internal hosts',
                    'target_count': len(unique_targets),
                    'targets': list(unique_targets)[:10],
                    'services_accessed': list(set(flow.dst_port for flow in src_flows)),
                    'affected_hosts': [src_ip] + list(unique_targets)[:10]
                })
        
        return threats
    
    def _detect_c2_communication(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Detect command and control communications"""
        threats = []
        
        # Look for beacon patterns (regular communication intervals)
        outbound_flows = defaultdict(list)
        for flow in flows:
            if self._is_internal_ip(flow.src_ip) and not self._is_internal_ip(flow.dst_ip):
                outbound_flows[(flow.src_ip, flow.dst_ip)].append(flow)
        
        for (src_ip, dst_ip), connection_flows in outbound_flows.items():
            if len(connection_flows) >= 5:  # At least 5 connections to analyze pattern
                # Analyze timing patterns (simplified)
                timestamps = [flow.start_time for flow in connection_flows]
                timestamps.sort()
                
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)
                
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    interval_variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                    regularity = 1 - (interval_variance / (avg_interval ** 2)) if avg_interval > 0 else 0
                    
                    if regularity > self.suspicious_patterns['c2_communication']['thresholds']['beacon_regularity_threshold']:
                        threats.append({
                            'category': 'c2_communication',
                            'severity': 'CRITICAL',
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'description': f'C2 beacon detected: {regularity:.2f} regularity score',
                            'connection_count': len(connection_flows),
                            'avg_interval': avg_interval,
                            'regularity_score': regularity,
                            'affected_hosts': [src_ip]
                        })
        
        return threats
    
    def _detect_anomalies(self, flows: List[NetworkFlow]) -> Dict:
        """Detect statistical anomalies in network traffic"""
        anomalies = {
            'volume_anomalies': [],
            'timing_anomalies': [],
            'protocol_anomalies': [],
            'geographic_anomalies': []
        }
        
        # Volume anomaly detection
        hourly_volume = defaultdict(int)
        for flow in flows:
            hour = flow.start_time.hour
            hourly_volume[hour] += flow.bytes_sent + flow.bytes_received
        
        if hourly_volume:
            volumes = list(hourly_volume.values())
            avg_volume = sum(volumes) / len(volumes)
            
            for hour, volume in hourly_volume.items():
                if volume > avg_volume * 3:  # 3x above average
                    anomalies['volume_anomalies'].append({
                        'hour': hour,
                        'volume': volume,
                        'baseline': avg_volume,
                        'deviation_factor': volume / avg_volume
                    })
        
        # Protocol anomaly detection
        protocol_counts = Counter(flow.protocol for flow in flows)
        total_flows = len(flows)
        
        for protocol, count in protocol_counts.items():
            percentage = (count / total_flows) * 100
            
            # Flag protocols that make up more than 80% of traffic
            if percentage > 80:
                anomalies['protocol_anomalies'].append({
                    'protocol': protocol,
                    'percentage': percentage,
                    'count': count,
                    'anomaly_type': 'dominant_protocol'
                })
        
        return anomalies
    
    def _analyze_geography(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze geographic distribution of traffic"""
        geographic_analysis = {
            'countries': Counter(),
            'regions': Counter(),
            'suspicious_locations': [],
            'internal_external_ratio': {
                'internal_flows': 0,
                'external_flows': 0,
                'mixed_flows': 0
            }
        }
        
        for flow in flows:
            src_internal = self._is_internal_ip(flow.src_ip)
            dst_internal = self._is_internal_ip(flow.dst_ip)
            
            if src_internal and dst_internal:
                geographic_analysis['internal_external_ratio']['internal_flows'] += 1
            elif not src_internal and not dst_internal:
                geographic_analysis['internal_external_ratio']['external_flows'] += 1
            else:
                geographic_analysis['internal_external_ratio']['mixed_flows'] += 1
            
            # Geographic lookup would be implemented with GeoIP database
            # For now, using simplified logic
            if not dst_internal:
                country = self._get_country_from_ip(flow.dst_ip)
                geographic_analysis['countries'][country] += 1
        
        return geographic_analysis
    
    def _analyze_timeline(self, flows: List[NetworkFlow]) -> Dict:
        """Analyze traffic timeline for patterns"""
        timeline_analysis = {
            'hourly_distribution': defaultdict(int),
            'daily_patterns': {},
            'peak_activity_hours': [],
            'off_hours_activity': []
        }
        
        for flow in flows:
            hour = flow.start_time.hour
            timeline_analysis['hourly_distribution'][hour] += 1
        
        # Identify peak hours
        if timeline_analysis['hourly_distribution']:
            max_activity = max(timeline_analysis['hourly_distribution'].values())
            for hour, count in timeline_analysis['hourly_distribution'].items():
                if count > max_activity * 0.8:  # Within 80% of peak
                    timeline_analysis['peak_activity_hours'].append(hour)
                
                # Check for off-hours activity
                if (hour >= 22 or hour <= 6) and count > 0:
                    timeline_analysis['off_hours_activity'].append({
                        'hour': hour,
                        'flow_count': count
                    })
        
        return timeline_analysis
    
    def _generate_network_recommendations(self, analysis_results: Dict) -> List[str]:
        """Generate network security recommendations"""
        recommendations = []
        
        threat_detection = analysis_results.get('threat_detection', {})
        threats = threat_detection.get('threats_detected', [])
        risk_score = threat_detection.get('risk_score', 0)
        
        # Risk-based recommendations
        if risk_score > 75:
            recommendations.extend([
                'CRITICAL: Immediate network isolation required for affected hosts',
                'Activate incident response team',
                'Implement emergency network segmentation',
                'Block identified malicious IPs at perimeter'
            ])
        elif risk_score > 50:
            recommendations.extend([
                'HIGH PRIORITY: Enhanced network monitoring required',
                'Review firewall rules and access controls',
                'Implement additional network segmentation',
                'Enable deep packet inspection'
            ])
        elif risk_score > 25:
            recommendations.extend([
                'MEDIUM PRIORITY: Investigate identified anomalies',
                'Update network security policies',
                'Consider deploying additional monitoring tools'
            ])
        
        # Threat-specific recommendations
        threat_categories = threat_detection.get('threat_categories', {})
        
        if 'port_scanning' in threat_categories:
            recommendations.append('Deploy network intrusion detection system (NIDS)')
            recommendations.append('Implement rate limiting for connection attempts')
        
        if 'dns_tunneling' in threat_categories:
            recommendations.append('Monitor DNS traffic for anomalies')
            recommendations.append('Implement DNS filtering and logging')
        
        if 'data_exfiltration' in threat_categories:
            recommendations.append('Implement data loss prevention (DLP) controls')
            recommendations.append('Monitor large outbound data transfers')
        
        if 'lateral_movement' in threat_categories:
            recommendations.append('Implement network segmentation')
            recommendations.append('Deploy endpoint detection and response (EDR)')
        
        if 'c2_communication' in threat_categories:
            recommendations.append('Block identified C2 domains and IPs')
            recommendations.append('Implement behavioral analysis for network traffic')
        
        # Protocol-specific recommendations
        protocol_analysis = analysis_results.get('protocol_analysis', {})
        
        if 'TELNET' in protocol_analysis:
            recommendations.append('Replace Telnet with SSH for secure remote access')
        
        if 'FTP' in protocol_analysis:
            recommendations.append('Consider replacing FTP with SFTP or FTPS')
        
        # General recommendations
        recommendations.extend([
            'Regularly update network security monitoring tools',
            'Conduct periodic network security assessments',
            'Implement network traffic baselining',
            'Provide network security training to administrators'
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    # Helper methods
    def _identify_service(self, port: int) -> str:
        """Identify service by port number"""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP'
        }
        return common_services.get(port, f'Unknown ({port})')
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private"""
        if not ip:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return True
    
    def _get_country_from_ip(self, ip: str) -> str:
        """Get country from IP address (simplified)"""
        # In a real implementation, this would use GeoIP database
        if self._is_internal_ip(ip):
            return 'Internal'
        
        # Simplified geographic detection based on IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            first_octet = int(str(ip_obj).split('.')[0])
            
            if first_octet in range(1, 32):
                return 'US'
            elif first_octet in range(32, 64):
                return 'Europe'
            elif first_octet in range(64, 96):
                return 'Asia'
            elif first_octet in range(96, 128):
                return 'Other'
            else:
                return 'Unknown'
        except ValueError:
            return 'Invalid'

class NetworkForensics:
    def __init__(self):
        self.evidence_chain = []
        self.analysis_tools = self._initialize_analysis_tools()
        
    def _initialize_analysis_tools(self) -> Dict:
        """Initialize network forensics tools"""
        return {
            'packet_analysis': self._analyze_packets,
            'flow_reconstruction': self._reconstruct_flows,
            'protocol_decoding': self._decode_protocols,
            'artifact_extraction': self._extract_artifacts,
            'timeline_reconstruction': self._reconstruct_timeline
        }
    
    def analyze_network_evidence(self, pcap_data: bytes) -> Dict:
        """Analyze network evidence from packet capture"""
        analysis_results = {
            'analysis_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'timestamp': datetime.now().isoformat(),
            'packet_analysis': {},
            'flow_reconstruction': {},
            'protocol_analysis': {},
            'extracted_artifacts': {},
            'timeline': {},
            'forensic_findings': []
        }
        
        # Note: In a real implementation, this would parse actual PCAP data
        # For this demonstration, we'll provide structure and methodology
        
        analysis_results['packet_analysis'] = self._analyze_packets(pcap_data)
        analysis_results['flow_reconstruction'] = self._reconstruct_flows(pcap_data)
        analysis_results['protocol_analysis'] = self._decode_protocols(pcap_data)
        analysis_results['extracted_artifacts'] = self._extract_artifacts(pcap_data)
        analysis_results['timeline'] = self._reconstruct_timeline(pcap_data)
        
        return analysis_results
    
    def _analyze_packets(self, pcap_data: bytes) -> Dict:
        """Analyze individual packets"""
        return {
            'total_packets': 0,
            'packet_types': {},
            'malformed_packets': [],
            'suspicious_packets': [],
            'note': 'Packet analysis requires PCAP parsing library'
        }
    
    def _reconstruct_flows(self, pcap_data: bytes) -> Dict:
        """Reconstruct network flows from packets"""
        return {
            'total_flows': 0,
            'completed_flows': 0,
            'incomplete_flows': 0,
            'suspicious_flows': [],
            'note': 'Flow reconstruction requires TCP stream analysis'
        }
    
    def _decode_protocols(self, pcap_data: bytes) -> Dict:
        """Decode network protocols"""
        return {
            'protocols_detected': [],
            'application_data': {},
            'credentials_found': [],
            'note': 'Protocol decoding requires specialized parsers'
        }
    
    def _extract_artifacts(self, pcap_data: bytes) -> Dict:
        """Extract forensic artifacts from network traffic"""
        return {
            'files_extracted': [],
            'urls_found': [],
            'credentials_detected': [],
            'malware_indicators': [],
            'note': 'Artifact extraction requires deep packet inspection'
        }
    
    def _reconstruct_timeline(self, pcap_data: bytes) -> Dict:
        """Reconstruct timeline of network events"""
        return {
            'events': [],
            'timeline_gaps': [],
            'correlation_points': [],
            'note': 'Timeline reconstruction requires timestamp analysis'
        }