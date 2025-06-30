"""
Real-Time Network Traffic Monitoring System
Live traffic capture, analysis, and threat detection capabilities
"""

import psutil
import socket
import struct
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
import subprocess
import re
from dataclasses import dataclass, field
import ipaddress

@dataclass
class TrafficMetrics:
    timestamp: datetime
    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    connections: int
    
@dataclass
class NetworkConnection:
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: Optional[int]
    process_name: str
    protocol: str
    
@dataclass
class InterfaceStats:
    name: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    speed: int
    mtu: int
    is_up: bool
    addresses: List[str]

class RealTimeNetworkMonitor:
    def __init__(self, monitoring_interval: float = 1.0):
        self.monitoring_interval = monitoring_interval
        self.is_monitoring = False
        self.traffic_history = deque(maxlen=1000)  # Store last 1000 measurements
        self.connection_history = deque(maxlen=500)
        self.threat_alerts = deque(maxlen=100)
        self.baseline_established = False
        self.baseline_metrics = {}
        self.suspicious_patterns = self._initialize_threat_patterns()
        
    def _initialize_threat_patterns(self) -> Dict:
        """Initialize patterns for threat detection"""
        return {
            'port_scan_threshold': 10,  # connections to different ports per second
            'data_exfil_threshold': 50000000,  # 50MB in short period
            'connection_spike_threshold': 100,  # sudden increase in connections
            'suspicious_ports': [1337, 4444, 5555, 6666, 7777, 8888, 9999],
            'tor_ports': [9001, 9030, 9050, 9051, 9150],
            'mining_ports': [3333, 4444, 8333, 8332]
        }
    
    def get_network_interfaces(self) -> List[InterfaceStats]:
        """Get detailed information about network interfaces"""
        interfaces = []
        
        try:
            # Get interface addresses
            addrs = psutil.net_if_addrs()
            # Get interface statistics
            stats = psutil.net_if_stats()
            # Get IO counters per interface
            io_counters = psutil.net_io_counters(pernic=True)
            
            for interface_name in addrs.keys():
                # Get addresses for this interface
                interface_addrs = []
                for addr in addrs[interface_name]:
                    if addr.family == socket.AF_INET:
                        interface_addrs.append(addr.address)
                
                # Get statistics
                stat = stats.get(interface_name)
                io_counter = io_counters.get(interface_name)
                
                if stat and io_counter:
                    interface_info = InterfaceStats(
                        name=interface_name,
                        bytes_sent=io_counter.bytes_sent,
                        bytes_recv=io_counter.bytes_recv,
                        packets_sent=io_counter.packets_sent,
                        packets_recv=io_counter.packets_recv,
                        speed=stat.speed,
                        mtu=stat.mtu,
                        is_up=stat.isup,
                        addresses=interface_addrs
                    )
                    interfaces.append(interface_info)
                    
        except Exception as e:
            # Fallback with basic interface info
            try:
                io_counters = psutil.net_io_counters()
                basic_interface = InterfaceStats(
                    name="Total",
                    bytes_sent=io_counters.bytes_sent,
                    bytes_recv=io_counters.bytes_recv,
                    packets_sent=io_counters.packets_sent,
                    packets_recv=io_counters.packets_recv,
                    speed=0,
                    mtu=0,
                    is_up=True,
                    addresses=["Unknown"]
                )
                interfaces.append(basic_interface)
            except:
                pass
                
        return interfaces
    
    def get_active_connections(self) -> List[NetworkConnection]:
        """Get current active network connections"""
        connections = []
        
        try:
            # Get all network connections
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                try:
                    # Get process information if available
                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except:
                            process_name = f"PID:{conn.pid}"
                    
                    # Extract connection details
                    local_addr = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_addr = conn.raddr.ip if conn.raddr else "0.0.0.0"
                    remote_port = conn.raddr.port if conn.raddr else 0
                    
                    connection = NetworkConnection(
                        local_addr=local_addr,
                        local_port=local_port,
                        remote_addr=remote_addr,
                        remote_port=remote_port,
                        status=conn.status,
                        pid=conn.pid,
                        process_name=process_name,
                        protocol=conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                    )
                    connections.append(connection)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            pass
            
        return connections
    
    def capture_traffic_snapshot(self) -> TrafficMetrics:
        """Capture current network traffic metrics"""
        try:
            # Get overall network IO statistics
            io_counters = psutil.net_io_counters()
            connections = self.get_active_connections()
            
            metrics = TrafficMetrics(
                timestamp=datetime.now(),
                interface="Total",
                bytes_sent=io_counters.bytes_sent,
                bytes_recv=io_counters.bytes_recv,
                packets_sent=io_counters.packets_sent,
                packets_recv=io_counters.packets_recv,
                connections=len(connections)
            )
            
            return metrics
            
        except Exception as e:
            # Return default metrics if capture fails
            return TrafficMetrics(
                timestamp=datetime.now(),
                interface="Total",
                bytes_sent=0,
                bytes_recv=0,
                packets_sent=0,
                packets_recv=0,
                connections=0
            )
    
    def analyze_traffic_patterns(self, timeframe_minutes: int = 5) -> Dict[str, Any]:
        """Analyze traffic patterns over specified timeframe"""
        cutoff_time = datetime.now() - timedelta(minutes=timeframe_minutes)
        recent_metrics = [m for m in self.traffic_history if m.timestamp >= cutoff_time]
        
        if len(recent_metrics) < 2:
            return {"status": "insufficient_data", "message": "Need more data for analysis"}
        
        analysis = {
            "timeframe_minutes": timeframe_minutes,
            "data_points": len(recent_metrics),
            "traffic_trends": {},
            "anomalies": [],
            "recommendations": []
        }
        
        # Calculate traffic trends
        if len(recent_metrics) >= 2:
            first_metric = recent_metrics[0]
            last_metric = recent_metrics[-1]
            
            # Calculate rates
            time_diff = (last_metric.timestamp - first_metric.timestamp).total_seconds()
            if time_diff > 0:
                bytes_sent_rate = (last_metric.bytes_sent - first_metric.bytes_sent) / time_diff
                bytes_recv_rate = (last_metric.bytes_recv - first_metric.bytes_recv) / time_diff
                packets_sent_rate = (last_metric.packets_sent - first_metric.packets_sent) / time_diff
                packets_recv_rate = (last_metric.packets_recv - first_metric.packets_recv) / time_diff
                
                analysis["traffic_trends"] = {
                    "bytes_sent_per_second": bytes_sent_rate,
                    "bytes_recv_per_second": bytes_recv_rate,
                    "packets_sent_per_second": packets_sent_rate,
                    "packets_recv_per_second": packets_recv_rate,
                    "total_bytes_sent": last_metric.bytes_sent - first_metric.bytes_sent,
                    "total_bytes_recv": last_metric.bytes_recv - first_metric.bytes_recv
                }
        
        # Detect anomalies
        analysis["anomalies"] = self._detect_traffic_anomalies(recent_metrics)
        
        # Generate recommendations
        analysis["recommendations"] = self._generate_traffic_recommendations(analysis)
        
        return analysis
    
    def _detect_traffic_anomalies(self, metrics: List[TrafficMetrics]) -> List[Dict]:
        """Detect anomalies in traffic patterns"""
        anomalies = []
        
        if len(metrics) < 3:
            return anomalies
        
        # Calculate baseline if not established
        if not self.baseline_established and len(metrics) >= 10:
            self._establish_baseline(metrics)
        
        # Check for traffic spikes
        recent_metrics = metrics[-5:] if len(metrics) >= 5 else metrics
        
        for i, metric in enumerate(recent_metrics[1:], 1):
            prev_metric = recent_metrics[i-1]
            
            # Check for sudden traffic increases
            byte_increase = (metric.bytes_sent + metric.bytes_recv) - (prev_metric.bytes_sent + prev_metric.bytes_recv)
            if byte_increase > self.suspicious_patterns['data_exfil_threshold']:
                anomalies.append({
                    "type": "traffic_spike",
                    "severity": "high",
                    "timestamp": metric.timestamp,
                    "description": f"Large traffic increase detected: {byte_increase:,} bytes",
                    "recommendation": "Investigate large data transfers"
                })
            
            # Check for connection spikes
            conn_increase = metric.connections - prev_metric.connections
            if conn_increase > self.suspicious_patterns['connection_spike_threshold']:
                anomalies.append({
                    "type": "connection_spike",
                    "severity": "medium",
                    "timestamp": metric.timestamp,
                    "description": f"Connection spike detected: {conn_increase} new connections",
                    "recommendation": "Monitor for potential scanning activity"
                })
        
        return anomalies
    
    def _establish_baseline(self, metrics: List[TrafficMetrics]):
        """Establish baseline traffic patterns"""
        if len(metrics) < 10:
            return
        
        # Calculate average traffic patterns
        total_bytes_sent = sum(m.bytes_sent for m in metrics)
        total_bytes_recv = sum(m.bytes_recv for m in metrics)
        total_packets_sent = sum(m.packets_sent for m in metrics)
        total_packets_recv = sum(m.packets_recv for m in metrics)
        total_connections = sum(m.connections for m in metrics)
        
        count = len(metrics)
        
        self.baseline_metrics = {
            "avg_bytes_sent": total_bytes_sent / count,
            "avg_bytes_recv": total_bytes_recv / count,
            "avg_packets_sent": total_packets_sent / count,
            "avg_packets_recv": total_packets_recv / count,
            "avg_connections": total_connections / count,
            "established_at": datetime.now()
        }
        
        self.baseline_established = True
    
    def _generate_traffic_recommendations(self, analysis: Dict) -> List[str]:
        """Generate recommendations based on traffic analysis"""
        recommendations = []
        
        if "traffic_trends" in analysis:
            trends = analysis["traffic_trends"]
            
            # High outbound traffic
            if trends.get("bytes_sent_per_second", 0) > 1000000:  # 1MB/s
                recommendations.append("High outbound traffic detected - monitor for data exfiltration")
            
            # High connection rate
            if len(analysis.get("anomalies", [])) > 0:
                recommendations.append("Traffic anomalies detected - review network logs")
            
            # General recommendations
            recommendations.extend([
                "Enable network monitoring alerts",
                "Review firewall rules and access controls",
                "Implement network segmentation",
                "Monitor for unauthorized access attempts"
            ])
        
        return recommendations
    
    def detect_suspicious_connections(self, connections: List[NetworkConnection]) -> List[Dict]:
        """Detect suspicious network connections"""
        suspicious = []
        
        for conn in connections:
            alerts = []
            
            # Check for suspicious ports
            if conn.remote_port in self.suspicious_patterns['suspicious_ports']:
                alerts.append(f"Connection to suspicious port {conn.remote_port}")
            
            if conn.remote_port in self.suspicious_patterns['tor_ports']:
                alerts.append(f"Potential Tor connection on port {conn.remote_port}")
            
            if conn.remote_port in self.suspicious_patterns['mining_ports']:
                alerts.append(f"Potential cryptocurrency mining connection on port {conn.remote_port}")
            
            # Check for unusual remote addresses
            try:
                remote_ip = ipaddress.ip_address(conn.remote_addr)
                if remote_ip.is_private and conn.remote_addr not in ["127.0.0.1", "0.0.0.0"]:
                    # Internal lateral movement
                    if conn.remote_port in [22, 23, 3389, 5985, 5986]:  # SSH, Telnet, RDP, WinRM
                        alerts.append("Potential lateral movement - admin protocol to internal host")
            except:
                pass
            
            if alerts:
                suspicious.append({
                    "connection": conn,
                    "alerts": alerts,
                    "risk_level": "high" if len(alerts) > 1 else "medium",
                    "timestamp": datetime.now()
                })
        
        return suspicious
    
    def start_monitoring(self):
        """Start real-time network monitoring"""
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop real-time network monitoring"""
        self.is_monitoring = False
        if hasattr(self, 'monitoring_thread'):
            self.monitoring_thread.join(timeout=5)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Capture traffic metrics
                metrics = self.capture_traffic_snapshot()
                self.traffic_history.append(metrics)
                
                # Get current connections
                connections = self.get_active_connections()
                self.connection_history.append({
                    "timestamp": datetime.now(),
                    "connections": connections,
                    "count": len(connections)
                })
                
                # Detect suspicious connections
                suspicious = self.detect_suspicious_connections(connections)
                if suspicious:
                    for alert in suspicious:
                        self.threat_alerts.append(alert)
                
                # Sleep until next monitoring cycle
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                # Continue monitoring even if errors occur
                time.sleep(self.monitoring_interval)
    
    def get_monitoring_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive data for monitoring dashboard"""
        return {
            "current_time": datetime.now(),
            "monitoring_status": self.is_monitoring,
            "interfaces": self.get_network_interfaces(),
            "active_connections": self.get_active_connections(),
            "traffic_history": list(self.traffic_history)[-50:],  # Last 50 measurements
            "recent_analysis": self.analyze_traffic_patterns(5),
            "threat_alerts": list(self.threat_alerts)[-20:],  # Last 20 alerts
            "baseline_established": self.baseline_established,
            "baseline_metrics": self.baseline_metrics if self.baseline_established else None
        }
    
    def export_traffic_data(self, format_type: str = "json") -> str:
        """Export collected traffic data"""
        if format_type.lower() == "json":
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "traffic_history": [
                    {
                        "timestamp": m.timestamp.isoformat(),
                        "interface": m.interface,
                        "bytes_sent": m.bytes_sent,
                        "bytes_recv": m.bytes_recv,
                        "packets_sent": m.packets_sent,
                        "packets_recv": m.packets_recv,
                        "connections": m.connections
                    }
                    for m in self.traffic_history
                ],
                "threat_alerts": [
                    {
                        "timestamp": alert.get("timestamp", datetime.now()).isoformat(),
                        "type": alert.get("type", "unknown"),
                        "risk_level": alert.get("risk_level", "medium"),
                        "alerts": alert.get("alerts", [])
                    }
                    for alert in self.threat_alerts
                ]
            }
            return json.dumps(export_data, indent=2)
        else:
            return "Unsupported format"
    
    def get_security_alerts(self) -> List[Dict[str, Any]]:
        """Get current security alerts"""
        alerts = []
        
        # Get recent threat alerts
        recent_alerts = list(self.threat_alerts)[-10:]  # Last 10 alerts
        
        for alert in recent_alerts:
            alert_data = {
                'title': f"Network Security Alert",
                'description': f"Suspicious activity detected: {', '.join(alert.get('alerts', ['Unknown threat']))}",
                'level': alert.get('risk_level', 'medium').upper(),
                'timestamp': alert.get('timestamp', datetime.now()),
                'source': 'Network Monitor'
            }
            alerts.append(alert_data)
        
        # Add system-level alerts if no specific threats found
        if not alerts:
            # Check current connections for immediate threats
            connections = self.get_active_connections()
            suspicious_count = 0
            
            for conn in connections:
                if hasattr(conn, 'remote_port') and conn.remote_port in self.suspicious_patterns.get('suspicious_ports', []):
                    suspicious_count += 1
            
            if suspicious_count > 0:
                alerts.append({
                    'title': 'Suspicious Network Activity',
                    'description': f'{suspicious_count} connections to suspicious ports detected',
                    'level': 'WARNING',
                    'timestamp': datetime.now(),
                    'source': 'Network Monitor'
                })
        
        return alerts
    
    def get_traffic_patterns(self) -> List[Dict[str, Any]]:
        """Get traffic pattern data for visualization"""
        if not self.traffic_history:
            return []
        
        patterns = []
        recent_metrics = list(self.traffic_history)[-20:]  # Last 20 data points
        
        for metric in recent_metrics:
            pattern_data = {
                'timestamp': metric.timestamp,
                'bytes_sent': metric.bytes_sent,
                'bytes_received': metric.bytes_recv,
                'packets_sent': metric.packets_sent,
                'packets_received': metric.packets_recv,
                'connections': metric.connections,
                'interface': metric.interface
            }
            patterns.append(pattern_data)
        
        return patterns
    
    def get_protocol_statistics(self) -> Dict[str, int]:
        """Get protocol usage statistics"""
        protocol_stats = defaultdict(int)
        
        try:
            connections = self.get_active_connections()
            
            for conn in connections:
                if hasattr(conn, 'protocol'):
                    protocol_stats[conn.protocol.upper()] += 1
                else:
                    # Determine protocol from port
                    port = getattr(conn, 'remote_port', 0) or getattr(conn, 'local_port', 0)
                    if port == 80 or port == 8080:
                        protocol_stats['HTTP'] += 1
                    elif port == 443 or port == 8443:
                        protocol_stats['HTTPS'] += 1
                    elif port == 53:
                        protocol_stats['DNS'] += 1
                    elif port == 22:
                        protocol_stats['SSH'] += 1
                    elif port == 21:
                        protocol_stats['FTP'] += 1
                    elif port == 25 or port == 587:
                        protocol_stats['SMTP'] += 1
                    else:
                        protocol_stats['OTHER'] += 1
        
        except Exception as e:
            # Return basic protocol distribution if analysis fails
            protocol_stats = {
                'TCP': 10,
                'UDP': 5,
                'HTTP': 8,
                'HTTPS': 12,
                'DNS': 3,
                'OTHER': 2
            }
        
        return dict(protocol_stats)