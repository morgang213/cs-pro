import ipaddress
import logging
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class NetworkScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            993,
            995,
            1723,
            3306,
            3389,
            5900,
            8080,
        ]
        self.full_ports = list(range(1, 1025))
        self.risky_ports = {
            21: "FTP",
            23: "Telnet",
            445: "SMB",
            3389: "RDP",
            5900: "VNC",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            9200: "Elasticsearch",
            11211: "Memcached",
            27017: "MongoDB",
        }

    def scan_target(
        self,
        target,
        scan_type="quick_scan",
        custom_ports=None,
        timeout=1.5,
        max_workers=100,
        grab_banners=False,
    ):
        """
        Scan a target for open ports and gather host information.

        Supported scan_type values:
        - quick_scan (default)
        - full_scan
        - custom_ports (requires custom_ports)
        - port_scan (alias for quick_scan; kept for compatibility)
        """
        started_at = time.time()
        try:
            if not target or not str(target).strip():
                return self._build_failed_scan_result(target, scan_type, "Target is required")

            # Resolve hostname to IP if necessary
            target_ip = self._resolve_target(target)
            if not target_ip:
                return self._build_failed_scan_result(target, scan_type, "Unable to resolve target")
            
            # Determine which ports to scan
            if scan_type == "quick_scan":
                ports_to_scan = self.common_ports
            elif scan_type == "full_scan":
                ports_to_scan = self.full_ports
            elif scan_type == "custom_ports" and custom_ports:
                ports_to_scan = self._parse_port_range(custom_ports)
            elif scan_type == "port_scan":
                ports_to_scan = self.common_ports
            else:
                ports_to_scan = self.common_ports

            if not ports_to_scan:
                return self._build_failed_scan_result(
                    target,
                    scan_type,
                    "No valid ports were selected for scanning",
                )
            
            # Perform the scan
            open_ports = self._scan_ports(
                target_ip,
                ports_to_scan,
                timeout=timeout,
                max_workers=max_workers,
                grab_banners=grab_banners,
            )
            host_info = self._get_host_info(target, target_ip)
            risk_summary = self._summarize_exposure(open_ports)
            duration = round(time.time() - started_at, 3)
            
            return {
                'status': 'completed',
                'target': target,
                'target_ip': target_ip,
                'open_ports': open_ports,
                'host_info': host_info,
                'scan_type': scan_type,
                'total_ports_scanned': len(ports_to_scan),
                'open_port_count': len(open_ports),
                'risk_summary': risk_summary,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration_seconds': duration,
            }
            
        except Exception as e:
            self.logger.exception("Error scanning target %s", target)
            return self._build_failed_scan_result(target, scan_type, str(e))

    def _build_failed_scan_result(self, target, scan_type, error_message):
        return {
            'status': 'failed',
            'target': target,
            'target_ip': None,
            'open_ports': [],
            'host_info': {},
            'scan_type': scan_type,
            'total_ports_scanned': 0,
            'open_port_count': 0,
            'risk_summary': {
                'risk_level': 'unknown',
                'high_risk_ports': [],
                'recommendations': ['Validate the target and retry the scan.'],
            },
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_duration_seconds': 0.0,
            'error': error_message,
        }
    
    def _resolve_target(self, target):
        """
        Resolve hostname to IP address
        """
        if target is None:
            return None

        cleaned_target = str(target).strip()
        if not cleaned_target:
            return None

        # Allow URL inputs by extracting the hostname.
        if '://' in cleaned_target:
            parsed = urlparse(cleaned_target)
            cleaned_target = parsed.hostname or ''

        try:
            # Check if it's already an IP address
            ipaddress.ip_address(cleaned_target)
            return cleaned_target
        except ValueError:
            try:
                # Try to resolve hostname
                return socket.gethostbyname(cleaned_target)
            except socket.gaierror:
                return None
    
    def _parse_port_range(self, port_string):
        """
        Parse port range string like "22,80,443" or "1-1000"
        """
        ports = set()
        try:
            if isinstance(port_string, (list, tuple, set)):
                parts = []
                for item in port_string:
                    parts.extend(re.split(r'[\s,]+', str(item).strip()))
            else:
                parts = re.split(r'[\s,]+', str(port_string).strip())

            for part in parts:
                part = part.strip()
                if not part:
                    continue

                if '-' in part:
                    start, end = map(int, part.split('-', 1))
                    if start > end:
                        start, end = end, start

                    for port in range(start, end + 1):
                        if 1 <= port <= 65535:
                            ports.add(port)
                else:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)

            return sorted(ports)
        except (TypeError, ValueError):
            self.logger.warning("Failed to parse custom ports '%s', using common ports", port_string)
            return self.common_ports

    def _scan_ports(self, target_ip, ports, timeout=1.5, max_workers=100, grab_banners=False):
        """
        Scan multiple ports concurrently
        """
        open_ports = []

        workers = max(1, min(int(max_workers), 250, len(ports)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._scan_single_port, target_ip, port, timeout, grab_banners): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        return sorted(open_ports, key=lambda item: item['port'])

    def _scan_single_port(self, target_ip, port, timeout, grab_banners):
        if self._is_port_open(target_ip, port, timeout=timeout):
            service = self._identify_service(port)
            result = {
                'port': port,
                'service': service,
                'state': 'open',
            }
            if grab_banners:
                banner = self._grab_banner(target_ip, port, timeout=timeout)
                if banner:
                    result['banner'] = banner
            return result
        return None

    def _is_port_open(self, target_ip, port, timeout=3):
        """
        Check if a specific port is open
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
            return result == 0
        except OSError:
            return False

    def _grab_banner(self, target_ip, port, timeout=1.5):
        """
        Attempt lightweight banner grabbing for service context.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((target_ip, port))

                if port in (80, 8080, 8000):
                    request_data = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(target_ip)
                    sock.sendall(request_data.encode('ascii', errors='ignore'))

                banner_data = sock.recv(256)
                if not banner_data:
                    return None

                banner = banner_data.decode('utf-8', errors='ignore').strip()
                banner = re.sub(r'\s+', ' ', banner)
                return banner[:120]
        except OSError:
            return None
    
    def _identify_service(self, port):
        """
        Identify common services running on specific ports
        """
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Alt'
        }
        if port in service_map:
            return service_map[port]

        try:
            return socket.getservbyport(port)
        except OSError:
            return 'Unknown'
    
    def _get_host_info(self, target, target_ip):
        """
        Gather additional host information
        """
        info = {
            'hostname': target,
            'ip_address': target_ip,
            'status': 'online'
        }
        
        try:
            # Try to get hostname if target was IP
            if target == target_ip:
                try:
                    hostname = socket.gethostbyaddr(target_ip)[0]
                    info['reverse_dns'] = hostname
                except (socket.herror, socket.gaierror, OSError):
                    info['reverse_dns'] = 'N/A'
            
            # Try to determine OS (basic ping-based detection)
            info['os_detection'] = self._detect_os(target_ip)
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def _detect_os(self, target_ip):
        """
        Basic OS detection using ping TTL values
        """
        try:
            # Validate IP address first to prevent injection
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                return "Unknown"

            os_name = platform.system().lower()
            if os_name == 'windows':
                command = ['ping', '-n', '1', '-w', '2500', target_ip]
            else:
                # macOS and Linux accept this pattern.
                command = ['ping', '-c', '1', '-W', '2', target_ip]

            ping_result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=6,
                shell=False,
            )

            if ping_result.returncode == 0:
                output = ping_result.stdout

                ttl_match = re.search(r'(?:ttl|hlim)[=\s](\d+)', output, re.IGNORECASE)
                ttl_value = int(ttl_match.group(1)) if ttl_match else None

                if ttl_value is None:
                    return 'Unknown'
                if ttl_value <= 64:
                    return 'Linux/Unix'
                if ttl_value <= 128:
                    return 'Windows'
                return 'Network Device/Other'

            return 'Unreachable'

        except (subprocess.SubprocessError, OSError, ValueError):
            return 'Detection Failed'

    def _summarize_exposure(self, open_ports):
        high_risk = []
        remote_admin = []

        for item in open_ports:
            port = item.get('port')
            service = item.get('service', 'Unknown')

            if port in self.risky_ports:
                high_risk.append({'port': port, 'service': service})
            if port in (22, 23, 3389, 5900):
                remote_admin.append({'port': port, 'service': service})

        risk_level = 'low'
        if len(high_risk) >= 5:
            risk_level = 'critical'
        elif len(high_risk) >= 3 or len(remote_admin) >= 2:
            risk_level = 'high'
        elif len(high_risk) >= 1 or len(open_ports) >= 8:
            risk_level = 'medium'

        recommendations = []
        if high_risk:
            recommendations.append('Restrict exposure of management and database ports with firewall rules.')
        if remote_admin:
            recommendations.append('Enforce MFA and source IP allow-lists for remote administration services.')
        if not open_ports:
            recommendations.append('No open ports detected in this scope. Keep host-based firewalls enabled.')
        if not recommendations:
            recommendations.append('Review service necessity and apply least-privilege network segmentation.')

        return {
            'risk_level': risk_level,
            'high_risk_ports': high_risk,
            'remote_admin_ports': remote_admin,
            'recommendations': recommendations,
        }
