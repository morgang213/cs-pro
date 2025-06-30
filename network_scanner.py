import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import ipaddress

class NetworkScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.full_ports = list(range(1, 1025))
    
    def scan_target(self, target, scan_type="quick_scan", custom_ports=None):
        """
        Scan a target for open ports and gather host information
        """
        try:
            # Resolve hostname to IP if necessary
            target_ip = self._resolve_target(target)
            if not target_ip:
                return None
            
            # Determine which ports to scan
            if scan_type == "quick_scan":
                ports_to_scan = self.common_ports
            elif scan_type == "full_scan":
                ports_to_scan = self.full_ports
            elif scan_type == "custom_ports" and custom_ports:
                ports_to_scan = self._parse_port_range(custom_ports)
            else:
                ports_to_scan = self.common_ports
            
            # Perform the scan
            open_ports = self._scan_ports(target_ip, ports_to_scan)
            host_info = self._get_host_info(target, target_ip)
            
            return {
                'target': target,
                'target_ip': target_ip,
                'open_ports': open_ports,
                'host_info': host_info,
                'scan_type': scan_type,
                'total_ports_scanned': len(ports_to_scan),
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            print(f"Error scanning target {target}: {str(e)}")
            return None
    
    def _resolve_target(self, target):
        """
        Resolve hostname to IP address
        """
        try:
            # Check if it's already an IP address
            ipaddress.ip_address(target)
            return target
        except ValueError:
            try:
                # Try to resolve hostname
                return socket.gethostbyname(target)
            except socket.gaierror:
                return None
    
    def _parse_port_range(self, port_string):
        """
        Parse port range string like "22,80,443" or "1-1000"
        """
        ports = []
        try:
            parts = port_string.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            return list(set(ports))  # Remove duplicates
        except:
            return self.common_ports
    
    def _scan_ports(self, target_ip, ports):
        """
        Scan multiple ports concurrently
        """
        open_ports = []
        
        def scan_single_port(port):
            if self._is_port_open(target_ip, port):
                service = self._identify_service(port)
                return {
                    'port': port,
                    'service': service,
                    'state': 'open'
                }
            return None
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(scan_single_port, ports)
            open_ports = [result for result in results if result is not None]
        
        return open_ports
    
    def _is_port_open(self, target_ip, port, timeout=3):
        """
        Check if a specific port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
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
        return service_map.get(port, 'Unknown')
    
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
                except:
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
            
            # Use secure subprocess call with validated input
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '5', target_ip],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False  # Explicitly disable shell
            )
            
            if ping_result.returncode == 0:
                output = ping_result.stdout
                if 'ttl=64' in output.lower():
                    return 'Linux/Unix'
                elif 'ttl=128' in output.lower():
                    return 'Windows'
                else:
                    return 'Unknown'
            else:
                return 'Unreachable'
                
        except:
            return 'Detection Failed'
