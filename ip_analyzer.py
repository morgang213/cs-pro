import socket
import ipaddress
import requests
import json
import os
from urllib.parse import urlparse

class IPAnalyzer:
    def __init__(self):
        # API keys from environment variables
        self.ipinfo_token = os.getenv('IPINFO_TOKEN', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberSec-Analyzer/1.0'
        })
        # Set reasonable timeouts to prevent hanging
        self.timeout = 10  # 10 second timeout for external API calls
    
    def analyze_ip(self, ip_address):
        """
        Comprehensive IP address analysis
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            
            result = {
                'ip_address': str(ip_obj),
                'ip_version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'geolocation': {},
                'security': {},
                'reputation': {},
                'network_info': {}
            }
            
            # Skip analysis for private/local IPs
            if ip_obj.is_private or ip_obj.is_loopback:
                result['geolocation'] = {'status': 'Private/Local IP - No geolocation data'}
                result['security'] = {'status': 'Private/Local IP - No security analysis'}
                result['reputation'] = {'status': 'Private/Local IP - No reputation data'}
            else:
                # Get geolocation info
                # Temporarily disabled for performance
                # result['geolocation'] = self._get_geolocation(ip_address)
                
                # Get security/reputation info
                result['security'] = self._get_security_info(ip_address)
                result['reputation'] = self._get_reputation_info(ip_address)
            
            # Get network information
            result['network_info'] = self._get_network_info(ip_address)
            
            return result
            
        except ValueError:
            return {'error': 'Invalid IP address format'}
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def _get_geolocation(self, ip_address):
        """
        Get geolocation information for IP address
        """
        try:
            # Try IPInfo.io first (free tier available)
            if self.ipinfo_token:
                url = f"https://ipinfo.io/{ip_address}/json?token={self.ipinfo_token}"
            else:
                url = f"https://ipinfo.io/{ip_address}/json"
            
            response = self.session.get(url, timeout=2)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse location if available
                location = data.get('loc', '').split(',') if data.get('loc') else []
                
                return {
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'postal': data.get('postal', 'Unknown'),
                    'latitude': location[0] if len(location) > 0 else 'Unknown',
                    'longitude': location[1] if len(location) > 1 else 'Unknown',
                    'timezone': data.get('timezone', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'asn': data.get('org', '').split()[0] if data.get('org') else 'Unknown',
                    'source': 'IPInfo.io'
                }
            else:
                # Fallback to free service
                return self._get_geolocation_fallback(ip_address)
                
        except Exception as e:
            return {'error': f'Geolocation lookup failed: {str(e)}'}
    
    def _get_geolocation_fallback(self, ip_address):
        """
        Fallback geolocation service
        """
        try:
            # Using ip-api.com as fallback (free service)
            url = f"http://ip-api.com/json/{ip_address}"
            response = self.session.get(url, timeout=2)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'postal': data.get('zip', 'Unknown'),
                        'latitude': str(data.get('lat', 'Unknown')),
                        'longitude': str(data.get('lon', 'Unknown')),
                        'timezone': data.get('timezone', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'source': 'IP-API.com'
                    }
                else:
                    return {'error': 'Geolocation service failed'}
            else:
                return {'error': 'Unable to connect to geolocation service'}
                
        except Exception as e:
            return {'error': f'Fallback geolocation failed: {str(e)}'}
    
    def _get_security_info(self, ip_address):
        """
        Get security information about IP address
        """
        security_info = {
            'blacklists': [],
            'threat_feeds': [],
            'malware_associated': False,
            'botnet_member': False,
            'scanner_activity': False
        }
        
        try:
            # Skip external API calls for stability in production
            # These can be enabled when proper API keys are configured
            if self.virustotal_api_key:
                security_info['virustotal_status'] = 'API key available but disabled for stability'
            else:
                security_info['virustotal_status'] = 'No API key configured'
            
            if self.abuseipdb_api_key:
                security_info['abuseipdb_status'] = 'API key available but disabled for stability' 
            else:
                security_info['abuseipdb_status'] = 'No API key configured'
            
            # Skip port scanning for stability and performance
            security_info['open_ports'] = []
            security_info['scan_note'] = 'Port scanning disabled for stability'
            
            return security_info
            
        except Exception as e:
            return {'error': f'Security analysis failed: {str(e)}'}
    
    def _check_virustotal(self, ip_address):
        """
        Check IP address against VirusTotal
        """
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.virustotal_api_key,
                'ip': ip_address
            }
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'virustotal_detected': data.get('detected_urls', []),
                    'virustotal_malware_samples': len(data.get('detected_communicating_samples', [])),
                    'virustotal_reputation': 'Clean' if not data.get('detected_urls') else 'Suspicious',
                    'source': 'VirusTotal'
                }
            else:
                return {'error': 'VirusTotal API request failed'}
                
        except Exception as e:
            return {'error': f'VirusTotal check failed: {str(e)}'}
    
    def _check_abuseipdb(self, ip_address):
        """
        Check IP address against AbuseIPDB
        """
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                return {
                    'abuseipdb_confidence': data.get('abuseConfidencePercentage', 0),
                    'abuseipdb_reports': data.get('totalReports', 0),
                    'abuseipdb_country': data.get('countryCode', 'Unknown'),
                    'abuseipdb_whitelisted': data.get('isWhitelisted', False),
                    'source': 'AbuseIPDB'
                }
            else:
                return {'error': 'AbuseIPDB API request failed'}
                
        except Exception as e:
            return {'error': f'AbuseIPDB check failed: {str(e)}'}
    
    def _check_common_malicious_ports(self, ip_address):
        """
        Check for commonly used malicious ports
        """
        malicious_ports = [
            1337,  # Often used by backdoors
            31337, # Elite/leet backdoor port
            12345, # NetBus backdoor
            54321, # Back Orifice backdoor
            6667,  # IRC (potentially malicious)
            6697,  # IRC SSL
            1234,  # SubSeven backdoor
            9999,  # Various backdoors
        ]
        
        open_malicious_ports = []
        
        for port in malicious_ports:
            if self._is_port_open(ip_address, port, timeout=2):
                open_malicious_ports.append(port)
        
        return open_malicious_ports
    
    def _is_port_open(self, ip_address, port, timeout=3):
        """
        Check if a port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_reputation_info(self, ip_address):
        """
        Get reputation information
        """
        try:
            # Combine information from various sources
            reputation_score = 100  # Start with perfect score
            threats = []
            
            # This would typically check multiple threat intelligence feeds
            # For now, we'll provide a basic implementation
            
            # Check if IP is in known bad ranges
            bad_ranges = [
                # Known malicious ranges (examples)
                ipaddress.ip_network('192.0.2.0/24'),  # Documentation range
                # Add more ranges as needed
            ]
            
            ip_obj = ipaddress.ip_address(ip_address)
            
            for bad_range in bad_ranges:
                if ip_obj in bad_range:
                    reputation_score -= 50
                    threats.append(f'IP in suspicious range: {bad_range}')
            
            # Basic reputation assessment
            if reputation_score >= 80:
                reputation = 'Good'
            elif reputation_score >= 60:
                reputation = 'Fair'
            elif reputation_score >= 40:
                reputation = 'Poor'
            else:
                reputation = 'Bad'
            
            return {
                'score': reputation_score,
                'reputation': reputation,
                'threats': threats,
                'last_seen_malicious': 'Unknown',
                'threat_types': []
            }
            
        except Exception as e:
            return {'error': f'Reputation analysis failed: {str(e)}'}
    
    def _get_network_info(self, ip_address):
        """
        Get network-related information
        """
        try:
            network_info = {}
            
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                network_info['hostname'] = hostname
            except:
                network_info['hostname'] = 'No reverse DNS'
            
            # Determine IP type and characteristics
            ip_obj = ipaddress.ip_address(ip_address)
            
            network_info.update({
                'ip_type': 'IPv4' if ip_obj.version == 4 else 'IPv6',
                'is_global': ip_obj.is_global if hasattr(ip_obj, 'is_global') else not ip_obj.is_private,
                'is_link_local': ip_obj.is_link_local,
                'is_site_local': getattr(ip_obj, 'is_site_local', False),
                'compressed': str(ip_obj.compressed) if hasattr(ip_obj, 'compressed') else str(ip_obj)
            })
            
            return network_info
            
        except Exception as e:
            return {'error': f'Network info lookup failed: {str(e)}'}
    
    def bulk_analyze_ips(self, ip_list):
        """
        Analyze multiple IP addresses
        """
        results = []
        
        for ip in ip_list:
            ip = ip.strip()
            if ip:
                result = self.analyze_ip(ip)
                results.append(result)
        
        return {
            'total_ips': len(results),
            'results': results,
            'summary': self._generate_bulk_summary(results)
        }
    
    def _generate_bulk_summary(self, results):
        """
        Generate summary for bulk IP analysis
        """
        summary = {
            'total_analyzed': len(results),
            'private_ips': 0,
            'public_ips': 0,
            'suspicious_ips': 0,
            'countries': {},
            'organizations': {}
        }
        
        for result in results:
            if result.get('is_private'):
                summary['private_ips'] += 1
            else:
                summary['public_ips'] += 1
            
            # Count countries
            country = result.get('geolocation', {}).get('country', 'Unknown')
            summary['countries'][country] = summary['countries'].get(country, 0) + 1
            
            # Count organizations
            org = result.get('geolocation', {}).get('org', 'Unknown')
            summary['organizations'][org] = summary['organizations'].get(org, 0) + 1
            
            # Count suspicious IPs
            reputation = result.get('reputation', {})
            if reputation.get('score', 100) < 70:
                summary['suspicious_ips'] += 1
        
        return summary
