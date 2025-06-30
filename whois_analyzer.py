import whois
import dns.resolver
import socket
from datetime import datetime
import re
import validators

class WhoisAnalyzer:
    def __init__(self):
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
    
    def analyze_domain(self, domain, analysis_options=None):
        """
        Comprehensive domain analysis including WHOIS and DNS
        """
        try:
            # Validate domain
            if not validators.domain(domain):
                return {'error': 'Invalid domain format'}
            
            # Default analysis options if none provided
            if analysis_options is None:
                analysis_options = ["WHOIS Lookup", "DNS Records", "SSL Certificate", "Security Assessment"]
            
            result = {
                'domain': domain,
                'status': 'Active',
                'whois': {},
                'dns_records': {},
                'ssl_info': {},
                'security_assessment': {}
            }
            
            # Get WHOIS information
            if "WHOIS Lookup" in analysis_options:
                result['whois'] = self._get_whois_info(domain)
            
            # Get DNS information
            if "DNS Records" in analysis_options:
                result['dns_records'] = self._get_dns_info(domain)
            
            # Get SSL certificate info
            if "SSL Certificate" in analysis_options:
                result['ssl_info'] = self._get_ssl_info(domain)
            
            # Perform security assessment
            if "Security Assessment" in analysis_options:
                result['security_assessment'] = self._analyze_domain_security(domain, result.get('whois', {}), result.get('dns_records', {}))
            
            return result
            
        except Exception as e:
            return {'error': f'Domain analysis failed: {str(e)}'}
    
    def _get_whois_info(self, domain):
        """
        Get WHOIS information for domain
        """
        try:
            w = whois.whois(domain)
            
            # Parse dates safely
            creation_date = self._parse_date(w.creation_date)
            expiration_date = self._parse_date(w.expiration_date)
            updated_date = self._parse_date(w.updated_date)
            
            return {
                'registrar': str(w.registrar) if w.registrar else 'Unknown',
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'updated_date': updated_date,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'org': str(w.org) if w.org else 'Unknown',
                'country': str(w.country) if w.country else 'Unknown',
                'registrant_name': str(w.name) if w.name else 'Unknown'
            }
            
        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}
    
    def _get_dns_info(self, domain):
        """
        Get comprehensive DNS information
        """
        dns_info = {}
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = []
                
                for answer in answers:
                    try:
                        if record_type == 'MX':
                            preference = getattr(answer, 'preference', 'N/A')
                            exchange = getattr(answer, 'exchange', 'N/A')
                            records.append(f"{preference} {exchange}")
                        elif record_type == 'SOA':
                            mname = getattr(answer, 'mname', 'N/A')
                            rname = getattr(answer, 'rname', 'N/A')
                            serial = getattr(answer, 'serial', 'N/A')
                            records.append(f"{mname} {rname} {serial}")
                        else:
                            records.append(str(answer))
                    except Exception:
                        records.append(str(answer))
                
                dns_info[record_type.lower()] = records
                
            except dns.resolver.NXDOMAIN:
                dns_info[record_type.lower()] = ['Domain not found']
            except dns.resolver.NoAnswer:
                dns_info[record_type.lower()] = ['No records found']
            except Exception as e:
                dns_info[record_type.lower()] = [f'Error: {str(e)}']
        
        return dns_info
    
    def _analyze_domain_security(self, domain, whois_info, dns_info):
        """
        Analyze domain for security indicators
        """
        security_analysis = {
            'risk_factors': [],
            'security_features': [],
            'recommendations': []
        }
        
        # Check domain age
        if whois_info.get('creation_date'):
            try:
                creation_date = datetime.strptime(whois_info['creation_date'], '%Y-%m-%d')
                age_days = (datetime.now() - creation_date).days
                
                if age_days < 30:
                    security_analysis['risk_factors'].append('Very new domain (less than 30 days old)')
                elif age_days < 180:
                    security_analysis['risk_factors'].append('Recently created domain (less than 6 months old)')
                else:
                    security_analysis['security_features'].append(f'Established domain ({age_days} days old)')
            except:
                pass
        
        # Check for suspicious patterns
        if self._has_suspicious_patterns(domain):
            security_analysis['risk_factors'].append('Domain contains suspicious patterns')
        
        # Check DNS configuration
        if 'txt' in dns_info:
            txt_records = dns_info['txt']
            spf_found = any('spf' in record.lower() for record in txt_records)
            dmarc_found = any('dmarc' in record.lower() for record in txt_records)
            
            if spf_found:
                security_analysis['security_features'].append('SPF record configured')
            else:
                security_analysis['recommendations'].append('Configure SPF record for email security')
            
            if dmarc_found:
                security_analysis['security_features'].append('DMARC record configured')
            else:
                security_analysis['recommendations'].append('Configure DMARC record for email security')
        
        # Check for multiple A records (possible CDN/load balancing)
        if 'a' in dns_info and len(dns_info['a']) > 1:
            security_analysis['security_features'].append('Multiple A records (likely using CDN/load balancing)')
        
        return security_analysis
    
    def _check_domain_reputation(self, domain):
        """
        Check domain reputation (basic implementation)
        """
        reputation = {
            'status': 'Unknown',
            'risk_score': 50,
            'indicators': []
        }
        
        # Basic reputation checks
        if self._is_in_common_tlds(domain):
            reputation['indicators'].append('Uses common TLD')
            reputation['risk_score'] -= 10
        
        if self._has_suspicious_patterns(domain):
            reputation['indicators'].append('Contains suspicious patterns')
            reputation['risk_score'] += 20
        
        # Determine status based on risk score
        if reputation['risk_score'] >= 70:
            reputation['status'] = 'High Risk'
        elif reputation['risk_score'] >= 40:
            reputation['status'] = 'Moderate Risk'
        else:
            reputation['status'] = 'Low Risk'
        
        return reputation
    
    def _get_ssl_info(self, domain):
        """
        Get SSL certificate information for domain
        """
        try:
            import ssl
            import socket
            from datetime import datetime
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to domain on port 443
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate information safely
                    ssl_info = {
                        'valid': True,
                        'issuer': 'Unknown',
                        'subject': 'Unknown',
                        'version': cert.get('version', 'Unknown'),
                        'serial_number': cert.get('serialNumber', 'Unknown'),
                        'not_before': cert.get('notBefore', 'Unknown'),
                        'not_after': cert.get('notAfter', 'Unknown'),
                        'expiration': cert.get('notAfter', 'Unknown')
                    }
                    
                    # Safely parse issuer information
                    try:
                        issuer_info = cert.get('issuer', [])
                        if issuer_info and isinstance(issuer_info, (list, tuple)):
                            for item in issuer_info:
                                if isinstance(item, (list, tuple)) and len(item) >= 2:
                                    if item[0] == 'organizationName':
                                        ssl_info['issuer'] = item[1]
                                        break
                    except:
                        pass
                    
                    # Safely parse subject information
                    try:
                        subject_info = cert.get('subject', [])
                        if subject_info and isinstance(subject_info, (list, tuple)):
                            for item in subject_info:
                                if isinstance(item, (list, tuple)) and len(item) >= 2:
                                    if item[0] == 'commonName':
                                        ssl_info['subject'] = item[1]
                                        break
                    except:
                        pass
                    
                    # Check if certificate is expired
                    try:
                        not_after = cert.get('notAfter')
                        if not_after and isinstance(not_after, str):
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            if expiry_date < datetime.now():
                                ssl_info['valid'] = False
                                ssl_info['error'] = 'Certificate expired'
                    except:
                        pass
                    
                    return ssl_info
                    
        except Exception as e:
            return {
                'valid': False,
                'error': f'SSL check failed: {str(e)}'
            }
    
    def _parse_date(self, date_value):
        """
        Parse date value safely
        """
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d')
        
        return str(date_value)
    
    def _has_suspicious_patterns(self, domain):
        """
        Check for suspicious domain patterns
        """
        suspicious_patterns = [
            r'\d{4,}',  # Many consecutive digits
            r'[a-z]{20,}',  # Very long strings
            r'(.)\1{3,}',  # Repeated characters
            r'(secure|bank|paypal|amazon|google|microsoft).*\.(tk|ml|ga|cf)',  # Suspicious TLD with brand names
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        
        return False
    
    def _is_in_common_tlds(self, domain):
        """
        Check if domain uses common TLD
        """
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil']
        return any(domain.endswith(tld) for tld in common_tlds)
    
    def bulk_analyze_domains(self, domain_list):
        """
        Analyze multiple domains
        """
        results = []
        
        for domain in domain_list:
            domain = domain.strip()
            if domain:
                result = self.analyze_domain(domain)
                results.append(result)
        
        return {
            'total_domains': len(results),
            'results': results,
            'summary': self._generate_bulk_summary(results)
        }
    
    def _generate_bulk_summary(self, results):
        """
        Generate summary for bulk domain analysis
        """
        summary = {
            'total_analyzed': len(results),
            'high_risk_domains': 0,
            'moderate_risk_domains': 0,
            'low_risk_domains': 0,
            'registrars': {},
            'countries': {}
        }
        
        for result in results:
            if not result.get('error'):
                # Count risk levels
                risk_status = result.get('reputation', {}).get('status', 'Unknown')
                if 'High' in risk_status:
                    summary['high_risk_domains'] += 1
                elif 'Moderate' in risk_status:
                    summary['moderate_risk_domains'] += 1
                else:
                    summary['low_risk_domains'] += 1
                
                # Count registrars
                registrar = result.get('whois_info', {}).get('registrar', 'Unknown')
                summary['registrars'][registrar] = summary['registrars'].get(registrar, 0) + 1
                
                # Count countries
                country = result.get('whois_info', {}).get('country', 'Unknown')
                summary['countries'][country] = summary['countries'].get(country, 0) + 1
        
        return summary