import re
import base64
import json
from datetime import datetime
import hashlib
import validators

class EmailAnalyzer:
    def __init__(self):
        self.suspicious_domains = {
            'temporary_email': [
                '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
                'mailinator.com', 'throwaway.email', 'temp-mail.org'
            ],
            'suspicious_tlds': [
                '.tk', '.ml', '.ga', '.cf', '.click', '.download',
                '.zip', '.review', '.country', '.stream'
            ]
        }
        
        self.phishing_keywords = [
            'urgent', 'verify', 'suspend', 'click here', 'act now',
            'confirm identity', 'update payment', 'security alert',
            'account locked', 'immediate action', 'expire'
        ]
    
    def analyze_email_address(self, email):
        """
        Analyze email address for security indicators
        """
        try:
            if not validators.email(email):
                return {'error': 'Invalid email format'}
            
            local_part, domain = email.split('@')
            
            analysis = {
                'email': email,
                'local_part': local_part,
                'domain': domain,
                'risk_score': 0,
                'risk_factors': [],
                'security_features': [],
                'domain_analysis': {},
                'recommendations': []
            }
            
            # Analyze local part
            analysis.update(self._analyze_local_part(local_part))
            
            # Analyze domain
            analysis['domain_analysis'] = self._analyze_email_domain(domain)
            
            # Check for suspicious patterns
            analysis.update(self._check_suspicious_patterns(email, local_part, domain))
            
            # Calculate overall risk score
            analysis['risk_score'] = self._calculate_risk_score(analysis)
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_email_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            return {'error': f'Email analysis failed: {str(e)}'}
    
    def analyze_email_content(self, email_content, sender_email=None):
        """
        Analyze email content for phishing and spam indicators
        """
        try:
            analysis = {
                'sender': sender_email,
                'content_length': len(email_content),
                'phishing_indicators': [],
                'spam_indicators': [],
                'security_score': 100,
                'suspicious_links': [],
                'attachments_analysis': [],
                'recommendations': []
            }
            
            # Check for phishing indicators
            analysis['phishing_indicators'] = self._detect_phishing_content(email_content)
            
            # Check for spam indicators
            analysis['spam_indicators'] = self._detect_spam_content(email_content)
            
            # Extract and analyze links
            analysis['suspicious_links'] = self._extract_suspicious_links(email_content)
            
            # Analyze sender if provided
            if sender_email:
                sender_analysis = self.analyze_email_address(sender_email)
                analysis['sender_analysis'] = sender_analysis
            
            # Calculate security score
            analysis['security_score'] = self._calculate_content_security_score(analysis)
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_content_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            return {'error': f'Email content analysis failed: {str(e)}'}
    
    def _analyze_local_part(self, local_part):
        """
        Analyze the local part of email address
        """
        analysis = {
            'local_part_length': len(local_part),
            'has_numbers': bool(re.search(r'\d', local_part)),
            'has_special_chars': bool(re.search(r'[^a-zA-Z0-9._-]', local_part)),
            'consecutive_dots': '..' in local_part,
            'starts_or_ends_with_dot': local_part.startswith('.') or local_part.endswith('.')
        }
        
        risk_factors = []
        
        # Check for suspicious patterns
        if analysis['consecutive_dots']:
            risk_factors.append('Consecutive dots in email address')
        
        if analysis['starts_or_ends_with_dot']:
            risk_factors.append('Email starts or ends with dot')
        
        if len(local_part) < 3:
            risk_factors.append('Very short local part')
        elif len(local_part) > 30:
            risk_factors.append('Unusually long local part')
        
        # Check for common suspicious patterns
        if re.search(r'^(admin|test|noreply|support)\d+$', local_part, re.IGNORECASE):
            risk_factors.append('Generic admin/test account pattern')
        
        analysis['risk_factors'] = risk_factors
        return analysis
    
    def _analyze_email_domain(self, domain):
        """
        Analyze email domain for security indicators
        """
        domain_analysis = {
            'is_temporary': False,
            'has_suspicious_tld': False,
            'domain_length': len(domain),
            'subdomain_count': domain.count('.'),
            'risk_factors': []
        }
        
        # Check if it's a temporary email domain
        if domain in self.suspicious_domains['temporary_email']:
            domain_analysis['is_temporary'] = True
            domain_analysis['risk_factors'].append('Temporary/disposable email domain')
        
        # Check for suspicious TLD
        for tld in self.suspicious_domains['suspicious_tlds']:
            if domain.endswith(tld):
                domain_analysis['has_suspicious_tld'] = True
                domain_analysis['risk_factors'].append(f'Suspicious TLD: {tld}')
                break
        
        # Check domain length and structure
        if len(domain) > 50:
            domain_analysis['risk_factors'].append('Unusually long domain name')
        
        if domain.count('.') > 3:
            domain_analysis['risk_factors'].append('Multiple subdomains (suspicious structure)')
        
        # Check for homograph attacks (basic check)
        if self._has_homograph_chars(domain):
            domain_analysis['risk_factors'].append('Possible homograph attack characters')
        
        return domain_analysis
    
    def _check_suspicious_patterns(self, email, local_part, domain):
        """
        Check for various suspicious patterns
        """
        patterns = {
            'risk_factors': [],
            'security_features': []
        }
        
        # Check for lookalike domains
        if self._is_lookalike_domain(domain):
            patterns['risk_factors'].append('Domain resembles popular service')
        
        # Check for random character patterns
        if self._has_random_pattern(local_part):
            patterns['risk_factors'].append('Local part appears randomly generated')
        
        # Check for typosquatting patterns
        if self._is_potential_typosquatting(domain):
            patterns['risk_factors'].append('Potential typosquatting domain')
        
        return patterns
    
    def _detect_phishing_content(self, content):
        """
        Detect phishing indicators in email content
        """
        indicators = []
        content_lower = content.lower()
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                indicators.append(f'Phishing keyword: "{keyword}"')
        
        # Check for urgent/threatening language
        urgent_patterns = [
            r'within \d+ hours?',
            r'expires? (today|tomorrow|soon)',
            r'immediate(ly)? (action|response)',
            r'account will be (closed|suspended|deleted)'
        ]
        
        for pattern in urgent_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f'Urgent/threatening language pattern: {pattern}')
        
        # Check for credential harvesting
        credential_patterns = [
            r'(username|password|ssn|social security)',
            r'(credit card|bank account|routing number)',
            r'(verify|confirm|update).*(account|identity|information)'
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f'Credential harvesting pattern: {pattern}')
        
        return indicators
    
    def _detect_spam_content(self, content):
        """
        Detect spam indicators in email content
        """
        indicators = []
        content_lower = content.lower()
        
        # Check for excessive capitalization
        if re.search(r'[A-Z]{10,}', content):
            indicators.append('Excessive capitalization')
        
        # Check for money-related spam
        money_patterns = [
            r'\$\d+[,\d]*',
            r'(make|earn|win).*(money|\$\d+)',
            r'(free|instant).*(cash|money)',
            r'(lottery|winner|prize)'
        ]
        
        for pattern in money_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f'Money/lottery spam pattern: {pattern}')
        
        # Check for excessive punctuation
        if re.search(r'[!]{3,}', content):
            indicators.append('Excessive exclamation marks')
        
        return indicators
    
    def _extract_suspicious_links(self, content):
        """
        Extract and analyze suspicious links
        """
        suspicious_links = []
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            link_analysis = {
                'url': url,
                'risk_factors': []
            }
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'short.link', 'ow.ly']
            if any(shortener in url for shortener in shorteners):
                link_analysis['risk_factors'].append('URL shortener used')
            
            # Check for suspicious TLDs
            for tld in self.suspicious_domains['suspicious_tlds']:
                if tld in url:
                    link_analysis['risk_factors'].append(f'Suspicious TLD: {tld}')
            
            # Check for IP addresses instead of domains
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                link_analysis['risk_factors'].append('IP address instead of domain')
            
            if link_analysis['risk_factors']:
                suspicious_links.append(link_analysis)
        
        return suspicious_links
    
    def _calculate_risk_score(self, analysis):
        """
        Calculate overall risk score for email address
        """
        risk_score = 0
        
        # Add points for each risk factor
        risk_score += len(analysis.get('risk_factors', [])) * 15
        risk_score += len(analysis.get('domain_analysis', {}).get('risk_factors', [])) * 20
        
        # Special penalties
        if analysis.get('domain_analysis', {}).get('is_temporary'):
            risk_score += 30
        
        if analysis.get('domain_analysis', {}).get('has_suspicious_tld'):
            risk_score += 25
        
        return min(risk_score, 100)
    
    def _calculate_content_security_score(self, analysis):
        """
        Calculate security score for email content
        """
        score = 100
        
        # Deduct points for indicators
        score -= len(analysis.get('phishing_indicators', [])) * 20
        score -= len(analysis.get('spam_indicators', [])) * 10
        score -= len(analysis.get('suspicious_links', [])) * 15
        
        return max(score, 0)
    
    def _generate_email_recommendations(self, analysis):
        """
        Generate recommendations for email address analysis
        """
        recommendations = []
        
        if analysis.get('domain_analysis', {}).get('is_temporary'):
            recommendations.append('Avoid using temporary email services for important accounts')
        
        if analysis.get('risk_score', 0) > 50:
            recommendations.append('Email address shows multiple risk factors - verify legitimacy')
        
        if analysis.get('domain_analysis', {}).get('has_suspicious_tld'):
            recommendations.append('Be cautious with emails from unusual top-level domains')
        
        return recommendations
    
    def _generate_content_recommendations(self, analysis):
        """
        Generate recommendations for email content analysis
        """
        recommendations = []
        
        if analysis.get('phishing_indicators'):
            recommendations.append('Email shows phishing indicators - do not click links or provide information')
        
        if analysis.get('suspicious_links'):
            recommendations.append('Suspicious links detected - verify URLs before clicking')
        
        if analysis.get('security_score', 100) < 70:
            recommendations.append('Email has low security score - treat with caution')
        
        return recommendations
    
    def _has_homograph_chars(self, text):
        """
        Basic check for homograph attack characters
        """
        # Simplified check for common homograph characters
        homograph_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic chars that look like Latin
        return any(char in text for char in homograph_chars)
    
    def _is_lookalike_domain(self, domain):
        """
        Check if domain looks like a popular service
        """
        popular_domains = ['gmail', 'yahoo', 'outlook', 'hotmail', 'apple', 'amazon', 'google', 'microsoft']
        domain_lower = domain.lower()
        
        for popular in popular_domains:
            if popular in domain_lower and popular != domain_lower.split('.')[0]:
                return True
        
        return False
    
    def _has_random_pattern(self, text):
        """
        Check if text appears randomly generated
        """
        # Simple heuristic: alternating consonants and vowels or too many consonants
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        if len(text) < 5:
            return False
        
        # Count consecutive consonants
        max_consecutive_consonants = 0
        current_consecutive = 0
        
        for char in text.lower():
            if char in consonants:
                current_consecutive += 1
                max_consecutive_consonants = max(max_consecutive_consonants, current_consecutive)
            else:
                current_consecutive = 0
        
        return max_consecutive_consonants > 4
    
    def _is_potential_typosquatting(self, domain):
        """
        Basic typosquatting detection
        """
        # Check for common typosquatting patterns
        typosquatting_patterns = [
            r'g[o0]ogle',
            r'[a@]mazon',
            r'p[a@]ypal',
            r'microsft',
            r'fac[e3]book'
        ]
        
        domain_lower = domain.lower()
        
        for pattern in typosquatting_patterns:
            if re.search(pattern, domain_lower):
                return True
        
        return False