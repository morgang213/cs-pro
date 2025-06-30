import re
import math
from collections import Counter

class PasswordAnalyzer:
    def __init__(self):
        # Common passwords list (simplified)
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
            'password1', '123456789', 'welcome123', 'admin123'
        }
        
        # Common patterns
        self.keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'abcd'
        ]
    
    def analyze_password(self, password):
        """
        Comprehensive password analysis
        """
        if not password:
            return {
                'score': 0,
                'complexity': 'Very Weak',
                'checks': {},
                'recommendations': ['Password is required']
            }
        
        # Perform various checks
        checks = {
            'minimum_length': len(password) >= 8,
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_numbers': bool(re.search(r'\d', password)),
            'has_special_chars': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password)),
            'not_common_password': password.lower() not in self.common_passwords,
            'no_keyboard_patterns': not self._has_keyboard_patterns(password.lower()),
            'no_repetitive_chars': not self._has_repetitive_characters(password),
            'good_length': len(password) >= 12,
            'excellent_length': len(password) >= 16
        }
        
        # Calculate entropy and score
        entropy = self._calculate_entropy(password)
        base_score = self._calculate_base_score(checks)
        entropy_bonus = min(entropy / 4, 20)  # Max 20 points from entropy
        
        total_score = min(base_score + entropy_bonus, 100)
        
        # Determine complexity level
        complexity = self._determine_complexity(total_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(checks, password)
        
        return {
            'score': int(total_score),
            'complexity': complexity,
            'checks': checks,
            'entropy': round(entropy, 2),
            'recommendations': recommendations,
            'length': len(password),
            'character_types': self._count_character_types(password)
        }
    
    def _calculate_entropy(self, password):
        """
        Calculate password entropy in bits
        """
        if not password:
            return 0
        
        # Character set size estimation
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            charset_size += 32
        if re.search(r'[^\w\s!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            charset_size += 10  # Other special characters
        
        # Calculate entropy
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
            
            # Reduce entropy for patterns
            if self._has_keyboard_patterns(password.lower()):
                entropy *= 0.7
            if self._has_repetitive_characters(password):
                entropy *= 0.8
            if password.lower() in self.common_passwords:
                entropy *= 0.3
                
            return entropy
        
        return 0
    
    def _calculate_base_score(self, checks):
        """
        Calculate base score from checks
        """
        score = 0
        
        # Essential checks (10 points each)
        essential_checks = [
            'minimum_length', 'has_uppercase', 'has_lowercase', 
            'has_numbers', 'not_common_password'
        ]
        
        for check in essential_checks:
            if checks.get(check, False):
                score += 10
        
        # Important checks (8 points each)
        important_checks = [
            'has_special_chars', 'no_keyboard_patterns', 'no_repetitive_chars'
        ]
        
        for check in important_checks:
            if checks.get(check, False):
                score += 8
        
        # Bonus checks (5 points each)
        bonus_checks = ['good_length', 'excellent_length']
        
        for check in bonus_checks:
            if checks.get(check, False):
                score += 5
        
        return score
    
    def _determine_complexity(self, score):
        """
        Determine password complexity level
        """
        if score >= 90:
            return 'Excellent'
        elif score >= 80:
            return 'Very Strong'
        elif score >= 70:
            return 'Strong'
        elif score >= 60:
            return 'Good'
        elif score >= 40:
            return 'Fair'
        elif score >= 20:
            return 'Weak'
        else:
            return 'Very Weak'
    
    def generate_strong_password(self, length=12, include_symbols=True):
        """
        Generate a strong password
        """
        import random
        import string
        
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Ensure at least one character from each set
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits)
        ]
        
        if include_symbols:
            password.append(random.choice(symbols))
            all_chars = lowercase + uppercase + digits + symbols
        else:
            all_chars = lowercase + uppercase + digits
        
        # Fill the rest randomly
        for _ in range(length - len(password)):
            password.append(random.choice(all_chars))
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)
    
    def _has_keyboard_patterns(self, password):
        """
        Check for keyboard patterns
        """
        for pattern in self.keyboard_patterns:
            if pattern in password:
                return True
        
        # Check for sequential patterns
        for i in range(len(password) - 2):
            if password[i:i+3] in 'abcdefghijklmnopqrstuvwxyz':
                return True
            if password[i:i+3] in '0123456789':
                return True
        
        return False
    
    def _has_repetitive_characters(self, password):
        """
        Check for repetitive character patterns
        """
        # Check for consecutive repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        
        # Check if more than 50% of characters are the same
        char_counts = Counter(password)
        max_count = max(char_counts.values()) if char_counts else 0
        
        return max_count > len(password) * 0.5
    
    def _count_character_types(self, password):
        """
        Count different types of characters
        """
        types = {
            'uppercase': len(re.findall(r'[A-Z]', password)),
            'lowercase': len(re.findall(r'[a-z]', password)),
            'digits': len(re.findall(r'\d', password)),
            'special': len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password)),
            'other': len(re.findall(r'[^\w!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password))
        }
        
        return types
    
    def _generate_recommendations(self, checks, password):
        """
        Generate improvement recommendations
        """
        recommendations = []
        
        if not checks.get('minimum_length'):
            recommendations.append('Use at least 8 characters (12+ recommended)')
        
        if not checks.get('has_uppercase'):
            recommendations.append('Include uppercase letters (A-Z)')
        
        if not checks.get('has_lowercase'):
            recommendations.append('Include lowercase letters (a-z)')
        
        if not checks.get('has_numbers'):
            recommendations.append('Include numbers (0-9)')
        
        if not checks.get('has_special_chars'):
            recommendations.append('Include special characters (!@#$%^&*)')
        
        if not checks.get('not_common_password'):
            recommendations.append('Avoid common passwords')
        
        if not checks.get('no_keyboard_patterns'):
            recommendations.append('Avoid keyboard patterns (qwerty, 123456, etc.)')
        
        if not checks.get('no_repetitive_chars'):
            recommendations.append('Avoid repetitive characters (aaa, 111, etc.)')
        
        if not checks.get('good_length'):
            recommendations.append('Consider using 12+ characters for better security')
        
        if len(recommendations) == 0:
            recommendations.append('Your password meets security requirements!')
        
        return recommendations
    
    def check_password_breach(self, password):
        """
        Check if password appears in known breaches (mock implementation)
        Note: In a real implementation, this would use APIs like HaveIBeenPwned
        """
        # Mock implementation - in reality, you'd hash the password and check against breach databases
        common_breached = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
        }
        
        is_breached = password.lower() in common_breached
        
        return {
            'is_breached': is_breached,
            'message': 'Password found in breach database' if is_breached else 'Password not found in breach database',
            'recommendation': 'Change password immediately' if is_breached else 'Password appears safe from known breaches'
        }
