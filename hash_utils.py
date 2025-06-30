import hashlib
import hmac
import os
import base64
from datetime import datetime

class HashUtils:
    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s
        }
    
    def generate_hash(self, text, algorithm='sha256', encoding='utf-8'):
        """
        Generate hash for given text using specified algorithm
        """
        try:
            if algorithm not in self.supported_algorithms:
                return f"Unsupported algorithm: {algorithm}"
            
            # Create hash object
            hash_obj = self.supported_algorithms[algorithm]()
            
            # Update hash object with text
            hash_obj.update(text.encode(encoding))
            
            # Return hexadecimal digest
            return hash_obj.hexdigest()
            
        except Exception as e:
            return f"Error generating hash: {str(e)}"
    
    def verify_hash(self, original_text, hash_to_verify, algorithm='sha256', encoding='utf-8'):
        """
        Verify if hash matches the original text
        """
        try:
            # Generate hash of original text
            calculated_hash = self.generate_hash(original_text, algorithm, encoding)
            
            # Compare hashes (case-insensitive)
            return calculated_hash.lower() == hash_to_verify.lower()
            
        except Exception as e:
            return False
    
    def generate_file_hash(self, file_path, algorithm='sha256'):
        """
        Generate hash for a file
        """
        try:
            if algorithm not in self.supported_algorithms:
                return f"Unsupported algorithm: {algorithm}"
            
            hash_obj = self.supported_algorithms[algorithm]()
            
            with open(file_path, 'rb') as file:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: file.read(4096), b""):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            return f"Error generating file hash: {str(e)}"
    
    def generate_hmac(self, message, key, algorithm='sha256', encoding='utf-8'):
        """
        Generate HMAC (Hash-based Message Authentication Code)
        """
        try:
            if algorithm not in self.supported_algorithms:
                return f"Unsupported algorithm: {algorithm}"
            
            # Convert key and message to bytes
            key_bytes = key.encode(encoding) if isinstance(key, str) else key
            message_bytes = message.encode(encoding) if isinstance(message, str) else message
            
            # Generate HMAC
            hmac_obj = hmac.new(key_bytes, message_bytes, self.supported_algorithms[algorithm])
            
            return hmac_obj.hexdigest()
            
        except Exception as e:
            return f"Error generating HMAC: {str(e)}"
    
    def verify_hmac(self, message, key, hmac_to_verify, algorithm='sha256', encoding='utf-8'):
        """
        Verify HMAC
        """
        try:
            # Generate HMAC for comparison
            calculated_hmac = self.generate_hmac(message, key, algorithm, encoding)
            
            # Secure comparison to prevent timing attacks
            return hmac.compare_digest(calculated_hmac, hmac_to_verify)
            
        except Exception as e:
            return False
    
    def generate_salt(self, length=32):
        """
        Generate random salt for password hashing
        """
        try:
            return os.urandom(length).hex()
        except Exception as e:
            return f"Error generating salt: {str(e)}"
    
    def hash_password(self, password, salt=None, algorithm='sha256', iterations=100000):
        """
        Hash password with salt (using PBKDF2)
        """
        try:
            if salt is None:
                salt = self.generate_salt()
            
            # Convert to bytes if string
            password_bytes = password.encode('utf-8') if isinstance(password, str) else password
            salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt
            
            # Use PBKDF2 for key derivation
            hash_bytes = hashlib.pbkdf2_hmac(algorithm, password_bytes, salt_bytes, iterations)
            
            return {
                'hash': hash_bytes.hex(),
                'salt': salt if isinstance(salt, str) else salt.hex(),
                'algorithm': algorithm,
                'iterations': iterations
            }
            
        except Exception as e:
            return f"Error hashing password: {str(e)}"
    
    def verify_password(self, password, stored_hash, salt, algorithm='sha256', iterations=100000):
        """
        Verify password against stored hash
        """
        try:
            # Hash the provided password with the same parameters
            result = self.hash_password(password, salt, algorithm, iterations)
            
            if isinstance(result, dict):
                return result['hash'] == stored_hash
            else:
                return False
                
        except Exception as e:
            return False
    
    def generate_checksum_report(self, file_paths, algorithm='sha256'):
        """
        Generate checksum report for multiple files
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'algorithm': algorithm,
            'files': []
        }
        
        for file_path in file_paths:
            try:
                file_hash = self.generate_file_hash(file_path, algorithm)
                file_size = os.path.getsize(file_path)
                
                report['files'].append({
                    'file_path': file_path,
                    'hash': file_hash,
                    'size_bytes': file_size,
                    'status': 'success'
                })
                
            except Exception as e:
                report['files'].append({
                    'file_path': file_path,
                    'hash': None,
                    'size_bytes': None,
                    'status': 'error',
                    'error': str(e)
                })
        
        return report
    
    def compare_files_by_hash(self, file1_path, file2_path, algorithm='sha256'):
        """
        Compare two files by their hash values
        """
        try:
            hash1 = self.generate_file_hash(file1_path, algorithm)
            hash2 = self.generate_file_hash(file2_path, algorithm)
            
            if hash1.startswith('Error') or hash2.startswith('Error'):
                return {
                    'identical': False,
                    'error': 'Could not generate hash for one or both files',
                    'hash1': hash1,
                    'hash2': hash2
                }
            
            return {
                'identical': hash1 == hash2,
                'hash1': hash1,
                'hash2': hash2,
                'algorithm': algorithm
            }
            
        except Exception as e:
            return {
                'identical': False,
                'error': str(e)
            }
    
    def get_hash_info(self, hash_string):
        """
        Analyze hash string to determine likely algorithm
        """
        hash_length = len(hash_string)
        
        algorithm_lengths = {
            32: 'MD5',
            40: 'SHA-1',
            56: 'SHA-224',
            64: 'SHA-256',
            96: 'SHA-384',
            128: 'SHA-512',
            64: 'BLAKE2s (256-bit)',
            128: 'BLAKE2b (512-bit)'
        }
        
        likely_algorithm = algorithm_lengths.get(hash_length, 'Unknown')
        
        # Check if hash contains only valid hexadecimal characters
        is_valid_hex = all(c in '0123456789abcdefABCDEF' for c in hash_string)
        
        return {
            'hash': hash_string,
            'length': hash_length,
            'likely_algorithm': likely_algorithm,
            'is_valid_hex': is_valid_hex,
            'format': 'hexadecimal' if is_valid_hex else 'unknown'
        }
    
    def encode_base64(self, text, encoding='utf-8'):
        """
        Encode text to Base64
        """
        try:
            text_bytes = text.encode(encoding) if isinstance(text, str) else text
            encoded = base64.b64encode(text_bytes)
            return encoded.decode('utf-8')
        except Exception as e:
            return f"Error encoding to Base64: {str(e)}"
    
    def decode_base64(self, encoded_text):
        """
        Decode Base64 text
        """
        try:
            decoded_bytes = base64.b64decode(encoded_text)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            return f"Error decoding from Base64: {str(e)}"
