import datetime
import logging
import os
import socket
import ssl
import tempfile
from urllib.parse import urlparse

try:
    from cryptography import x509

    HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - optional runtime path
    x509 = None
    HAS_CRYPTOGRAPHY = False


class TLSSecurityAnalyzer:
    """Analyze TLS exposure for a target host and port."""

    def __init__(self, timeout=6):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.weak_cipher_tokens = (
            'RC4',
            '3DES',
            'DES',
            'MD5',
            'NULL',
            'EXPORT',
            'ANON',
        )

    def analyze_target(self, target, port=443):
        hostname, normalized_port = self._normalize_target(target, port)
        if not hostname:
            return {
                'status': 'failed',
                'target': target,
                'hostname': None,
                'port': normalized_port,
                'certificate': {},
                'protocol_support': {},
                'cipher': {},
                'findings': [],
                'risk_level': 'unknown',
                'error': 'Invalid target',
            }

        certificate = self._get_certificate_details(hostname, normalized_port)
        protocol_support = self._test_protocol_support(hostname, normalized_port)
        cipher = self._get_negotiated_cipher(hostname, normalized_port)

        findings = []
        findings.extend(self._certificate_findings(certificate))
        findings.extend(self._protocol_findings(protocol_support))
        findings.extend(self._cipher_findings(cipher))

        if certificate.get('error') and not findings:
            findings.append(
                self._finding(
                    name='Certificate Retrieval Failed',
                    severity='medium',
                    description='Unable to retrieve the remote certificate.',
                    impact='TLS posture cannot be fully validated.',
                    recommendation='Confirm target reachability and TLS service availability.',
                )
            )

        return {
            'status': 'completed' if not certificate.get('fatal_error') else 'failed',
            'target': target,
            'hostname': hostname,
            'port': normalized_port,
            'certificate': certificate,
            'protocol_support': protocol_support,
            'cipher': cipher,
            'findings': findings,
            'risk_level': self._calculate_risk_level(findings),
            'error': certificate.get('fatal_error'),
            'timestamp': datetime.datetime.utcnow().isoformat(),
        }

    def _normalize_target(self, target, port):
        if target is None:
            return None, self._safe_port(port)

        cleaned = str(target).strip()
        if not cleaned:
            return None, self._safe_port(port)

        parsed_port = self._safe_port(port)

        if '://' in cleaned:
            parsed = urlparse(cleaned)
            return parsed.hostname, parsed.port or parsed_port

        if ':' in cleaned and cleaned.count(':') == 1:
            host_candidate, _, port_candidate = cleaned.partition(':')
            if port_candidate.isdigit():
                return host_candidate, self._safe_port(int(port_candidate))

        return cleaned, parsed_port

    def _safe_port(self, port):
        try:
            value = int(port)
            if 1 <= value <= 65535:
                return value
        except (TypeError, ValueError):
            pass
        return 443

    def _get_certificate_details(self, hostname, port):
        details = {
            'subject': None,
            'issuer': None,
            'serial_number': None,
            'not_before': None,
            'not_after': None,
            'days_until_expiry': None,
            'san_count': 0,
        }

        if HAS_CRYPTOGRAPHY:
            try:
                pem_data = ssl.get_server_certificate((hostname, port), timeout=self.timeout)
                cert = x509.load_pem_x509_certificate(pem_data.encode('ascii'))
                not_before, not_after = self._extract_cert_validity(cert)

                details['subject'] = cert.subject.rfc4514_string()
                details['issuer'] = cert.issuer.rfc4514_string()
                details['serial_number'] = format(cert.serial_number, 'x').upper()
                details['not_before'] = not_before.strftime('%b %d %H:%M:%S %Y GMT')
                details['not_after'] = not_after.strftime('%b %d %H:%M:%S %Y GMT')
                details['days_until_expiry'] = (not_after - datetime.datetime.now(datetime.timezone.utc)).days

                try:
                    san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    details['san_count'] = len(san_extension.value)
                except x509.ExtensionNotFound:
                    details['san_count'] = 0

                return details
            except Exception as exc:
                # Fall back to ssl.getpeercert() path below when PEM parsing fails.
                self.logger.debug('PEM certificate parsing failed for %s:%s (%s)', hostname, port, exc)

        stdlib_decoder = getattr(getattr(ssl, '_ssl', None), '_test_decode_cert', None)
        if stdlib_decoder is not None:
            temp_path = None
            try:
                pem_data = ssl.get_server_certificate((hostname, port), timeout=self.timeout)
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
                    temp_file.write(pem_data)
                    temp_path = temp_file.name

                parsed = stdlib_decoder(temp_path)
                details['subject'] = self._flatten_name(parsed.get('subject', []))
                details['issuer'] = self._flatten_name(parsed.get('issuer', []))
                details['serial_number'] = parsed.get('serialNumber')
                details['not_before'] = parsed.get('notBefore')
                details['not_after'] = parsed.get('notAfter')
                details['san_count'] = len(parsed.get('subjectAltName', []))

                not_after = parsed.get('notAfter')
                if not_after:
                    try:
                        expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        details['days_until_expiry'] = (expiry - datetime.datetime.utcnow()).days
                    except ValueError:
                        details['error'] = 'Unable to parse certificate expiration date'

                return details
            except Exception as exc:
                self.logger.debug('Stdlib certificate decode failed for %s:%s (%s)', hostname, port, exc)
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()

            if not cert:
                details['error'] = 'Empty certificate data returned by peer'
                return details

            details['subject'] = self._flatten_name(cert.get('subject', []))
            details['issuer'] = self._flatten_name(cert.get('issuer', []))
            details['serial_number'] = cert.get('serialNumber')
            details['not_before'] = cert.get('notBefore')
            details['not_after'] = cert.get('notAfter')
            details['san_count'] = len(cert.get('subjectAltName', []))

            not_after = cert.get('notAfter')
            if not_after:
                try:
                    expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    details['days_until_expiry'] = (expiry - datetime.datetime.utcnow()).days
                except ValueError:
                    details['error'] = 'Unable to parse certificate expiration date'

            return details
        except Exception as exc:
            details['error'] = str(exc)
            details['fatal_error'] = str(exc)
            return details

    def _extract_cert_validity(self, cert):
        not_before = getattr(cert, 'not_valid_before_utc', None)
        not_after = getattr(cert, 'not_valid_after_utc', None)

        if not_before is None:
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        return not_before, not_after

    def _flatten_name(self, name_tuples):
        components = []
        for entry in name_tuples:
            for key, value in entry:
                components.append('{}={}'.format(key, value))
        return ', '.join(components) if components else None

    def _test_protocol_support(self, hostname, port):
        support = {
            'TLSv1.0': None,
            'TLSv1.1': None,
            'TLSv1.2': None,
            'TLSv1.3': None,
        }

        if not hasattr(ssl, 'TLSVersion'):
            return support

        version_map = {
            'TLSv1.0': getattr(ssl.TLSVersion, 'TLSv1', None),
            'TLSv1.1': getattr(ssl.TLSVersion, 'TLSv1_1', None),
            'TLSv1.2': getattr(ssl.TLSVersion, 'TLSv1_2', None),
            'TLSv1.3': getattr(ssl.TLSVersion, 'TLSv1_3', None),
        }

        for label, version in version_map.items():
            if version is None:
                continue

            support[label] = self._probe_protocol(hostname, port, version)

        return support

    def _probe_protocol(self, hostname, port, tls_version):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if hasattr(context, 'minimum_version') and hasattr(context, 'maximum_version'):
                context.minimum_version = tls_version
                context.maximum_version = tls_version

            with socket.create_connection((hostname, port), timeout=self.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=hostname):
                    return True
        except ssl.SSLError:
            return False
        except ValueError:
            # Raised when local OpenSSL policy disallows legacy protocol negotiation.
            return False
        except OSError:
            return False

    def _get_negotiated_cipher(self, hostname, port):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                    selected_cipher = tls_sock.cipher()

            if not selected_cipher:
                return {'name': None, 'protocol': None, 'bits': None}

            return {
                'name': selected_cipher[0],
                'protocol': selected_cipher[1],
                'bits': selected_cipher[2],
            }
        except Exception:
            return {'name': None, 'protocol': None, 'bits': None}

    def _certificate_findings(self, certificate):
        findings = []
        days_until_expiry = certificate.get('days_until_expiry')

        if days_until_expiry is None:
            return findings

        if days_until_expiry < 0:
            findings.append(
                self._finding(
                    name='Expired TLS Certificate',
                    severity='critical',
                    description='Certificate is already expired ({} days).'.format(abs(days_until_expiry)),
                    impact='Users are exposed to trust warnings and possible interception risk.',
                    recommendation='Renew and deploy a valid TLS certificate immediately.',
                )
            )
        elif days_until_expiry < 14:
            findings.append(
                self._finding(
                    name='Certificate Near Expiration',
                    severity='high',
                    description='Certificate expires in {} days.'.format(days_until_expiry),
                    impact='Potential service disruption and trust failures.',
                    recommendation='Schedule immediate certificate renewal.',
                )
            )
        elif days_until_expiry < 45:
            findings.append(
                self._finding(
                    name='Certificate Renewal Recommended',
                    severity='medium',
                    description='Certificate expires in {} days.'.format(days_until_expiry),
                    impact='Approaching expiration can cause operational risk.',
                    recommendation='Plan certificate renewal and deployment.',
                )
            )

        return findings

    def _protocol_findings(self, protocol_support):
        findings = []
        weak_protocols = []

        for label in ('TLSv1.0', 'TLSv1.1'):
            if protocol_support.get(label):
                weak_protocols.append(label)

        if weak_protocols:
            findings.append(
                self._finding(
                    name='Legacy TLS Protocols Enabled',
                    severity='high',
                    description='Server accepts legacy protocols: {}.'.format(', '.join(weak_protocols)),
                    impact='Legacy protocols are vulnerable to downgrade and cryptographic attacks.',
                    recommendation='Disable TLSv1.0 and TLSv1.1. Enforce TLSv1.2 or TLSv1.3 only.',
                )
            )

        if protocol_support.get('TLSv1.2') is False and protocol_support.get('TLSv1.3') is False:
            findings.append(
                self._finding(
                    name='Modern TLS Not Detected',
                    severity='critical',
                    description='TLSv1.2 and TLSv1.3 could not be negotiated.',
                    impact='Service may be relying on obsolete protocol support.',
                    recommendation='Enable TLSv1.2+ and update TLS stack.',
                )
            )

        return findings

    def _cipher_findings(self, cipher):
        findings = []
        cipher_name = cipher.get('name')
        if not cipher_name:
            return findings

        upper_name = cipher_name.upper()
        if any(token in upper_name for token in self.weak_cipher_tokens):
            findings.append(
                self._finding(
                    name='Weak Cipher Suite Negotiated',
                    severity='high',
                    description='Negotiated cipher appears weak: {}.'.format(cipher_name),
                    impact='Weak ciphers lower confidentiality and integrity guarantees.',
                    recommendation='Disable weak ciphers and prefer AEAD suites (AES-GCM or CHACHA20-POLY1305).',
                )
            )

        bits = cipher.get('bits')
        if isinstance(bits, int) and bits < 128:
            findings.append(
                self._finding(
                    name='Low Cipher Key Length',
                    severity='medium',
                    description='Negotiated cipher key length is {} bits.'.format(bits),
                    impact='Lower key lengths can reduce cryptographic strength.',
                    recommendation='Use cipher suites with at least 128-bit security.',
                )
            )

        return findings

    def _finding(self, name, severity, description, impact, recommendation):
        return {
            'name': name,
            'severity': severity,
            'description': description,
            'impact': impact,
            'recommendation': recommendation,
        }

    def _calculate_risk_level(self, findings):
        severities = [item.get('severity', '').lower() for item in findings]

        if 'critical' in severities:
            return 'critical'
        if severities.count('high') >= 2:
            return 'high'
        if 'high' in severities or severities.count('medium') >= 2:
            return 'medium'
        if findings:
            return 'low'
        return 'minimal'
