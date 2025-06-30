import os
import json
import re
import html
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import uuid
import logging

Base = declarative_base()

# Security validation class for input sanitization
class SecurityValidator:
    """Input validation and sanitization for security purposes"""
    
    @staticmethod
    def sanitize_string(input_str, max_length=255):
        """Sanitize string input to prevent injection attacks"""
        if not input_str:
            return ""
        
        # Convert to string and limit length
        safe_str = str(input_str)[:max_length]
        
        # Remove potentially dangerous characters
        safe_str = re.sub(r'[<>&"\']', '', safe_str)
        
        # HTML escape for additional safety
        safe_str = html.escape(safe_str)
        
        return safe_str.strip()
    
    @staticmethod
    def validate_scan_type(scan_type):
        """Validate scan type against allowed values"""
        allowed_types = [
            'network', 'vulnerability', 'password', 'hash', 'ip', 
            'domain', 'email', 'log', 'threat_intel', 'port_scan'
        ]
        
        if scan_type not in allowed_types:
            raise ValueError(f"Invalid scan type: {scan_type}")
        
        return scan_type
    
    @staticmethod
    def validate_severity(severity):
        """Validate severity level"""
        allowed_severities = ['critical', 'high', 'medium', 'low', 'info']
        
        if severity and severity.lower() not in allowed_severities:
            raise ValueError(f"Invalid severity level: {severity}")
        
        return severity.lower() if severity else None
    
    @staticmethod
    def validate_ip_address(ip_str):
        """Basic IP address format validation"""
        if not ip_str:
            return ""
        
        # Simple regex for IPv4/IPv6 validation
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        if re.match(ipv4_pattern, ip_str) or re.match(ipv6_pattern, ip_str):
            return ip_str
        
        # If not valid IP, sanitize as regular string
        return SecurityValidator.sanitize_string(ip_str, 45)
    
    @staticmethod
    def validate_url(url_str):
        """Basic URL validation and sanitization"""
        if not url_str:
            return ""
        
        # Basic URL pattern validation
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        
        if re.match(url_pattern, url_str, re.IGNORECASE):
            return url_str[:500]  # Limit URL length
        
        # If not valid URL, sanitize as string
        return SecurityValidator.sanitize_string(url_str, 500)
    
    @staticmethod
    def validate_json_data(data):
        """Validate and sanitize JSON data"""
        if not data:
            return "{}"
        
        try:
            # If it's already a dict, convert to JSON string
            if isinstance(data, dict):
                # Remove potentially dangerous keys
                safe_data = {k: v for k, v in data.items() 
                           if not k.startswith('_') and not callable(v)}
                return json.dumps(safe_data)[:10000]  # Limit size
            
            # If it's a string, validate as JSON
            elif isinstance(data, str):
                parsed = json.loads(data)
                return json.dumps(parsed)[:10000]
            
            else:
                return json.dumps(str(data))[:10000]
                
        except (json.JSONDecodeError, TypeError):
            # If JSON parsing fails, return safe empty object
            return "{}"

class ScanHistory(Base):
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String(50), nullable=False)  # network, vulnerability, password, etc.
    target = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default='completed')  # completed, failed, in_progress
    results = Column(Text)  # JSON string of results
    risk_score = Column(Float)
    user_notes = Column(Text)

class VulnerabilityFindings(Base):
    __tablename__ = 'vulnerability_findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20))  # critical, high, medium, low, info
    target_url = Column(String(500))
    description = Column(Text)
    recommendation = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False)

class NetworkAssets(Base):
    __tablename__ = 'network_assets'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255))
    open_ports = Column(Text)  # JSON string of ports
    services = Column(Text)  # JSON string of services
    os_fingerprint = Column(String(200))
    last_scanned = Column(DateTime, default=datetime.utcnow)
    risk_level = Column(String(20))
    location_data = Column(Text)  # JSON string of geolocation

class SecurityReports(Base):
    __tablename__ = 'security_reports'
    
    id = Column(Integer, primary_key=True)
    report_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    report_type = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    report_data = Column(Text)  # JSON string of report content
    format_type = Column(String(20))  # markdown, json, pdf
    file_path = Column(String(500))

class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True)
    indicator = Column(String(500), nullable=False)  # IP, domain, email, hash
    indicator_type = Column(String(50), nullable=False)
    threat_type = Column(String(100))
    confidence_score = Column(Float)
    source = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    threat_metadata = Column(Text)  # JSON string for additional data

class DatabaseManager:
    def __init__(self):
        self.database_url = os.getenv('DATABASE_URL')
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable is not set")
        
        # Enhanced security configuration for database connection
        engine_config = {
            'echo': False,  # Disable SQL logging in production
            'pool_pre_ping': True,  # Validate connections before use
            'pool_recycle': 3600,  # Recycle connections every hour
            'connect_args': {
                'sslmode': 'prefer',  # Prefer SSL connections
                'connect_timeout': 10,  # Connection timeout
            }
        }
        
        self.engine = create_engine(self.database_url, **engine_config)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.validator = SecurityValidator()
        
        # Set up logging for security events
        logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        
        self.create_tables()
    
    def create_tables(self):
        """Create all database tables"""
        Base.metadata.create_all(bind=self.engine)
        
        # Also create user tracking tables
        try:
            from utils.user_tracking import Base as UserBase
            UserBase.metadata.create_all(bind=self.engine)
        except Exception as e:
            print(f"Warning: Could not create user tracking tables: {e}")
    
    def get_session(self):
        """Get a database session"""
        return self.SessionLocal()
    
    def save_scan_result(self, scan_type, target, results, risk_score=None, user_notes=None):
        """Save scan results to database with input validation"""
        session = self.get_session()
        try:
            # Validate and sanitize inputs
            validated_scan_type = self.validator.validate_scan_type(scan_type)
            sanitized_target = self.validator.sanitize_string(target, 255)
            sanitized_results = self.validator.validate_json_data(results)
            sanitized_notes = self.validator.sanitize_string(user_notes, 1000) if user_notes else None
            
            # Validate risk score
            if risk_score is not None:
                if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 10:
                    self.logger.warning(f"Invalid risk score provided: {risk_score}")
                    risk_score = None
            
            scan = ScanHistory(
                scan_type=validated_scan_type,
                target=sanitized_target,
                results=sanitized_results,
                risk_score=risk_score,
                user_notes=sanitized_notes
            )
            session.add(scan)
            session.commit()
            
            self.logger.info(f"Scan result saved: {validated_scan_type} for {sanitized_target}")
            return scan.scan_id
            
        except ValueError as ve:
            session.rollback()
            self.logger.error(f"Validation error in save_scan_result: {ve}")
            raise ve
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database error in save_scan_result: {e}")
            raise e
        finally:
            session.close()
    
    def get_scan_history(self, scan_type=None, limit=50):
        """Retrieve scan history"""
        session = self.get_session()
        try:
            query = session.query(ScanHistory)
            if scan_type:
                query = query.filter(ScanHistory.scan_type == scan_type)
            
            scans = query.order_by(ScanHistory.timestamp.desc()).limit(limit).all()
            
            results = []
            for scan in scans:
                results.append({
                    'scan_id': scan.scan_id,
                    'scan_type': scan.scan_type,
                    'target': scan.target,
                    'timestamp': scan.timestamp.isoformat() if hasattr(scan, 'timestamp') and scan.timestamp else None,
                    'status': scan.status,
                    'risk_score': scan.risk_score,
                    'user_notes': scan.user_notes
                })
            return results
        finally:
            session.close()
    
    def save_vulnerability(self, scan_id, vuln_type, severity, target_url=None, 
                          description=None, recommendation=None):
        """Save vulnerability finding with input validation"""
        session = self.get_session()
        try:
            # Validate and sanitize inputs
            sanitized_scan_id = self.validator.sanitize_string(scan_id, 36)
            sanitized_vuln_type = self.validator.sanitize_string(vuln_type, 100)
            validated_severity = self.validator.validate_severity(severity)
            sanitized_url = self.validator.validate_url(target_url) if target_url else None
            sanitized_description = self.validator.sanitize_string(description, 2000) if description else None
            sanitized_recommendation = self.validator.sanitize_string(recommendation, 2000) if recommendation else None
            
            vuln = VulnerabilityFindings(
                scan_id=sanitized_scan_id,
                vulnerability_type=sanitized_vuln_type,
                severity=validated_severity,
                target_url=sanitized_url,
                description=sanitized_description,
                recommendation=sanitized_recommendation
            )
            session.add(vuln)
            session.commit()
            
            self.logger.info(f"Vulnerability saved: {sanitized_vuln_type} ({validated_severity})")
            return vuln.id
            
        except ValueError as ve:
            session.rollback()
            self.logger.error(f"Validation error in save_vulnerability: {ve}")
            raise ve
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database error in save_vulnerability: {e}")
            raise e
        finally:
            session.close()
    
    def get_vulnerabilities(self, severity=None, limit=100):
        """Retrieve vulnerability findings"""
        session = self.get_session()
        try:
            query = session.query(VulnerabilityFindings)
            if severity:
                query = query.filter(VulnerabilityFindings.severity == severity)
            
            vulns = query.order_by(VulnerabilityFindings.discovered_at.desc()).limit(limit).all()
            
            results = []
            for vuln in vulns:
                results.append({
                    'id': vuln.id,
                    'scan_id': vuln.scan_id,
                    'vulnerability_type': vuln.vulnerability_type,
                    'severity': vuln.severity,
                    'target_url': vuln.target_url,
                    'description': vuln.description,
                    'recommendation': vuln.recommendation,
                    'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                    'is_resolved': vuln.is_resolved
                })
            return results
        finally:
            session.close()
    
    def save_network_asset(self, ip_address, hostname=None, open_ports=None, 
                          services=None, os_fingerprint=None, risk_level=None, location_data=None):
        """Save or update network asset information"""
        session = self.get_session()
        try:
            # Check if asset already exists
            existing = session.query(NetworkAssets).filter(
                NetworkAssets.ip_address == ip_address
            ).first()
            
            if existing:
                # Update existing asset with proper assignment
                if hostname:
                    existing.hostname = hostname
                if open_ports:
                    existing.open_ports = json.dumps(open_ports) if isinstance(open_ports, list) else str(open_ports)
                if services:
                    existing.services = json.dumps(services) if isinstance(services, list) else str(services)
                if os_fingerprint:
                    existing.os_fingerprint = os_fingerprint
                if risk_level:
                    existing.risk_level = risk_level
                if location_data:
                    existing.location_data = json.dumps(location_data) if isinstance(location_data, dict) else str(location_data)
                # Use update() method for datetime fields to avoid SQLAlchemy issues
                session.query(NetworkAssets).filter(NetworkAssets.id == existing.id).update({
                    NetworkAssets.last_scanned: datetime.utcnow()
                })
                asset_id = existing.id
            else:
                # Create new asset
                asset = NetworkAssets(
                    ip_address=ip_address,
                    hostname=hostname,
                    open_ports=json.dumps(open_ports) if isinstance(open_ports, list) else open_ports,
                    services=json.dumps(services) if isinstance(services, list) else services,
                    os_fingerprint=os_fingerprint,
                    risk_level=risk_level,
                    location_data=json.dumps(location_data) if isinstance(location_data, dict) else location_data
                )
                session.add(asset)
                session.flush()
                asset_id = asset.id
            
            session.commit()
            return asset_id
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_network_assets(self, risk_level=None, limit=100):
        """Retrieve network assets"""
        session = self.get_session()
        try:
            query = session.query(NetworkAssets)
            if risk_level:
                query = query.filter(NetworkAssets.risk_level == risk_level)
            
            assets = query.order_by(NetworkAssets.last_scanned.desc()).limit(limit).all()
            
            results = []
            for asset in assets:
                results.append({
                    'id': asset.id,
                    'ip_address': asset.ip_address,
                    'hostname': asset.hostname,
                    'open_ports': json.loads(asset.open_ports) if asset.open_ports else [],
                    'services': json.loads(asset.services) if asset.services else [],
                    'os_fingerprint': asset.os_fingerprint,
                    'last_scanned': asset.last_scanned.isoformat() if asset.last_scanned else None,
                    'risk_level': asset.risk_level,
                    'location_data': json.loads(asset.location_data) if asset.location_data else {}
                })
            return results
        finally:
            session.close()
    
    def save_security_report(self, report_type, title, report_data, format_type='json', file_path=None):
        """Save security report"""
        session = self.get_session()
        try:
            report = SecurityReports(
                report_type=report_type,
                title=title,
                report_data=json.dumps(report_data) if isinstance(report_data, dict) else report_data,
                format_type=format_type,
                file_path=file_path
            )
            session.add(report)
            session.commit()
            return report.report_id
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_security_reports(self, report_type=None, limit=50):
        """Retrieve security reports"""
        session = self.get_session()
        try:
            query = session.query(SecurityReports)
            if report_type:
                query = query.filter(SecurityReports.report_type == report_type)
            
            reports = query.order_by(SecurityReports.generated_at.desc()).limit(limit).all()
            
            results = []
            for report in reports:
                results.append({
                    'report_id': report.report_id,
                    'report_type': report.report_type,
                    'title': report.title,
                    'generated_at': report.generated_at.isoformat() if report.generated_at else None,
                    'format_type': report.format_type,
                    'file_path': report.file_path
                })
            return results
        finally:
            session.close()
    
    def save_threat_intelligence(self, indicator, indicator_type, threat_type=None, 
                                confidence_score=None, source=None, metadata=None):
        """Save threat intelligence data"""
        session = self.get_session()
        try:
            # Check if indicator already exists
            existing = session.query(ThreatIntelligence).filter(
                ThreatIntelligence.indicator == indicator,
                ThreatIntelligence.indicator_type == indicator_type
            ).first()
            
            if existing:
                # Update existing indicator
                if threat_type:
                    existing.threat_type = threat_type
                if confidence_score is not None:
                    existing.confidence_score = confidence_score
                if source:
                    existing.source = source
                if metadata:
                    existing.threat_metadata = json.dumps(metadata) if isinstance(metadata, dict) else metadata
                existing.last_updated = datetime.utcnow()
                intel_id = existing.id
            else:
                # Create new threat intelligence entry
                intel = ThreatIntelligence(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    threat_type=threat_type,
                    confidence_score=confidence_score,
                    source=source,
                    threat_metadata=json.dumps(metadata) if isinstance(metadata, dict) else metadata
                )
                session.add(intel)
                session.flush()
                intel_id = intel.id
            
            session.commit()
            return intel_id
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_threat_intelligence(self, indicator_type=None, threat_type=None, limit=100):
        """Retrieve threat intelligence data"""
        session = self.get_session()
        try:
            query = session.query(ThreatIntelligence).filter(ThreatIntelligence.is_active == True)
            
            if indicator_type:
                query = query.filter(ThreatIntelligence.indicator_type == indicator_type)
            if threat_type:
                query = query.filter(ThreatIntelligence.threat_type == threat_type)
            
            intel = query.order_by(ThreatIntelligence.last_updated.desc()).limit(limit).all()
            
            results = []
            for item in intel:
                results.append({
                    'id': item.id,
                    'indicator': item.indicator,
                    'indicator_type': item.indicator_type,
                    'threat_type': item.threat_type,
                    'confidence_score': item.confidence_score,
                    'source': item.source,
                    'first_seen': item.first_seen.isoformat() if item.first_seen else None,
                    'last_updated': item.last_updated.isoformat() if item.last_updated else None,
                    'metadata': json.loads(item.threat_metadata) if item.threat_metadata else {}
                })
            return results
        finally:
            session.close()
    
    def get_dashboard_stats(self):
        """Get statistics for dashboard"""
        session = self.get_session()
        try:
            stats = {
                'total_scans': session.query(ScanHistory).count(),
                'total_vulnerabilities': session.query(VulnerabilityFindings).count(),
                'total_assets': session.query(NetworkAssets).count(),
                'total_reports': session.query(SecurityReports).count(),
                'high_risk_vulnerabilities': session.query(VulnerabilityFindings).filter(
                    VulnerabilityFindings.severity.in_(['critical', 'high'])
                ).count(),
                'recent_scans': session.query(ScanHistory).filter(
                    ScanHistory.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                ).count()
            }
            return stats
        finally:
            session.close()