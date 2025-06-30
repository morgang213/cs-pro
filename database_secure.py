import os
import json
import re
import html
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from typing import Optional, Dict, List, Any, Union
import uuid
import logging

Base = declarative_base()

# Secure input validation class
class SecurityValidator:
    """Enhanced input validation and sanitization for security purposes"""
    
    @staticmethod
    def sanitize_string(input_str: Optional[str], max_length: int = 255) -> str:
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
    def validate_scan_type(scan_type: str) -> str:
        """Validate scan type against allowed values"""
        allowed_types = [
            'network', 'vulnerability', 'password', 'hash', 'ip', 
            'domain', 'email', 'log', 'threat_intel', 'port_scan'
        ]
        
        if scan_type not in allowed_types:
            raise ValueError(f"Invalid scan type: {scan_type}")
        
        return scan_type
    
    @staticmethod
    def validate_severity(severity: Optional[str]) -> Optional[str]:
        """Validate severity level"""
        if not severity:
            return None
            
        allowed_severities = ['critical', 'high', 'medium', 'low', 'info']
        
        if severity.lower() not in allowed_severities:
            raise ValueError(f"Invalid severity level: {severity}")
        
        return severity.lower()

# Database Models
class ScanHistory(Base):
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default='completed')
    results = Column(Text)
    risk_score = Column(Float)
    user_notes = Column(Text)

class VulnerabilityFindings(Base):
    __tablename__ = 'vulnerability_findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20))
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
    open_ports = Column(Text)
    services = Column(Text)
    os_fingerprint = Column(String(200))
    last_scanned = Column(DateTime, default=datetime.utcnow)
    risk_level = Column(String(20))
    location_data = Column(Text)

class SecurityReports(Base):
    __tablename__ = 'security_reports'
    
    id = Column(Integer, primary_key=True)
    report_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    report_type = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    report_data = Column(Text)
    format_type = Column(String(20))
    file_path = Column(String(500))

class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True)
    indicator = Column(String(500), nullable=False)
    indicator_type = Column(String(50), nullable=False)
    threat_type = Column(String(100))
    confidence_score = Column(Float)
    source = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    threat_metadata = Column(Text)

class SecureDatabaseManager:
    """Secure database manager with comprehensive error handling"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engine = None
        self.Session = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database connection with security settings"""
        try:
            # Use PostgreSQL if available, otherwise SQLite
            database_url = os.getenv('DATABASE_URL')
            
            if database_url:
                # PostgreSQL connection with security settings
                self.engine = create_engine(
                    database_url,
                    pool_pre_ping=True,
                    pool_recycle=300,
                    echo=False
                )
            else:
                # SQLite fallback with security settings
                self.engine = create_engine(
                    'sqlite:///cybersec_data.db',
                    poolclass=StaticPool,
                    connect_args={'check_same_thread': False}
                )
            
            self.Session = sessionmaker(bind=self.engine)
            self.create_tables()
            
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise
    
    def create_tables(self):
        """Create all database tables"""
        try:
            Base.metadata.create_all(self.engine)
            self.logger.info("Database tables created successfully")
        except Exception as e:
            self.logger.error(f"Table creation failed: {e}")
            raise
    
    def get_session(self):
        """Get a database session with error handling"""
        try:
            return self.Session()
        except Exception as e:
            self.logger.error(f"Session creation failed: {e}")
            raise
    
    def save_scan_result(self, scan_type: str, target: str, results: Dict[str, Any], 
                        risk_score: Optional[float] = None, user_notes: Optional[str] = None) -> str:
        """Save scan results with comprehensive validation"""
        session = self.get_session()
        try:
            # Validate inputs
            scan_type = SecurityValidator.validate_scan_type(scan_type)
            target = SecurityValidator.sanitize_string(target, 255)
            results_json = SecurityValidator.validate_json_data(results)
            
            if user_notes:
                user_notes = SecurityValidator.sanitize_string(user_notes, 1000)
            
            # Create scan record
            scan = ScanHistory(
                scan_type=scan_type,
                target=target,
                results=results_json,
                risk_score=risk_score,
                user_notes=user_notes
            )
            
            session.add(scan)
            session.commit()
            
            return scan.scan_id
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Failed to save scan result: {e}")
            raise
        finally:
            session.close()
    
    def get_scan_history(self, scan_type: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve scan history with security validation"""
        session = self.get_session()
        try:
            query = session.query(ScanHistory)
            
            if scan_type:
                scan_type = SecurityValidator.validate_scan_type(scan_type)
                query = query.filter(ScanHistory.scan_type == scan_type)
            
            scans = query.order_by(ScanHistory.timestamp.desc()).limit(limit).all()
            
            results = []
            for scan in scans:
                try:
                    # Safe access to scan attributes
                    timestamp_str = scan.timestamp.isoformat() if scan.timestamp else None
                    
                    results.append({
                        'scan_id': scan.scan_id,
                        'scan_type': scan.scan_type,
                        'target': scan.target,
                        'timestamp': timestamp_str,
                        'status': scan.status,
                        'risk_score': scan.risk_score,
                        'user_notes': scan.user_notes
                    })
                except Exception as e:
                    self.logger.warning(f"Error processing scan record {scan.id}: {e}")
                    continue
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve scan history: {e}")
            return []
        finally:
            session.close()
    
    def save_vulnerability(self, scan_id: str, vuln_type: str, severity: Optional[str], 
                          target_url: Optional[str] = None, description: Optional[str] = None, 
                          recommendation: Optional[str] = None) -> int:
        """Save vulnerability finding with validation"""
        session = self.get_session()
        try:
            # Validate inputs
            scan_id = SecurityValidator.sanitize_string(scan_id, 36)
            vuln_type = SecurityValidator.sanitize_string(vuln_type, 100)
            severity = SecurityValidator.validate_severity(severity)
            
            if target_url:
                target_url = SecurityValidator.validate_url(target_url)
            if description:
                description = SecurityValidator.sanitize_string(description, 2000)
            if recommendation:
                recommendation = SecurityValidator.sanitize_string(recommendation, 2000)
            
            vulnerability = VulnerabilityFindings(
                scan_id=scan_id,
                vulnerability_type=vuln_type,
                severity=severity,
                target_url=target_url,
                description=description,
                recommendation=recommendation
            )
            
            session.add(vulnerability)
            session.commit()
            
            return vulnerability.id
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Failed to save vulnerability: {e}")
            raise
        finally:
            session.close()
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics with error handling"""
        session = self.get_session()
        try:
            stats = {}
            
            # Get scan counts
            total_scans = session.query(ScanHistory).count()
            stats['total_scans'] = total_scans
            
            # Get vulnerability counts by severity
            critical_vulns = session.query(VulnerabilityFindings).filter(
                VulnerabilityFindings.severity == 'critical'
            ).count()
            stats['critical_vulnerabilities'] = critical_vulns
            
            high_vulns = session.query(VulnerabilityFindings).filter(
                VulnerabilityFindings.severity == 'high'
            ).count()
            stats['high_vulnerabilities'] = high_vulns
            
            # Get network assets count
            total_assets = session.query(NetworkAssets).count()
            stats['network_assets'] = total_assets
            
            # Get threat intelligence count
            total_threats = session.query(ThreatIntelligence).count()
            stats['threat_indicators'] = total_threats
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get dashboard stats: {e}")
            return {
                'total_scans': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'network_assets': 0,
                'threat_indicators': 0
            }
        finally:
            session.close()

# Add missing validation methods to SecurityValidator
SecurityValidator.validate_json_data = lambda data: json.dumps(data) if isinstance(data, dict) else "{}"
SecurityValidator.validate_url = lambda url: url[:500] if url and url.startswith(('http://', 'https://')) else ""