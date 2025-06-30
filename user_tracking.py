"""
User Tracking and Session Management
Tracks individual user sessions, activities, and statistics
"""

import streamlit as st
import uuid
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import json
import hashlib
from typing import Dict, List, Optional

Base = declarative_base()

class UserSessions(Base):
    __tablename__ = 'user_sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), unique=True, nullable=False)
    user_identifier = Column(String(255))  # IP hash or user-provided ID
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    total_tools_used = Column(Integer, default=0)
    tools_accessed = Column(Text)  # JSON array of tools used
    scan_count = Column(Integer, default=0)
    vulnerability_count = Column(Integer, default=0)
    report_count = Column(Integer, default=0)
    session_data = Column(Text)  # JSON for additional session info
    is_active = Column(Boolean, default=True)

class UserActivity(Base):
    __tablename__ = 'user_activity'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey('user_sessions.session_id'))
    activity_type = Column(String(50), nullable=False)  # 'scan', 'analysis', 'report', etc.
    tool_name = Column(String(100), nullable=False)
    target = Column(String(500))  # What was analyzed
    timestamp = Column(DateTime, default=datetime.utcnow)
    duration_seconds = Column(Integer)
    results_summary = Column(Text)  # Brief summary of results
    success = Column(Boolean, default=True)

class UserStats(Base):
    __tablename__ = 'user_stats'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey('user_sessions.session_id'))
    date = Column(String(10))  # YYYY-MM-DD
    scans_performed = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    reports_generated = Column(Integer, default=0)
    tools_used = Column(Text)  # JSON array of tools used today
    time_spent_minutes = Column(Integer, default=0)
    unique_targets = Column(Integer, default=0)

class UserTracker:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.session_id = self._get_or_create_session()
        
    def _get_or_create_session(self) -> str:
        """Get or create user session"""
        # Check if session exists in Streamlit session state
        if 'user_session_id' not in st.session_state:
            # Create new session
            session_id = str(uuid.uuid4())
            st.session_state.user_session_id = session_id
            st.session_state.session_start_time = datetime.now()
            
            # Create user identifier (hash of IP + browser info)
            user_identifier = self._create_user_identifier()
            
            # Save to database
            self._create_user_session(session_id, user_identifier)
        else:
            session_id = st.session_state.user_session_id
            self._update_last_seen(session_id)
            
        return session_id
    
    def _create_user_identifier(self) -> str:
        """Create anonymous user identifier"""
        # Get client IP from Streamlit headers (if available)
        try:
            # In production, you might get this from headers
            client_info = f"{st.get_option('server.address')}:{datetime.now().date()}"
            return hashlib.sha256(client_info.encode()).hexdigest()[:16]
        except:
            return "anonymous_user"
    
    def _create_user_session(self, session_id: str, user_identifier: str):
        """Create new user session in database"""
        session = self.db_manager.get_session()
        try:
            user_session = UserSessions(
                session_id=session_id,
                user_identifier=user_identifier,
                tools_accessed="[]",
                session_data=json.dumps({
                    "browser": "unknown",
                    "platform": "web",
                    "start_time": datetime.now().isoformat()
                })
            )
            session.add(user_session)
            session.commit()
        finally:
            session.close()
    
    def _update_last_seen(self, session_id: str):
        """Update last seen timestamp"""
        session = self.db_manager.get_session()
        try:
            user_session = session.query(UserSessions).filter_by(session_id=session_id).first()
            if user_session:
                user_session.last_seen = datetime.utcnow()
                session.commit()
        finally:
            session.close()
    
    def track_tool_usage(self, tool_name: str, target: str = None, results_summary: str = None):
        """Track when user uses a security tool"""
        session = self.db_manager.get_session()
        try:
            # Record activity
            activity = UserActivity(
                session_id=self.session_id,
                activity_type="tool_usage",
                tool_name=tool_name,
                target=target,
                results_summary=results_summary
            )
            session.add(activity)
            
            # Update session stats
            user_session = session.query(UserSessions).filter_by(session_id=self.session_id).first()
            if user_session:
                # Update tools accessed
                tools_list = json.loads(user_session.tools_accessed or "[]")
                if tool_name not in tools_list:
                    tools_list.append(tool_name)
                    user_session.tools_accessed = json.dumps(tools_list)
                    user_session.total_tools_used = len(tools_list)
                
                session.commit()
        finally:
            session.close()
    
    def track_scan_result(self, scan_type: str, target: str, vulnerabilities_found: int = 0):
        """Track scan completion and results"""
        session = self.db_manager.get_session()
        try:
            # Record activity
            activity = UserActivity(
                session_id=self.session_id,
                activity_type="scan",
                tool_name=scan_type,
                target=target,
                results_summary=f"Found {vulnerabilities_found} vulnerabilities"
            )
            session.add(activity)
            
            # Update session counters
            user_session = session.query(UserSessions).filter_by(session_id=self.session_id).first()
            if user_session:
                user_session.scan_count += 1
                user_session.vulnerability_count += vulnerabilities_found
                session.commit()
            
            # Update daily stats
            self._update_daily_stats("scan", vulnerabilities_found)
            
        finally:
            session.close()
    
    def track_report_generation(self, report_type: str):
        """Track report generation"""
        session = self.db_manager.get_session()
        try:
            # Record activity
            activity = UserActivity(
                session_id=self.session_id,
                activity_type="report",
                tool_name="report_generator",
                target=report_type,
                results_summary=f"Generated {report_type} report"
            )
            session.add(activity)
            
            # Update session counters
            user_session = session.query(UserSessions).filter_by(session_id=self.session_id).first()
            if user_session:
                user_session.report_count += 1
                session.commit()
            
            # Update daily stats
            self._update_daily_stats("report")
            
        finally:
            session.close()
    
    def _update_daily_stats(self, activity_type: str, count: int = 1):
        """Update daily statistics"""
        today = datetime.now().strftime("%Y-%m-%d")
        session = self.db_manager.get_session()
        try:
            # Get or create daily stats
            daily_stats = session.query(UserStats).filter_by(
                session_id=self.session_id,
                date=today
            ).first()
            
            if not daily_stats:
                daily_stats = UserStats(
                    session_id=self.session_id,
                    date=today,
                    tools_used="[]"
                )
                session.add(daily_stats)
            
            # Update based on activity type
            if activity_type == "scan":
                daily_stats.scans_performed += 1
                daily_stats.vulnerabilities_found += count
            elif activity_type == "report":
                daily_stats.reports_generated += 1
            
            session.commit()
        finally:
            session.close()
    
    def get_user_session_stats(self) -> Dict:
        """Get current session statistics"""
        session = self.db_manager.get_session()
        try:
            user_session = session.query(UserSessions).filter_by(session_id=self.session_id).first()
            if not user_session:
                return {}
            
            # Calculate session duration
            session_duration = datetime.utcnow() - user_session.first_seen
            
            return {
                "session_id": user_session.session_id,
                "session_duration_minutes": int(session_duration.total_seconds() / 60),
                "tools_used": len(json.loads(user_session.tools_accessed or "[]")),
                "tools_list": json.loads(user_session.tools_accessed or "[]"),
                "scans_performed": user_session.scan_count,
                "vulnerabilities_found": user_session.vulnerability_count,
                "reports_generated": user_session.report_count,
                "first_seen": user_session.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": user_session.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            }
        finally:
            session.close()
    
    def get_user_activity_history(self, limit: int = 50) -> List[Dict]:
        """Get recent user activity"""
        session = self.db_manager.get_session()
        try:
            activities = session.query(UserActivity)\
                .filter_by(session_id=self.session_id)\
                .order_by(UserActivity.timestamp.desc())\
                .limit(limit).all()
            
            return [{
                "timestamp": activity.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "tool": activity.tool_name,
                "activity": activity.activity_type,
                "target": activity.target,
                "summary": activity.results_summary,
                "success": activity.success
            } for activity in activities]
        finally:
            session.close()
    
    def get_daily_stats(self, days: int = 7) -> List[Dict]:
        """Get daily statistics for the last N days"""
        session = self.db_manager.get_session()
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            stats = session.query(UserStats)\
                .filter_by(session_id=self.session_id)\
                .filter(UserStats.date >= start_date.strftime("%Y-%m-%d"))\
                .order_by(UserStats.date.desc()).all()
            
            return [{
                "date": stat.date,
                "scans": stat.scans_performed,
                "vulnerabilities": stat.vulnerabilities_found,
                "reports": stat.reports_generated,
                "tools_used": len(json.loads(stat.tools_used or "[]")),
                "time_spent": stat.time_spent_minutes
            } for stat in stats]
        finally:
            session.close()
    
    def get_tool_usage_summary(self) -> Dict:
        """Get summary of tool usage"""
        session = self.db_manager.get_session()
        try:
            activities = session.query(UserActivity)\
                .filter_by(session_id=self.session_id).all()
            
            tool_counts = {}
            for activity in activities:
                tool = activity.tool_name
                if tool not in tool_counts:
                    tool_counts[tool] = 0
                tool_counts[tool] += 1
            
            return tool_counts
        finally:
            session.close()
    
    def export_user_data(self) -> Dict:
        """Export all user data for privacy compliance"""
        return {
            "session_stats": self.get_user_session_stats(),
            "activity_history": self.get_user_activity_history(limit=1000),
            "daily_stats": self.get_daily_stats(days=30),
            "tool_usage": self.get_tool_usage_summary()
        }
    
    @staticmethod
    def create_tables(engine):
        """Create user tracking tables"""
        Base.metadata.create_all(bind=engine)