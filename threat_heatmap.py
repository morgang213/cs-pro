import requests
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import ipaddress
# Removed geoip2 dependencies to use free APIs instead
from collections import defaultdict
import threading
import time

class ThreatHeatmapGenerator:
    def __init__(self):
        self.threat_data = []
        self.update_interval = 30  # seconds
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Common threat intelligence sources (mock endpoints for demo)
        self.threat_sources = {
            'malicious_ips': [
                '185.220.100.240',  # Known Tor exit node
                '198.98.62.124',    # Suspicious IP
                '45.148.10.67',     # Malware C&C
                '103.145.13.26',    # Botnet IP
                '92.63.197.153',    # Attack source
            ],
            'attack_types': ['DDoS', 'Brute Force', 'Malware', 'Phishing', 'Botnet']
        }
        
    def get_ip_geolocation(self, ip_address):
        """Get geolocation for IP address with fallback data"""
        # Mock geolocation data for demo purposes
        ip_geo_map = {
            '185.220.100.240': {'country': 'Germany', 'country_code': 'DE', 'city': 'Frankfurt'},
            '198.98.62.124': {'country': 'United States', 'country_code': 'US', 'city': 'New York'},
            '45.148.10.67': {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow'},
            '103.145.13.26': {'country': 'China', 'country_code': 'CN', 'city': 'Beijing'},
            '92.63.197.153': {'country': 'Netherlands', 'country_code': 'NL', 'city': 'Amsterdam'},
        }
        
        geo_data = ip_geo_map.get(ip_address, {
            'country': 'Unknown', 
            'country_code': 'UN', 
            'city': 'Unknown'
        })
        
        return {
            'ip': ip_address,
            'country': geo_data['country'],
            'country_code': geo_data['country_code'],
            'region': geo_data.get('region', 'Unknown'),
            'city': geo_data['city'],
            'lat': 0,
            'lon': 0,
            'org': 'Unknown',
            'isp': 'Unknown'
        }
    
    def generate_threat_intelligence(self):
        """Generate realistic threat intelligence data"""
        import random
        
        threat_data = []
        current_time = datetime.now()
        
        # Generate data for the last 24 hours
        for hour in range(24):
            timestamp = current_time - timedelta(hours=hour)
            
            # Generate random threat events
            num_events = random.randint(5, 20)
            for _ in range(num_events):
                # Select random malicious IP
                ip = random.choice(self.threat_sources['malicious_ips'])
                attack_type = random.choice(self.threat_sources['attack_types'])
                
                # Get geolocation
                geo_data = self.get_ip_geolocation(ip)
                
                # Generate severity based on attack type
                severity_weights = {
                    'DDoS': [0.2, 0.3, 0.3, 0.2],  # low, medium, high, critical
                    'Brute Force': [0.1, 0.4, 0.4, 0.1],
                    'Malware': [0.1, 0.2, 0.4, 0.3],
                    'Phishing': [0.3, 0.4, 0.2, 0.1],
                    'Botnet': [0.1, 0.3, 0.3, 0.3]
                }
                
                severity_levels = ['low', 'medium', 'high', 'critical']
                severity = random.choices(severity_levels, weights=severity_weights[attack_type])[0]
                
                threat_event = {
                    'timestamp': timestamp,
                    'ip_address': ip,
                    'attack_type': attack_type,
                    'severity': severity,
                    'country': geo_data['country'],
                    'country_code': geo_data['country_code'],
                    'city': geo_data['city'],
                    'latitude': geo_data['lat'],
                    'longitude': geo_data['lon'],
                    'organization': geo_data['org'],
                    'confidence': random.uniform(0.7, 0.95),
                    'target_port': random.choice([22, 80, 443, 25, 53, 3389]),
                    'blocked': random.choice([True, False]),
                }
                
                threat_data.append(threat_event)
        
        return threat_data
    
    def create_global_heatmap(self, threat_data=None):
        """Create global threat heatmap"""
        if threat_data is None:
            threat_data = self.generate_threat_intelligence()
        
        df = pd.DataFrame(threat_data)
        
        if df.empty:
            return go.Figure().add_annotation(
                text="No threat data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
        
        # Aggregate threats by country
        country_threats = df.groupby(['country', 'country_code']).agg({
            'ip_address': 'count',
            'severity': lambda x: sum(1 for s in x if s in ['high', 'critical']),
            'confidence': 'mean'
        }).reset_index()
        
        country_threats.columns = ['country', 'country_code', 'total_threats', 'high_severity_threats', 'avg_confidence']
        
        # Create choropleth map
        fig = px.choropleth(
            country_threats,
            locations='country_code',
            color='total_threats',
            hover_name='country',
            hover_data={
                'total_threats': True,
                'high_severity_threats': True,
                'avg_confidence': ':.2f'
            },
            color_continuous_scale='Reds',
            title='Global Network Threat Heatmap',
            labels={'total_threats': 'Threat Count'}
        )
        
        fig.update_layout(
            title_x=0.5,
            geo=dict(showframe=False, showcoastlines=True),
            height=600
        )
        
        return fig
    
    def create_threat_timeline(self, threat_data=None):
        """Create threat activity timeline"""
        if threat_data is None:
            threat_data = self.generate_threat_intelligence()
        
        df = pd.DataFrame(threat_data)
        
        if df.empty:
            return go.Figure()
        
        # Group by hour and severity
        df['hour'] = df['timestamp'].dt.floor('H')
        timeline_data = df.groupby(['hour', 'severity']).size().reset_index(name='count')
        
        # Create stacked bar chart
        fig = px.bar(
            timeline_data,
            x='hour',
            y='count',
            color='severity',
            title='Threat Activity Timeline (Last 24 Hours)',
            color_discrete_map={
                'low': '#ffffcc',
                'medium': '#fd8d3c',
                'high': '#e31a1c',
                'critical': '#800026'
            }
        )
        
        fig.update_layout(
            title_x=0.5,
            xaxis_title='Time',
            yaxis_title='Threat Count',
            height=400
        )
        
        return fig
    
    def generate_heatmap(self, threat_types=None, time_range=24):
        """Generate heatmap data for visualization"""
        # Generate threat intelligence data
        threat_data = self.generate_threat_intelligence()
        
        if not threat_data:
            return {
                'countries': {},
                'timeline': [],
                'total_threats': 0,
                'metrics': {}
            }
        
        df = pd.DataFrame(threat_data)
        
        # Aggregate by country
        country_data = df.groupby('country').agg({
            'ip_address': 'count',
            'severity': lambda x: sum(1 for s in x if s in ['high', 'critical'])
        }).to_dict()
        
        countries = {}
        if 'ip_address' in country_data:
            countries = country_data['ip_address']
        
        # Create timeline data
        timeline = []
        for i in range(24):
            timeline.append({
                'time': f"{i:02d}:00",
                'threats': max(1, len(threat_data) // 24 + (i % 3))
            })
        
        # Calculate metrics
        metrics = self.create_severity_metrics(threat_data)
        
        return {
            'countries': countries,
            'timeline': timeline,
            'total_threats': len(threat_data),
            'metrics': metrics
        }
    
    def create_attack_type_distribution(self, threat_data=None):
        """Create attack type distribution chart"""
        if threat_data is None:
            threat_data = self.generate_threat_intelligence()
        
        df = pd.DataFrame(threat_data)
        
        if df.empty:
            return go.Figure()
        
        # Count attack types
        attack_counts = df['attack_type'].value_counts()
        
        fig = px.pie(
            values=attack_counts.values,
            names=attack_counts.index,
            title='Attack Type Distribution',
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        
        fig.update_layout(title_x=0.5, height=400)
        
        return fig
    
    def create_severity_metrics(self, threat_data=None):
        """Create severity-based metrics"""
        if threat_data is None:
            threat_data = self.generate_threat_intelligence()
        
        df = pd.DataFrame(threat_data)
        
        if df.empty:
            return {
                'total_threats': 0,
                'critical_threats': 0,
                'high_threats': 0,
                'blocked_threats': 0,
                'threat_countries': 0
            }
        
        metrics = {
            'total_threats': len(df),
            'critical_threats': len(df[df['severity'] == 'critical']),
            'high_threats': len(df[df['severity'] == 'high']),
            'blocked_threats': len(df[df['blocked'] == True]),
            'threat_countries': df['country'].nunique(),
            'avg_confidence': df['confidence'].mean()
        }
        
        return metrics
    
    def get_top_threat_sources(self, threat_data=None, limit=10):
        """Get top threat source countries"""
        if threat_data is None:
            threat_data = self.generate_threat_intelligence()
        
        df = pd.DataFrame(threat_data)
        
        if df.empty:
            return []
        
        top_sources = df.groupby('country').agg({
            'ip_address': 'count',
            'severity': lambda x: sum(1 for s in x if s in ['high', 'critical'])
        }).reset_index()
        
        top_sources.columns = ['country', 'threat_count', 'high_severity_count']
        top_sources = top_sources.sort_values('threat_count', ascending=False).head(limit)
        
        return top_sources.to_dict('records')
    
    def get_threat_indicators(self, threat_data=None):
        """Get key threat indicators"""
        if threat_data is None:
            threat_data = self.generate_threat_intelligence()
        
        df = pd.DataFrame(threat_data)
        
        if df.empty:
            return []
        
        # Get unique malicious IPs with details
        indicators = []
        for ip in df['ip_address'].unique():
            ip_data = df[df['ip_address'] == ip].iloc[0]
            
            indicators.append({
                'ip_address': ip,
                'country': ip_data['country'],
                'attack_types': list(df[df['ip_address'] == ip]['attack_type'].unique()),
                'severity_max': df[df['ip_address'] == ip]['severity'].map(
                    {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                ).max(),
                'first_seen': df[df['ip_address'] == ip]['timestamp'].min(),
                'last_seen': df[df['ip_address'] == ip]['timestamp'].max(),
                'total_attacks': len(df[df['ip_address'] == ip])
            })
        
        # Sort by severity and attack count
        indicators.sort(key=lambda x: (x['severity_max'], x['total_attacks']), reverse=True)
        
        return indicators[:20]  # Return top 20 indicators