import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime

class UIHelpers:
    """Helper functions for consistent UI components"""
    
    @staticmethod
    def show_loading_message(message="Processing..."):
        """Show a consistent loading message"""
        return st.spinner(message)
    
    @staticmethod
    def show_success_alert(message):
        """Show a success alert with consistent styling"""
        st.success(f"✅ {message}")
    
    @staticmethod
    def show_error_alert(message):
        """Show an error alert with consistent styling"""
        st.error(f"❌ {message}")
    
    @staticmethod
    def show_warning_alert(message):
        """Show a warning alert with consistent styling"""
        st.warning(f"⚠️ {message}")
    
    @staticmethod
    def show_info_alert(message):
        """Show an info alert with consistent styling"""
        st.info(f"ℹ️ {message}")
    
    @staticmethod
    def create_metric_card(title, value, delta=None, help_text=None):
        """Create a metric card with consistent styling"""
        return st.metric(
            label=title,
            value=value,
            delta=delta,
            help=help_text
        )
    
    @staticmethod
    def create_risk_score_gauge(score, title="Risk Score"):
        """Create a risk score gauge chart"""
        if not isinstance(score, (int, float)):
            return None
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': title},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "red"}],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90}}))
        
        fig.update_layout(height=300)
        return fig
    
    @staticmethod
    def create_vulnerability_chart(vulnerabilities):
        """Create a vulnerability severity chart"""
        if not vulnerabilities:
            return None
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if not severity_counts:
            return None
        
        fig = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title="Vulnerabilities by Severity",
            color_discrete_map={
                'Critical': '#FF0000',
                'High': '#FF6600',
                'Medium': '#FFAA00',
                'Low': '#FFFF00',
                'Info': '#00AA00'
            }
        )
        return fig
    
    @staticmethod
    def safe_get(data, key, default="N/A"):
        """Safely get value from dictionary with proper type checking"""
        if not isinstance(data, dict):
            return default
        return data.get(key, default)
    
    @staticmethod
    def safe_list_access(data, index, default="N/A"):
        """Safely access list items with bounds checking"""
        if not isinstance(data, list) or index >= len(data):
            return default
        return data[index]
    
    @staticmethod
    def format_risk_level(score):
        """Format risk score into human-readable level"""
        if not isinstance(score, (int, float)):
            return "Unknown"
        
        if score >= 80:
            return "🔴 High Risk"
        elif score >= 60:
            return "🟡 Medium Risk"
        elif score >= 40:
            return "🟠 Low-Medium Risk"
        else:
            return "🟢 Low Risk"
    
    @staticmethod
    def create_data_table(data, columns=None):
        """Create a formatted data table"""
        if not data:
            return st.write("No data available")
        
        if isinstance(data, list) and len(data) > 0:
            df = pd.DataFrame(data)
            if columns:
                df = df[columns] if all(col in df.columns for col in columns) else df
            return st.dataframe(df, use_container_width=True)
        else:
            return st.write("No data available")
    
    @staticmethod
    def create_expandable_section(title, content_dict, max_items=10):
        """Create an expandable section for detailed information"""
        with st.expander(title):
            if isinstance(content_dict, dict):
                for key, value in list(content_dict.items())[:max_items]:
                    if isinstance(value, list):
                        st.write(f"**{key}:**")
                        for item in value[:5]:  # Limit list items
                            st.write(f"  • {item}")
                        if len(value) > 5:
                            st.write(f"  ... and {len(value) - 5} more items")
                    else:
                        st.write(f"**{key}:** {value}")
            else:
                st.write(str(content_dict))
    
    @staticmethod
    def show_progress_bar(current, total, text="Progress"):
        """Show a progress bar with text"""
        progress = current / total if total > 0 else 0
        st.progress(progress)
        st.write(f"{text}: {current}/{total} ({progress:.1%})")
    
    @staticmethod
    def create_timeline_chart(events):
        """Create a timeline chart for events"""
        if not events or not isinstance(events, list):
            return None
        
        # Convert events to DataFrame for plotting
        df_events = []
        for event in events:
            if isinstance(event, dict):
                df_events.append({
                    'timestamp': event.get('timestamp', 'Unknown'),
                    'count': event.get('count', 1),
                    'type': event.get('type', 'Event')
                })
        
        if not df_events:
            return None
        
        df = pd.DataFrame(df_events)
        fig = px.line(df, x='timestamp', y='count', title='Security Events Timeline')
        fig.update_layout(height=400)
        return fig
    
    @staticmethod
    def validate_input(input_value, input_type="text", min_length=1, max_length=1000):
        """Validate user input with appropriate checks"""
        if not input_value or len(input_value.strip()) < min_length:
            return False, f"Input must be at least {min_length} characters long"
        
        if len(input_value) > max_length:
            return False, f"Input must be less than {max_length} characters"
        
        if input_type == "email":
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, input_value):
                return False, "Please enter a valid email address"
        
        elif input_type == "domain":
            import re
            domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, input_value):
                return False, "Please enter a valid domain name"
        
        elif input_type == "ip":
            import ipaddress
            try:
                ipaddress.ip_address(input_value)
            except ValueError:
                return False, "Please enter a valid IP address"
        
        return True, "Valid input"