import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
from html import escape

class UIHelpers:
    """Helper functions for consistent UI components"""

    _THEME_FLAG = "_cybersec_professional_theme_applied"
    _PAGE_FLAG = "_cybersec_page_config_applied"

    @staticmethod
    def ensure_professional_ui(
        page_title="CyberSec Operations Console",
        layout="wide",
        sidebar_state="expanded",
    ):
        """Best-effort one-call initializer for page config and theme."""
        UIHelpers.configure_professional_page(
            page_title=page_title,
            layout=layout,
            sidebar_state=sidebar_state,
        )
        UIHelpers.apply_professional_theme()

    @staticmethod
    def configure_professional_page(
        page_title="CyberSec Operations Console",
        layout="wide",
        sidebar_state="expanded",
    ):
        """Configure Streamlit page once, safely, for professional dashboards."""
        if st.session_state.get(UIHelpers._PAGE_FLAG):
            return

        # set_page_config must run before most Streamlit calls; guard to avoid hard failures.
        try:
            st.set_page_config(
                page_title=page_title,
                layout=layout,
                initial_sidebar_state=sidebar_state,
            )
            st.session_state[UIHelpers._PAGE_FLAG] = True
        except Exception:
            # Ignore when page config was already set by a caller.
            st.session_state[UIHelpers._PAGE_FLAG] = True

    @staticmethod
    def apply_professional_theme():
        """Apply a unified visual theme for all Streamlit security surfaces."""
        # Attempt page config first; harmlessly ignored if Streamlit state is already initialized.
        UIHelpers.configure_professional_page()

        if st.session_state.get(UIHelpers._THEME_FLAG):
            return

        st.markdown(
            """
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=IBM+Plex+Sans:wght@400;600;700&display=swap');

                :root {
                    --cs-bg-deep: #05130e;
                    --cs-bg-mid: #0c2319;
                    --cs-surface: #112b20;
                    --cs-line: #1f6a4d;
                    --cs-text-main: #e6fff1;
                    --cs-text-muted: #9fd9bc;
                    --cs-accent: #3fffb6;
                    --cs-cyan: #77e4ff;
                    --cs-warning: #ffc562;
                    --cs-danger: #ff7f7f;
                    --cs-success: #78f0b2;
                }

                .stApp {
                    background:
                        radial-gradient(circle at 12% 14%, rgba(63, 255, 182, 0.10) 0%, transparent 30%),
                        radial-gradient(circle at 85% 6%, rgba(119, 228, 255, 0.10) 0%, transparent 26%),
                        linear-gradient(135deg, var(--cs-bg-deep) 0%, var(--cs-bg-mid) 100%);
                    color: var(--cs-text-main);
                }

                .stApp h1,
                .stApp h2,
                .stApp h3,
                .stApp h4,
                .stApp h5,
                .stApp h6 {
                    color: var(--cs-text-main);
                    font-family: 'Space Mono', monospace;
                    letter-spacing: 0.02em;
                }

                .stMarkdown,
                .stText,
                .stCaption,
                .stMetric,
                .stDataFrame,
                .stSelectbox,
                .stTextInput,
                .stTextArea,
                .stNumberInput,
                .stMultiSelect,
                .stRadio,
                .stCheckbox,
                .stButton,
                .stDownloadButton {
                    font-family: 'IBM Plex Sans', sans-serif;
                }

                section[data-testid="stSidebar"] {
                    background: linear-gradient(180deg, rgba(8, 30, 20, 0.95) 0%, rgba(5, 18, 12, 0.97) 100%);
                    border-right: 1px solid rgba(63, 255, 182, 0.25);
                }

                .stAlert {
                    border-radius: 12px;
                    border: 1px solid var(--cs-line);
                }

                .cs-alert {
                    border-radius: 10px;
                    padding: 0.65rem 0.85rem;
                    margin: 0.4rem 0;
                    border: 1px solid var(--cs-line);
                    font-size: 0.95rem;
                    line-height: 1.4;
                    background: rgba(17, 43, 32, 0.85);
                    color: var(--cs-text-main);
                }

                .cs-alert-success {
                    border-color: rgba(120, 240, 178, 0.55);
                    background: rgba(120, 240, 178, 0.12);
                }

                .cs-alert-error {
                    border-color: rgba(255, 127, 127, 0.60);
                    background: rgba(255, 127, 127, 0.12);
                }

                .cs-alert-warning {
                    border-color: rgba(255, 197, 98, 0.60);
                    background: rgba(255, 197, 98, 0.12);
                }

                .cs-alert-info {
                    border-color: rgba(119, 228, 255, 0.60);
                    background: rgba(119, 228, 255, 0.12);
                }
            </style>
            """,
            unsafe_allow_html=True,
        )

        st.session_state[UIHelpers._THEME_FLAG] = True

    @staticmethod
    def _render_alert(css_modifier, message):
        UIHelpers.apply_professional_theme()
        safe_message = escape(str(message))
        st.markdown(
            '<div class="cs-alert cs-alert-{}">{}</div>'.format(css_modifier, safe_message),
            unsafe_allow_html=True,
        )
    
    @staticmethod
    def show_loading_message(message="Processing..."):
        """Show a consistent loading message"""
        UIHelpers.apply_professional_theme()
        return st.spinner(message)
    
    @staticmethod
    def show_success_alert(message):
        """Show a success alert with consistent styling"""
        UIHelpers._render_alert('success', 'SUCCESS: {}'.format(message))
    
    @staticmethod
    def show_error_alert(message):
        """Show an error alert with consistent styling"""
        UIHelpers._render_alert('error', 'ERROR: {}'.format(message))
    
    @staticmethod
    def show_warning_alert(message):
        """Show a warning alert with consistent styling"""
        UIHelpers._render_alert('warning', 'WARNING: {}'.format(message))
    
    @staticmethod
    def show_info_alert(message):
        """Show an info alert with consistent styling"""
        UIHelpers._render_alert('info', 'INFO: {}'.format(message))
    
    @staticmethod
    def create_metric_card(title, value, delta=None, help_text=None):
        """Create a metric card with consistent styling"""
        UIHelpers.apply_professional_theme()
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

        UIHelpers.apply_professional_theme()
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': title},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "#3fffb6"},
                'steps': [
                    {'range': [0, 50], 'color': "#224f39"},
                    {'range': [50, 80], 'color': "#915f19"},
                    {'range': [80, 100], 'color': "#802f2f"}],
                'threshold': {
                    'line': {'color': "#ff7f7f", 'width': 4},
                    'thickness': 0.75,
                    'value': 90}}))
        
        fig.update_layout(
            height=300,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': '#e6fff1', 'family': 'IBM Plex Sans, sans-serif'},
        )
        return fig
    
    @staticmethod
    def create_vulnerability_chart(vulnerabilities):
        """Create a vulnerability severity chart"""
        if not vulnerabilities:
            return None

        UIHelpers.apply_professional_theme()
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = str(vuln.get('severity', 'Unknown')).strip().capitalize()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if not severity_counts:
            return None
        
        fig = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title="Vulnerabilities by Severity",
            color_discrete_map={
                'Critical': '#ff5f5f',
                'High': '#ff885f',
                'Medium': '#ffc562',
                'Low': '#77e4ff',
                'Info': '#78f0b2'
            }
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': '#e6fff1', 'family': 'IBM Plex Sans, sans-serif'},
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