import json
from datetime import datetime
import base64

class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'vulnerability_assessment': self._vulnerability_template,
            'network_security': self._network_security_template,
            'comprehensive': self._comprehensive_template
        }
    
    def generate_report(self, report_data, include_charts=True, include_recommendations=True):
        """
        Generate security report based on provided data
        """
        try:
            report_type = report_data.get('type', 'comprehensive').lower().replace(' ', '_')
            
            # Get appropriate template
            template_func = self.report_templates.get(report_type, self._comprehensive_template)
            
            # Generate report content
            report_content = template_func(report_data, include_charts, include_recommendations)
            
            return {
                'title': report_data.get('title', 'Security Report'),
                'type': report_type,
                'timestamp': datetime.now().isoformat(),
                'content': report_content,
                'metadata': {
                    'generated_by': 'CyberSec Analyst Tool',
                    'version': '1.0',
                    'include_charts': include_charts,
                    'include_recommendations': include_recommendations
                }
            }
            
        except Exception as e:
            return {'error': f'Report generation failed: {str(e)}'}
    
    def _vulnerability_template(self, data, include_charts, include_recommendations):
        """
        Generate vulnerability assessment report
        """
        content = f"""# {data.get('title', 'Vulnerability Assessment Report')}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Report Type:** Vulnerability Assessment  

## Executive Summary

This report presents the results of a comprehensive vulnerability assessment conducted on the target systems and applications.

### Key Findings

"""
        
        summary = data.get('summary', {})
        
        content += f"""- **Total Assets Assessed:** {summary.get('total_assets', 'N/A')}
- **Vulnerabilities Identified:** {summary.get('vulnerabilities_found', 'N/A')}
- **Critical Issues:** {summary.get('critical_issues', 'N/A')}
- **High-Risk Issues:** {summary.get('high_risk_issues', 'N/A')}
- **Medium-Risk Issues:** {summary.get('medium_risk_issues', 'N/A')}
- **Low-Risk Issues:** {summary.get('low_risk_issues', 'N/A')}

## Risk Assessment

Based on the vulnerability assessment, the overall security posture is evaluated as follows:

"""
        
        # Add risk level assessment
        critical_count = summary.get('critical_issues', 0)
        if isinstance(critical_count, int) and critical_count > 0:
            content += "**🔴 HIGH RISK** - Critical vulnerabilities require immediate attention.\n\n"
        elif summary.get('vulnerabilities_found', 0) > 5:
            content += "**🟡 MEDIUM RISK** - Multiple vulnerabilities identified that should be addressed.\n\n"
        else:
            content += "**🟢 LOW RISK** - Few or no significant vulnerabilities identified.\n\n"
        
        # Add detailed findings
        content += """## Detailed Findings

### Critical Vulnerabilities

The following critical vulnerabilities require immediate remediation:

1. **SQL Injection Vulnerabilities**
   - **Impact:** High - Could lead to data breach
   - **Affected Systems:** Web applications
   - **Recommendation:** Implement parameterized queries

2. **Unpatched Software Components**
   - **Impact:** High - Known exploits available
   - **Affected Systems:** Various system components
   - **Recommendation:** Apply security updates immediately

### High-Risk Vulnerabilities

1. **Cross-Site Scripting (XSS)**
   - **Impact:** Medium-High - User session compromise
   - **Affected Systems:** Web applications
   - **Recommendation:** Implement input validation and CSP

2. **Weak Authentication Mechanisms**
   - **Impact:** Medium-High - Unauthorized access
   - **Affected Systems:** Authentication systems
   - **Recommendation:** Implement multi-factor authentication

"""
        
        if include_recommendations:
            content += self._add_vulnerability_recommendations()
        
        if include_charts:
            content += self._add_chart_placeholders('vulnerability')
        
        return content
    
    def _network_security_template(self, data, include_charts, include_recommendations):
        """
        Generate network security report
        """
        content = f"""# {data.get('title', 'Network Security Assessment Report')}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Report Type:** Network Security Assessment  

## Executive Summary

This report presents the findings from a comprehensive network security assessment, including port scans, service enumeration, and security configuration analysis.

### Assessment Scope

"""
        
        summary = data.get('summary', {})
        
        content += f"""- **Network Ranges Scanned:** {summary.get('network_ranges', 'Various')}
- **Total Hosts Discovered:** {summary.get('total_hosts', 'N/A')}
- **Active Services Identified:** {summary.get('active_services', 'N/A')}
- **Security Issues Found:** {summary.get('security_issues', 'N/A')}

## Network Discovery Results

### Host Discovery

The following active hosts were identified during the network scan:

| IP Address | Hostname | OS Detection | Open Ports | Risk Level |
|------------|----------|--------------|------------|------------|
| 192.168.1.1 | router.local | Unknown | 80, 443, 22 | Low |
| 192.168.1.10 | server.local | Linux | 22, 80, 443, 3306 | Medium |
| 192.168.1.20 | workstation.local | Windows | 135, 139, 445 | Medium |

### Port Scan Results

#### High-Risk Open Ports

The following potentially risky services were identified:

1. **FTP (Port 21)** - Unencrypted file transfer protocol
   - **Hosts:** 2 hosts
   - **Risk:** Medium - Credentials transmitted in plaintext
   - **Recommendation:** Migrate to SFTP or FTPS

2. **Telnet (Port 23)** - Unencrypted remote access
   - **Hosts:** 1 host
   - **Risk:** High - All traffic unencrypted
   - **Recommendation:** Replace with SSH immediately

3. **Database Services (Ports 3306, 1433, 5432)**
   - **Hosts:** 3 hosts
   - **Risk:** High - Direct database access
   - **Recommendation:** Restrict access to application servers only

### Service Enumeration

Detailed service analysis revealed:

- **Web Services:** 5 HTTP/HTTPS services identified
- **SSH Services:** 8 SSH services (version analysis recommended)
- **Database Services:** 3 database services exposed
- **File Sharing:** 2 SMB/CIFS services detected

"""
        
        if include_recommendations:
            content += self._add_network_recommendations()
        
        if include_charts:
            content += self._add_chart_placeholders('network')
        
        return content
    
    def _comprehensive_template(self, data, include_charts, include_recommendations):
        """
        Generate comprehensive security report
        """
        content = f"""# {data.get('title', 'Comprehensive Security Assessment Report')}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Report Type:** Comprehensive Security Assessment  

## Executive Summary

This comprehensive security assessment provides a holistic view of the organization's security posture, covering network security, application security, infrastructure security, and security policies.

### Overall Security Posture

"""
        
        summary = data.get('summary', {})
        
        content += f"""- **Total Assets Assessed:** {summary.get('total_assets', 'N/A')}
- **Security Controls Evaluated:** {summary.get('controls_evaluated', 'N/A')}
- **Critical Findings:** {summary.get('critical_issues', 'N/A')}
- **Total Recommendations:** {summary.get('recommendations', 'N/A')}

### Risk Summary

| Risk Level | Count | Percentage |
|------------|-------|------------|
| Critical | {summary.get('critical_issues', 0)} | {self._calculate_percentage(summary.get('critical_issues', 0), summary.get('total_findings', 1))}% |
| High | {summary.get('high_issues', 0)} | {self._calculate_percentage(summary.get('high_issues', 0), summary.get('total_findings', 1))}% |
| Medium | {summary.get('medium_issues', 0)} | {self._calculate_percentage(summary.get('medium_issues', 0), summary.get('total_findings', 1))}% |
| Low | {summary.get('low_issues', 0)} | {self._calculate_percentage(summary.get('low_issues', 0), summary.get('total_findings', 1))}% |

## Assessment Methodology

The comprehensive assessment was conducted using industry-standard methodologies including:

- **OWASP Testing Guide** for web application security
- **NIST Cybersecurity Framework** for overall security posture
- **SANS Top 20 Critical Security Controls** for control effectiveness
- **PTES (Penetration Testing Execution Standard)** for network security testing

## Network Security Assessment

### Network Architecture Review

The network architecture assessment revealed:

1. **Network Segmentation**
   - **Status:** Partially Implemented
   - **Finding:** Critical assets not properly isolated
   - **Risk:** High - Lateral movement possible

2. **Firewall Configuration**
   - **Status:** Needs Improvement
   - **Finding:** Overly permissive rules identified
   - **Risk:** Medium - Unnecessary exposure

3. **Network Monitoring**
   - **Status:** Limited
   - **Finding:** Insufficient logging and monitoring
   - **Risk:** Medium - Limited incident detection capability

### Network Services Security

Key findings from network service analysis:

- **Secure Services:** 65% of services using secure protocols
- **Legacy Protocols:** 3 instances of unencrypted protocols detected
- **Service Hardening:** 40% of services require security hardening
- **Access Controls:** 80% of services have appropriate access controls

## Application Security Assessment

### Web Application Security

Web application testing identified the following:

1. **Input Validation Issues**
   - **Finding:** 3 applications lack proper input validation
   - **Risk:** High - SQL injection and XSS vulnerabilities
   - **Affected Apps:** Customer portal, Admin interface, API endpoints

2. **Authentication and Authorization**
   - **Finding:** Weak password policies in 2 applications
   - **Risk:** Medium - Account compromise risk
   - **Recommendation:** Implement MFA and stronger password requirements

3. **Session Management**
   - **Finding:** Session fixation vulnerabilities in 1 application
   - **Risk:** Medium - Session hijacking possible
   - **Recommendation:** Implement secure session handling

### API Security

API security assessment results:

- **Authentication:** 2 APIs lack proper authentication
- **Rate Limiting:** 60% of APIs missing rate limiting
- **Input Validation:** 3 APIs vulnerable to injection attacks
- **Documentation:** 40% of APIs lack security documentation

## Infrastructure Security

### Server Security

Server hardening assessment:

1. **Operating System Security**
   - **Patching Status:** 85% of systems up to date
   - **Unnecessary Services:** 12 unnecessary services identified
   - **User Account Management:** 3 inactive accounts found

2. **Database Security**
   - **Default Credentials:** 1 database using default credentials
   - **Encryption:** 2 databases lack encryption at rest
   - **Access Controls:** Database permissions need review

### Cloud Security (if applicable)

Cloud infrastructure assessment findings:

- **IAM Configuration:** Overprivileged accounts identified
- **Storage Security:** 2 storage buckets publicly accessible
- **Network Security:** Security groups need tightening
- **Monitoring:** Cloud security monitoring partially implemented

## Security Controls Assessment

### Technical Controls

| Control Category | Implementation Status | Effectiveness | Priority |
|------------------|----------------------|---------------|----------|
| Access Control | Partially Implemented | Medium | High |
| Encryption | Needs Improvement | Low | Critical |
| Logging & Monitoring | Limited | Low | High |
| Vulnerability Management | Good | High | Medium |
| Incident Response | Partially Implemented | Medium | High |

### Administrative Controls

- **Security Policies:** 70% complete, need updates
- **Security Training:** Annual training implemented
- **Risk Management:** Process exists but needs enhancement
- **Vendor Management:** Security assessment process lacking

### Physical Controls

- **Access Controls:** Card-based access system in place
- **Monitoring:** CCTV coverage adequate
- **Environmental:** Fire suppression and climate control adequate

"""
        
        if include_recommendations:
            content += self._add_comprehensive_recommendations()
        
        if include_charts:
            content += self._add_chart_placeholders('comprehensive')
        
        content += self._add_conclusion()
        
        return content
    
    def _add_vulnerability_recommendations(self):
        """
        Add vulnerability-specific recommendations
        """
        return """
## Recommendations

### Immediate Actions (Critical Priority)

1. **Patch Critical Vulnerabilities**
   - Apply all available security patches
   - Prioritize internet-facing systems
   - Timeline: Within 72 hours

2. **Fix SQL Injection Vulnerabilities**
   - Implement parameterized queries
   - Review all database interactions
   - Timeline: Within 1 week

3. **Address Authentication Weaknesses**
   - Implement multi-factor authentication
   - Enforce strong password policies
   - Timeline: Within 2 weeks

### Short-term Actions (High Priority)

1. **Implement Web Application Firewall (WAF)**
   - Deploy WAF for all web applications
   - Configure appropriate rule sets
   - Timeline: Within 1 month

2. **Security Code Review**
   - Conduct thorough code review
   - Implement secure coding practices
   - Timeline: Within 6 weeks

### Long-term Actions (Medium Priority)

1. **Security Awareness Training**
   - Implement regular security training
   - Focus on secure development practices
   - Timeline: Within 3 months

2. **Vulnerability Management Program**
   - Establish regular vulnerability scanning
   - Implement patch management process
   - Timeline: Within 6 months

"""
    
    def _add_network_recommendations(self):
        """
        Add network security recommendations
        """
        return """
## Recommendations

### Immediate Actions

1. **Disable Insecure Protocols**
   - Disable Telnet and migrate to SSH
   - Replace FTP with SFTP/FTPS
   - Timeline: Within 1 week

2. **Implement Network Segmentation**
   - Isolate critical systems
   - Implement VLANs for different security zones
   - Timeline: Within 2 weeks

3. **Restrict Database Access**
   - Block direct database access from internet
   - Implement database firewalls
   - Timeline: Within 72 hours

### Short-term Actions

1. **Deploy Network Monitoring**
   - Implement SIEM solution
   - Configure intrusion detection
   - Timeline: Within 1 month

2. **Harden Network Services**
   - Update service configurations
   - Disable unnecessary services
   - Timeline: Within 2 weeks

### Long-term Actions

1. **Implement Zero Trust Architecture**
   - Plan migration to zero trust model
   - Implement micro-segmentation
   - Timeline: Within 6 months

2. **Regular Security Assessments**
   - Schedule quarterly network scans
   - Implement continuous monitoring
   - Timeline: Ongoing

"""
    
    def _add_comprehensive_recommendations(self):
        """
        Add comprehensive security recommendations
        """
        return """
## Strategic Recommendations

### Immediate Actions (0-30 days)

1. **Critical Vulnerability Remediation**
   - Address all critical and high-risk vulnerabilities
   - Focus on internet-facing systems first
   - Implement emergency patches where necessary

2. **Access Control Enhancement**
   - Review and update user access privileges
   - Implement principle of least privilege
   - Remove unnecessary user accounts

3. **Security Monitoring Enhancement**
   - Deploy security information and event management (SIEM)
   - Configure real-time alerting for critical events
   - Establish 24/7 security monitoring capability

### Short-term Actions (30-90 days)

1. **Security Architecture Review**
   - Conduct comprehensive architecture review
   - Implement network segmentation improvements
   - Deploy additional security controls

2. **Application Security Enhancement**
   - Implement secure development lifecycle (SDLC)
   - Deploy web application firewalls
   - Conduct security code reviews

3. **Incident Response Capability**
   - Develop comprehensive incident response plan
   - Establish incident response team
   - Conduct incident response exercises

### Long-term Actions (90+ days)

1. **Security Program Maturation**
   - Implement comprehensive security governance
   - Establish security metrics and KPIs
   - Regular security program assessments

2. **Advanced Security Controls**
   - Deploy advanced threat detection capabilities
   - Implement security orchestration and automation
   - Establish threat intelligence program

3. **Continuous Improvement**
   - Implement continuous security monitoring
   - Regular security assessments and penetration testing
   - Security awareness and training programs

## Implementation Roadmap

### Phase 1: Foundation (Months 1-3)
- Critical vulnerability remediation
- Basic security controls implementation
- Incident response capability establishment

### Phase 2: Enhancement (Months 4-6)
- Advanced security controls deployment
- Security monitoring and detection enhancement
- Security program governance implementation

### Phase 3: Optimization (Months 7-12)
- Continuous improvement processes
- Advanced threat detection capabilities
- Security automation and orchestration

## Budget Considerations

### High Priority Investments
- Security monitoring and SIEM solution: $50,000-100,000
- Vulnerability management platform: $25,000-50,000
- Security training and awareness: $15,000-30,000

### Medium Priority Investments
- Advanced threat detection: $75,000-150,000
- Security automation tools: $40,000-80,000
- Penetration testing services: $20,000-40,000

### Long-term Investments
- Security program maturation: $100,000-200,000
- Advanced security architecture: $150,000-300,000
- Continuous monitoring capabilities: $75,000-150,000

"""
    
    def _add_chart_placeholders(self, report_type):
        """
        Add chart placeholders for different report types
        """
        if report_type == 'vulnerability':
            return """
## Visual Analysis

### Vulnerability Distribution by Severity
[Chart: Pie chart showing distribution of vulnerabilities by severity level]

### Vulnerability Trends Over Time
[Chart: Line graph showing vulnerability discovery trends]

### Top Vulnerable Systems
[Chart: Bar chart showing systems with most vulnerabilities]

"""
        elif report_type == 'network':
            return """
## Visual Analysis

### Port Distribution
[Chart: Bar chart showing most common open ports]

### Service Distribution
[Chart: Pie chart showing service types distribution]

### Risk Level by Host
[Chart: Scatter plot showing risk levels across hosts]

"""
        else:  # comprehensive
            return """
## Visual Analysis

### Overall Risk Distribution
[Chart: Pie chart showing risk distribution across all categories]

### Security Control Effectiveness
[Chart: Radar chart showing security control maturity levels]

### Threat Landscape Overview
[Chart: Heat map showing threat categories and likelihood]

### Security Investment ROI
[Chart: Bar chart showing recommended security investments]

"""
    
    def _add_conclusion(self):
        """
        Add conclusion section
        """
        return """
## Conclusion

This comprehensive security assessment has identified several areas requiring immediate attention and long-term strategic planning. The organization's current security posture shows both strengths and areas for improvement.

### Key Strengths
- Established security awareness
- Basic security controls in place
- Commitment to security improvement

### Areas for Improvement
- Vulnerability management processes
- Network security architecture
- Security monitoring capabilities
- Incident response preparedness

### Next Steps

1. **Prioritize Critical Issues**: Address all critical and high-risk findings immediately
2. **Develop Implementation Plan**: Create detailed timeline for recommended actions
3. **Allocate Resources**: Ensure adequate budget and personnel for security improvements
4. **Regular Assessments**: Establish ongoing security assessment schedule
5. **Continuous Monitoring**: Implement continuous security monitoring capabilities

The successful implementation of these recommendations will significantly enhance the organization's security posture and reduce overall risk exposure.

---

**Report Prepared By:** CyberSec Analyst Tool  
**Contact Information:** security@organization.com  
**Report Version:** 1.0  

"""
    
    def _calculate_percentage(self, value, total):
        """
        Calculate percentage safely
        """
        if total == 0:
            return 0
        return round((value / total) * 100, 1)
    
    def export_report(self, report, format='markdown'):
        """
        Export report in different formats
        """
        if format == 'markdown':
            return report.get('content', '')
        elif format == 'json':
            return json.dumps(report, indent=2, default=str)
        elif format == 'html':
            # Convert markdown to HTML (simplified)
            html_content = report.get('content', '').replace('\n## ', '\n<h2>').replace('\n### ', '\n<h3>')
            html_content = html_content.replace('\n# ', '\n<h1>')
            html_content = html_content.replace('\n', '<br>\n')
            
            return f"""<!DOCTYPE html>
<html>
<head>
    <title>{report.get('title', 'Security Report')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; }}
        h3 {{ color: #999; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>"""
        else:
            return report.get('content', '')
