"""
Compliance and Risk Assessment Framework
Support for NIST, ISO 27001, PCI DSS, SOX, GDPR and other compliance frameworks
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import re
from collections import defaultdict, Counter

class ComplianceFramework(Enum):
    NIST_CSF = "NIST_CSF"
    ISO_27001 = "ISO_27001"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    CIS_CONTROLS = "CIS_CONTROLS"

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"

class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING_REVIEW = "PENDING_REVIEW"

@dataclass
class ControlRequirement:
    control_id: str
    title: str
    description: str
    framework: ComplianceFramework
    category: str
    subcategory: str
    implementation_guidance: List[str]
    evidence_requirements: List[str]
    testing_procedures: List[str]
    risk_level: RiskLevel
    
@dataclass
class ComplianceAssessment:
    assessment_id: str
    framework: ComplianceFramework
    organization: str
    assessed_by: str
    assessment_date: datetime
    controls_assessed: List[str]
    findings: List[Dict]
    overall_score: float
    compliance_status: ComplianceStatus
    recommendations: List[str]
    remediation_plan: List[Dict]

class ComplianceManager:
    def __init__(self):
        self.frameworks = self._initialize_frameworks()
        self.assessments = {}
        self.risk_matrix = self._initialize_risk_matrix()
        self.evidence_repository = {}
        
    def _initialize_frameworks(self) -> Dict:
        """Initialize compliance framework definitions"""
        return {
            ComplianceFramework.NIST_CSF: self._load_nist_csf(),
            ComplianceFramework.ISO_27001: self._load_iso_27001(),
            ComplianceFramework.PCI_DSS: self._load_pci_dss(),
            ComplianceFramework.SOX: self._load_sox(),
            ComplianceFramework.GDPR: self._load_gdpr(),
            ComplianceFramework.HIPAA: self._load_hipaa(),
            ComplianceFramework.SOC2: self._load_soc2(),
            ComplianceFramework.CIS_CONTROLS: self._load_cis_controls()
        }
    
    def _load_nist_csf(self) -> Dict:
        """Load NIST Cybersecurity Framework controls"""
        return {
            'framework_name': 'NIST Cybersecurity Framework',
            'version': '1.1',
            'categories': {
                'IDENTIFY': {
                    'ID.AM': {
                        'name': 'Asset Management',
                        'controls': {
                            'ID.AM-1': ControlRequirement(
                                control_id='ID.AM-1',
                                title='Physical devices and systems within the organization are inventoried',
                                description='Maintain an accurate inventory of all physical devices and systems',
                                framework=ComplianceFramework.NIST_CSF,
                                category='IDENTIFY',
                                subcategory='Asset Management',
                                implementation_guidance=[
                                    'Implement automated asset discovery tools',
                                    'Maintain centralized asset inventory database',
                                    'Regular physical asset audits',
                                    'Document asset ownership and classification'
                                ],
                                evidence_requirements=[
                                    'Asset inventory reports',
                                    'Asset discovery tool outputs',
                                    'Physical audit reports',
                                    'Asset classification documents'
                                ],
                                testing_procedures=[
                                    'Review asset inventory completeness',
                                    'Verify asset discovery tool configuration',
                                    'Test asset tracking processes',
                                    'Validate asset classification accuracy'
                                ],
                                risk_level=RiskLevel.HIGH
                            ),
                            'ID.AM-2': ControlRequirement(
                                control_id='ID.AM-2',
                                title='Software platforms and applications within the organization are inventoried',
                                description='Maintain an accurate inventory of software platforms and applications',
                                framework=ComplianceFramework.NIST_CSF,
                                category='IDENTIFY',
                                subcategory='Asset Management',
                                implementation_guidance=[
                                    'Deploy software asset management tools',
                                    'Track licensed and unlicensed software',
                                    'Monitor software installations and removals',
                                    'Maintain software version control'
                                ],
                                evidence_requirements=[
                                    'Software inventory reports',
                                    'License compliance reports',
                                    'Software installation logs',
                                    'Version control documentation'
                                ],
                                testing_procedures=[
                                    'Verify software inventory accuracy',
                                    'Test software discovery tools',
                                    'Review license compliance',
                                    'Validate version tracking'
                                ],
                                risk_level=RiskLevel.MEDIUM
                            )
                        }
                    },
                    'ID.GV': {
                        'name': 'Governance',
                        'controls': {
                            'ID.GV-1': ControlRequirement(
                                control_id='ID.GV-1',
                                title='Organizational cybersecurity policy is established and communicated',
                                description='Establish and communicate organizational cybersecurity policy',
                                framework=ComplianceFramework.NIST_CSF,
                                category='IDENTIFY',
                                subcategory='Governance',
                                implementation_guidance=[
                                    'Develop comprehensive cybersecurity policy',
                                    'Ensure executive sponsorship and approval',
                                    'Communicate policy to all stakeholders',
                                    'Implement regular policy reviews and updates'
                                ],
                                evidence_requirements=[
                                    'Approved cybersecurity policy document',
                                    'Policy communication records',
                                    'Training completion records',
                                    'Policy review and update documentation'
                                ],
                                testing_procedures=[
                                    'Review policy comprehensiveness',
                                    'Verify executive approval',
                                    'Test policy communication effectiveness',
                                    'Validate policy review processes'
                                ],
                                risk_level=RiskLevel.HIGH
                            )
                        }
                    }
                },
                'PROTECT': {
                    'PR.AC': {
                        'name': 'Identity Management and Access Control',
                        'controls': {
                            'PR.AC-1': ControlRequirement(
                                control_id='PR.AC-1',
                                title='Identities and credentials are issued, managed, verified, revoked, and audited',
                                description='Comprehensive identity and credential management',
                                framework=ComplianceFramework.NIST_CSF,
                                category='PROTECT',
                                subcategory='Identity Management and Access Control',
                                implementation_guidance=[
                                    'Implement identity management system',
                                    'Define credential lifecycle processes',
                                    'Establish regular access reviews',
                                    'Implement automated provisioning/deprovisioning'
                                ],
                                evidence_requirements=[
                                    'Identity management system documentation',
                                    'Access review reports',
                                    'Provisioning/deprovisioning logs',
                                    'Credential audit reports'
                                ],
                                testing_procedures=[
                                    'Test identity management processes',
                                    'Verify access review procedures',
                                    'Validate automated provisioning',
                                    'Review credential audit trails'
                                ],
                                risk_level=RiskLevel.CRITICAL
                            )
                        }
                    }
                },
                'DETECT': {
                    'DE.AE': {
                        'name': 'Anomalies and Events',
                        'controls': {
                            'DE.AE-1': ControlRequirement(
                                control_id='DE.AE-1',
                                title='A baseline of network operations and expected data flows is established',
                                description='Establish network baseline and monitor for deviations',
                                framework=ComplianceFramework.NIST_CSF,
                                category='DETECT',
                                subcategory='Anomalies and Events',
                                implementation_guidance=[
                                    'Deploy network monitoring tools',
                                    'Establish traffic baselines',
                                    'Implement anomaly detection',
                                    'Document normal network patterns'
                                ],
                                evidence_requirements=[
                                    'Network baseline documentation',
                                    'Traffic monitoring reports',
                                    'Anomaly detection alerts',
                                    'Network topology diagrams'
                                ],
                                testing_procedures=[
                                    'Verify baseline accuracy',
                                    'Test anomaly detection capabilities',
                                    'Review monitoring coverage',
                                    'Validate alert mechanisms'
                                ],
                                risk_level=RiskLevel.HIGH
                            )
                        }
                    }
                },
                'RESPOND': {
                    'RS.RP': {
                        'name': 'Response Planning',
                        'controls': {
                            'RS.RP-1': ControlRequirement(
                                control_id='RS.RP-1',
                                title='Response plan is executed during or after an incident',
                                description='Execute incident response plan effectively',
                                framework=ComplianceFramework.NIST_CSF,
                                category='RESPOND',
                                subcategory='Response Planning',
                                implementation_guidance=[
                                    'Develop incident response procedures',
                                    'Define roles and responsibilities',
                                    'Establish communication protocols',
                                    'Implement response automation'
                                ],
                                evidence_requirements=[
                                    'Incident response plan document',
                                    'Response team assignments',
                                    'Communication procedures',
                                    'Incident response logs'
                                ],
                                testing_procedures=[
                                    'Conduct tabletop exercises',
                                    'Test response procedures',
                                    'Verify communication protocols',
                                    'Validate response automation'
                                ],
                                risk_level=RiskLevel.CRITICAL
                            )
                        }
                    }
                },
                'RECOVER': {
                    'RC.RP': {
                        'name': 'Recovery Planning',
                        'controls': {
                            'RC.RP-1': ControlRequirement(
                                control_id='RC.RP-1',
                                title='Recovery plan is executed during or after a cybersecurity incident',
                                description='Execute recovery procedures effectively',
                                framework=ComplianceFramework.NIST_CSF,
                                category='RECOVER',
                                subcategory='Recovery Planning',
                                implementation_guidance=[
                                    'Develop recovery procedures',
                                    'Define recovery priorities',
                                    'Establish backup and restore processes',
                                    'Implement business continuity measures'
                                ],
                                evidence_requirements=[
                                    'Recovery plan documentation',
                                    'Backup verification reports',
                                    'Recovery test results',
                                    'Business continuity plans'
                                ],
                                testing_procedures=[
                                    'Conduct recovery exercises',
                                    'Test backup and restore',
                                    'Verify recovery timeframes',
                                    'Validate business continuity'
                                ],
                                risk_level=RiskLevel.HIGH
                            )
                        }
                    }
                }
            }
        }
    
    def _load_iso_27001(self) -> Dict:
        """Load ISO 27001 controls"""
        return {
            'framework_name': 'ISO/IEC 27001:2013',
            'version': '2013',
            'domains': {
                'A.5': {
                    'name': 'Information Security Policies',
                    'controls': {
                        'A.5.1.1': ControlRequirement(
                            control_id='A.5.1.1',
                            title='Policies for information security',
                            description='A set of policies for information security shall be defined, approved by management, published and communicated to employees and relevant external parties',
                            framework=ComplianceFramework.ISO_27001,
                            category='Information Security Policies',
                            subcategory='Management direction for information security',
                            implementation_guidance=[
                                'Define comprehensive information security policies',
                                'Obtain management approval and endorsement',
                                'Publish policies to all relevant parties',
                                'Implement regular policy review and update processes'
                            ],
                            evidence_requirements=[
                                'Approved information security policy documents',
                                'Management approval documentation',
                                'Policy distribution records',
                                'Policy review and update logs'
                            ],
                            testing_procedures=[
                                'Review policy completeness and adequacy',
                                'Verify management approval process',
                                'Test policy communication effectiveness',
                                'Validate policy review procedures'
                            ],
                            risk_level=RiskLevel.HIGH
                        )
                    }
                },
                'A.9': {
                    'name': 'Access Control',
                    'controls': {
                        'A.9.1.1': ControlRequirement(
                            control_id='A.9.1.1',
                            title='Access control policy',
                            description='An access control policy shall be established, documented and reviewed based on business and information security requirements',
                            framework=ComplianceFramework.ISO_27001,
                            category='Access Control',
                            subcategory='Business requirements of access control',
                            implementation_guidance=[
                                'Develop access control policy based on business requirements',
                                'Document access control procedures and standards',
                                'Implement regular policy reviews',
                                'Align with information security requirements'
                            ],
                            evidence_requirements=[
                                'Access control policy document',
                                'Policy review records',
                                'Business requirement analysis',
                                'Security requirement documentation'
                            ],
                            testing_procedures=[
                                'Review access control policy adequacy',
                                'Test policy implementation',
                                'Verify regular review processes',
                                'Validate alignment with requirements'
                            ],
                            risk_level=RiskLevel.CRITICAL
                        )
                    }
                }
            }
        }
    
    def _load_pci_dss(self) -> Dict:
        """Load PCI DSS requirements"""
        return {
            'framework_name': 'Payment Card Industry Data Security Standard',
            'version': '4.0',
            'requirements': {
                'Req1': {
                    'name': 'Install and maintain network security controls',
                    'controls': {
                        '1.1.1': ControlRequirement(
                            control_id='1.1.1',
                            title='Processes and mechanisms for implementing and maintaining network security controls',
                            description='All security policies and operational procedures that are identified in Requirement 1 are documented, kept up to date, and in use',
                            framework=ComplianceFramework.PCI_DSS,
                            category='Network Security Controls',
                            subcategory='Firewall Configuration',
                            implementation_guidance=[
                                'Document all network security policies',
                                'Maintain current operational procedures',
                                'Ensure procedures are actively used',
                                'Implement regular review and update processes'
                            ],
                            evidence_requirements=[
                                'Network security policy documents',
                                'Operational procedure documentation',
                                'Usage verification records',
                                'Review and update logs'
                            ],
                            testing_procedures=[
                                'Review documentation completeness',
                                'Verify procedure currency',
                                'Test procedure implementation',
                                'Validate review processes'
                            ],
                            risk_level=RiskLevel.HIGH
                        )
                    }
                }
            }
        }
    
    def _load_sox(self) -> Dict:
        """Load SOX (Sarbanes-Oxley) controls"""
        return {
            'framework_name': 'Sarbanes-Oxley Act',
            'version': '2002',
            'sections': {
                'Section404': {
                    'name': 'Management Assessment of Internal Controls',
                    'controls': {
                        'ITGC-001': ControlRequirement(
                            control_id='ITGC-001',
                            title='IT General Controls - Access Management',
                            description='Controls over access to applications and data that support financial reporting',
                            framework=ComplianceFramework.SOX,
                            category='IT General Controls',
                            subcategory='Access Management',
                            implementation_guidance=[
                                'Implement role-based access controls',
                                'Establish access review procedures',
                                'Document access request and approval processes',
                                'Maintain audit trails for access changes'
                            ],
                            evidence_requirements=[
                                'Access control matrix documentation',
                                'Access review reports',
                                'Access request and approval records',
                                'Audit trail reports'
                            ],
                            testing_procedures=[
                                'Test access control effectiveness',
                                'Review access provisioning processes',
                                'Verify access review completeness',
                                'Validate audit trail accuracy'
                            ],
                            risk_level=RiskLevel.CRITICAL
                        )
                    }
                }
            }
        }
    
    def _load_gdpr(self) -> Dict:
        """Load GDPR requirements"""
        return {
            'framework_name': 'General Data Protection Regulation',
            'version': '2018',
            'articles': {
                'Article32': {
                    'name': 'Security of processing',
                    'controls': {
                        'GDPR-32.1': ControlRequirement(
                            control_id='GDPR-32.1',
                            title='Appropriate technical and organisational measures',
                            description='Taking into account the state of the art, the costs of implementation and the nature, scope, context and purposes of processing',
                            framework=ComplianceFramework.GDPR,
                            category='Security of Processing',
                            subcategory='Technical and Organisational Measures',
                            implementation_guidance=[
                                'Implement encryption of personal data',
                                'Ensure ongoing confidentiality and integrity',
                                'Establish availability and resilience measures',
                                'Implement regular security testing'
                            ],
                            evidence_requirements=[
                                'Encryption implementation documentation',
                                'Security measure documentation',
                                'Availability and resilience reports',
                                'Security testing results'
                            ],
                            testing_procedures=[
                                'Test encryption effectiveness',
                                'Verify confidentiality measures',
                                'Test availability and resilience',
                                'Review security testing procedures'
                            ],
                            risk_level=RiskLevel.HIGH
                        )
                    }
                }
            }
        }
    
    def _load_hipaa(self) -> Dict:
        """Load HIPAA Security Rule requirements"""
        return {
            'framework_name': 'Health Insurance Portability and Accountability Act',
            'version': 'Security Rule',
            'safeguards': {
                'Administrative': {
                    'name': 'Administrative Safeguards',
                    'controls': {
                        '164.308(a)(1)': ControlRequirement(
                            control_id='164.308(a)(1)',
                            title='Security Officer',
                            description='Assign security responsibilities to an individual',
                            framework=ComplianceFramework.HIPAA,
                            category='Administrative Safeguards',
                            subcategory='Security Management Process',
                            implementation_guidance=[
                                'Designate a security officer',
                                'Define security responsibilities',
                                'Establish security management processes',
                                'Implement accountability measures'
                            ],
                            evidence_requirements=[
                                'Security officer designation documentation',
                                'Job description and responsibilities',
                                'Security management procedures',
                                'Accountability measures documentation'
                            ],
                            testing_procedures=[
                                'Verify security officer designation',
                                'Review security responsibilities',
                                'Test security management processes',
                                'Validate accountability measures'
                            ],
                            risk_level=RiskLevel.HIGH
                        )
                    }
                }
            }
        }
    
    def _load_soc2(self) -> Dict:
        """Load SOC 2 Trust Service Criteria"""
        return {
            'framework_name': 'SOC 2 Trust Service Criteria',
            'version': '2017',
            'criteria': {
                'Security': {
                    'name': 'Security',
                    'controls': {
                        'CC6.1': ControlRequirement(
                            control_id='CC6.1',
                            title='Logical and physical access controls',
                            description='The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries',
                            framework=ComplianceFramework.SOC2,
                            category='Security',
                            subcategory='Access Controls',
                            implementation_guidance=[
                                'Implement logical access controls',
                                'Establish physical access controls',
                                'Define access control policies',
                                'Monitor access control effectiveness'
                            ],
                            evidence_requirements=[
                                'Access control policy documentation',
                                'Logical access control implementation',
                                'Physical access control measures',
                                'Access monitoring reports'
                            ],
                            testing_procedures=[
                                'Test logical access controls',
                                'Review physical access controls',
                                'Verify access control policies',
                                'Validate monitoring procedures'
                            ],
                            risk_level=RiskLevel.HIGH
                        )
                    }
                }
            }
        }
    
    def _load_cis_controls(self) -> Dict:
        """Load CIS Critical Security Controls"""
        return {
            'framework_name': 'CIS Critical Security Controls',
            'version': '8.0',
            'controls': {
                'CIS1': {
                    'name': 'Inventory and Control of Enterprise Assets',
                    'controls': {
                        'CIS1.1': ControlRequirement(
                            control_id='CIS1.1',
                            title='Establish and Maintain Detailed Enterprise Asset Inventory',
                            description='Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets',
                            framework=ComplianceFramework.CIS_CONTROLS,
                            category='Basic',
                            subcategory='Asset Management',
                            implementation_guidance=[
                                'Deploy automated asset discovery tools',
                                'Maintain centralized asset database',
                                'Implement regular asset scans',
                                'Document asset attributes and ownership'
                            ],
                            evidence_requirements=[
                                'Asset inventory database',
                                'Automated discovery tool reports',
                                'Asset scan results',
                                'Asset ownership documentation'
                            ],
                            testing_procedures=[
                                'Verify asset inventory accuracy',
                                'Test automated discovery tools',
                                'Review asset scan coverage',
                                'Validate ownership documentation'
                            ],
                            risk_level=RiskLevel.HIGH
                        )
                    }
                }
            }
        }
    
    def _initialize_risk_matrix(self) -> Dict:
        """Initialize risk assessment matrix"""
        return {
            'likelihood': {
                'Very High': 5,
                'High': 4,
                'Medium': 3,
                'Low': 2,
                'Very Low': 1
            },
            'impact': {
                'Critical': 5,
                'High': 4,
                'Medium': 3,
                'Low': 2,
                'Very Low': 1
            },
            'risk_levels': {
                (5, 5): RiskLevel.CRITICAL,
                (5, 4): RiskLevel.CRITICAL,
                (4, 5): RiskLevel.CRITICAL,
                (5, 3): RiskLevel.HIGH,
                (4, 4): RiskLevel.HIGH,
                (3, 5): RiskLevel.HIGH,
                (4, 3): RiskLevel.MEDIUM,
                (3, 4): RiskLevel.MEDIUM,
                (3, 3): RiskLevel.MEDIUM,
                (2, 4): RiskLevel.MEDIUM,
                (4, 2): RiskLevel.MEDIUM,
                (2, 3): RiskLevel.LOW,
                (3, 2): RiskLevel.LOW,
                (2, 2): RiskLevel.LOW,
                (1, 3): RiskLevel.LOW,
                (3, 1): RiskLevel.LOW,
                (1, 2): RiskLevel.NEGLIGIBLE,
                (2, 1): RiskLevel.NEGLIGIBLE,
                (1, 1): RiskLevel.NEGLIGIBLE
            }
        }
    
    def conduct_compliance_assessment(self, framework: ComplianceFramework, 
                                    organization: str, assessor: str,
                                    controls_to_assess: Optional[List[str]] = None) -> str:
        """Conduct comprehensive compliance assessment"""
        assessment_id = hashlib.md5(f"{framework.value}_{organization}_{datetime.now()}".encode()).hexdigest()[:8]
        
        framework_controls = self.frameworks[framework]
        assessment_scope = controls_to_assess or self._get_all_control_ids(framework)
        
        findings = []
        overall_score = 0
        compliant_controls = 0
        total_controls = len(assessment_scope)
        
        for control_id in assessment_scope:
            control = self._find_control(framework, control_id)
            if control:
                finding = self._assess_control(control)
                findings.append(finding)
                
                if finding['status'] == ComplianceStatus.COMPLIANT:
                    compliant_controls += 1
                    overall_score += 100
                elif finding['status'] == ComplianceStatus.PARTIALLY_COMPLIANT:
                    compliant_controls += 0.5
                    overall_score += 50
        
        if total_controls > 0:
            overall_score = overall_score / total_controls
        
        # Determine overall compliance status
        if overall_score >= 95:
            compliance_status = ComplianceStatus.COMPLIANT
        elif overall_score >= 70:
            compliance_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            framework=framework,
            organization=organization,
            assessed_by=assessor,
            assessment_date=datetime.now(),
            controls_assessed=assessment_scope,
            findings=findings,
            overall_score=overall_score,
            compliance_status=compliance_status,
            recommendations=self._generate_compliance_recommendations(findings),
            remediation_plan=self._generate_remediation_plan(findings)
        )
        
        self.assessments[assessment_id] = assessment
        return assessment_id
    
    def _get_all_control_ids(self, framework: ComplianceFramework) -> List[str]:
        """Get all control IDs for a framework"""
        control_ids = []
        framework_data = self.frameworks[framework]
        
        if framework == ComplianceFramework.NIST_CSF:
            for category in framework_data['categories'].values():
                for subcategory in category.values():
                    if isinstance(subcategory, dict) and 'controls' in subcategory:
                        control_ids.extend(subcategory['controls'].keys())
        elif framework == ComplianceFramework.ISO_27001:
            for domain in framework_data['domains'].values():
                if 'controls' in domain:
                    control_ids.extend(domain['controls'].keys())
        # Add other framework parsing logic as needed
        
        return control_ids
    
    def _find_control(self, framework: ComplianceFramework, control_id: str) -> Optional[ControlRequirement]:
        """Find a specific control in a framework"""
        framework_data = self.frameworks[framework]
        
        if framework == ComplianceFramework.NIST_CSF:
            for category in framework_data['categories'].values():
                for subcategory in category.values():
                    if isinstance(subcategory, dict) and 'controls' in subcategory:
                        if control_id in subcategory['controls']:
                            return subcategory['controls'][control_id]
        
        # Add other framework search logic as needed
        return None
    
    def _assess_control(self, control: ControlRequirement) -> Dict:
        """Assess a specific control (simplified assessment)"""
        # In a real implementation, this would involve detailed testing
        # For demonstration purposes, we'll simulate assessment results
        
        # Simulated assessment logic
        compliance_score = 75  # Default score for demonstration
        
        if compliance_score >= 95:
            status = ComplianceStatus.COMPLIANT
            risk_level = RiskLevel.LOW
        elif compliance_score >= 70:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            risk_level = RiskLevel.MEDIUM
        else:
            status = ComplianceStatus.NON_COMPLIANT
            risk_level = RiskLevel.HIGH
        
        return {
            'control_id': control.control_id,
            'control_title': control.title,
            'status': status,
            'score': compliance_score,
            'risk_level': risk_level,
            'findings': [
                'Control implementation reviewed',
                'Evidence collection completed',
                'Testing procedures executed'
            ],
            'gaps': [
                'Documentation could be improved',
                'Regular reviews need enhancement'
            ] if status != ComplianceStatus.COMPLIANT else [],
            'evidence_collected': control.evidence_requirements[:2],  # Simulate partial evidence
            'recommendations': [
                'Enhance documentation',
                'Implement regular reviews',
                'Improve monitoring procedures'
            ] if status != ComplianceStatus.COMPLIANT else []
        }
    
    def _generate_compliance_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate compliance recommendations based on findings"""
        recommendations = []
        
        non_compliant_count = sum(1 for f in findings if f['status'] == ComplianceStatus.NON_COMPLIANT)
        partially_compliant_count = sum(1 for f in findings if f['status'] == ComplianceStatus.PARTIALLY_COMPLIANT)
        
        if non_compliant_count > 0:
            recommendations.extend([
                f'Address {non_compliant_count} non-compliant controls immediately',
                'Implement comprehensive remediation plan',
                'Establish control monitoring procedures',
                'Conduct regular compliance assessments'
            ])
        
        if partially_compliant_count > 0:
            recommendations.extend([
                f'Improve {partially_compliant_count} partially compliant controls',
                'Enhance documentation and evidence collection',
                'Implement additional control testing procedures'
            ])
        
        recommendations.extend([
            'Establish compliance management program',
            'Implement continuous monitoring',
            'Provide compliance training to staff',
            'Regular third-party compliance assessments'
        ])
        
        return recommendations
    
    def _generate_remediation_plan(self, findings: List[Dict]) -> List[Dict]:
        """Generate remediation plan for non-compliant controls"""
        remediation_plan = []
        
        for finding in findings:
            if finding['status'] != ComplianceStatus.COMPLIANT:
                remediation_plan.append({
                    'control_id': finding['control_id'],
                    'priority': 'High' if finding['status'] == ComplianceStatus.NON_COMPLIANT else 'Medium',
                    'remediation_actions': finding.get('recommendations', []),
                    'estimated_effort': 'Medium',
                    'target_completion': (datetime.now() + timedelta(days=30)).isoformat(),
                    'responsible_party': 'Security Team',
                    'success_criteria': f'Achieve compliance for {finding["control_id"]}'
                })
        
        return remediation_plan
    
    def perform_risk_assessment(self, assets: List[Dict], threats: List[Dict], 
                              vulnerabilities: List[Dict]) -> Dict:
        """Perform comprehensive risk assessment"""
        risk_assessment = {
            'assessment_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'timestamp': datetime.now().isoformat(),
            'assets_assessed': len(assets),
            'threats_identified': len(threats),
            'vulnerabilities_found': len(vulnerabilities),
            'risk_scenarios': [],
            'overall_risk_score': 0,
            'risk_distribution': Counter(),
            'recommendations': []
        }
        
        # Generate risk scenarios
        for asset in assets:
            for threat in threats:
                for vulnerability in vulnerabilities:
                    scenario = self._create_risk_scenario(asset, threat, vulnerability)
                    if scenario:
                        risk_assessment['risk_scenarios'].append(scenario)
        
        # Calculate overall risk score
        if risk_assessment['risk_scenarios']:
            total_risk = sum(scenario['risk_score'] for scenario in risk_assessment['risk_scenarios'])
            risk_assessment['overall_risk_score'] = total_risk / len(risk_assessment['risk_scenarios'])
        
        # Risk distribution
        for scenario in risk_assessment['risk_scenarios']:
            risk_assessment['risk_distribution'][scenario['risk_level'].value] += 1
        
        # Generate recommendations
        risk_assessment['recommendations'] = self._generate_risk_recommendations(risk_assessment)
        
        return risk_assessment
    
    def _create_risk_scenario(self, asset: Dict, threat: Dict, vulnerability: Dict) -> Optional[Dict]:
        """Create risk scenario from asset, threat, and vulnerability combination"""
        # Check if threat can exploit vulnerability in asset
        if not self._is_applicable_combination(asset, threat, vulnerability):
            return None
        
        # Calculate likelihood and impact
        likelihood = self._calculate_likelihood(threat, vulnerability)
        impact = self._calculate_impact(asset, threat)
        
        # Determine risk level
        risk_level = self.risk_matrix['risk_levels'].get((likelihood, impact), RiskLevel.MEDIUM)
        risk_score = likelihood * impact
        
        return {
            'scenario_id': hashlib.md5(f"{asset['name']}_{threat['name']}_{vulnerability['name']}".encode()).hexdigest()[:8],
            'asset': asset['name'],
            'threat': threat['name'],
            'vulnerability': vulnerability['name'],
            'likelihood': likelihood,
            'impact': impact,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'description': f"{threat['name']} exploiting {vulnerability['name']} in {asset['name']}",
            'potential_consequences': self._get_potential_consequences(asset, threat),
            'mitigation_strategies': self._get_mitigation_strategies(threat, vulnerability)
        }
    
    def _is_applicable_combination(self, asset: Dict, threat: Dict, vulnerability: Dict) -> bool:
        """Check if threat-vulnerability combination applies to asset"""
        # Simplified logic - in reality, this would be more sophisticated
        asset_type = asset.get('type', '').lower()
        threat_targets = threat.get('targets', [])
        vuln_affects = vulnerability.get('affects', [])
        
        return (asset_type in threat_targets or 
                any(target in asset_type for target in threat_targets) or
                asset_type in vuln_affects or
                any(affect in asset_type for affect in vuln_affects))
    
    def _calculate_likelihood(self, threat: Dict, vulnerability: Dict) -> int:
        """Calculate likelihood of threat exploiting vulnerability"""
        threat_likelihood = threat.get('likelihood', 3)  # Default to medium
        vuln_exploitability = vulnerability.get('exploitability', 3)  # Default to medium
        
        # Combine threat likelihood and vulnerability exploitability
        combined_likelihood = (threat_likelihood + vuln_exploitability) / 2
        return min(5, max(1, round(combined_likelihood)))
    
    def _calculate_impact(self, asset: Dict, threat: Dict) -> int:
        """Calculate impact of threat on asset"""
        asset_criticality = asset.get('criticality', 3)  # Default to medium
        threat_impact = threat.get('impact', 3)  # Default to medium
        
        # Combine asset criticality and threat impact
        combined_impact = max(asset_criticality, threat_impact)
        return min(5, max(1, combined_impact))
    
    def _get_potential_consequences(self, asset: Dict, threat: Dict) -> List[str]:
        """Get potential consequences of threat affecting asset"""
        consequences = []
        
        asset_type = asset.get('type', '').lower()
        threat_type = threat.get('type', '').lower()
        
        if 'data' in asset_type:
            consequences.extend(['Data breach', 'Privacy violation', 'Regulatory penalties'])
        
        if 'financial' in asset_type:
            consequences.extend(['Financial loss', 'Regulatory fines', 'Audit findings'])
        
        if 'system' in asset_type:
            consequences.extend(['Service disruption', 'Operational impact', 'Recovery costs'])
        
        if 'malware' in threat_type:
            consequences.extend(['System compromise', 'Data corruption', 'Lateral movement'])
        
        return consequences[:5]  # Limit to top 5
    
    def _get_mitigation_strategies(self, threat: Dict, vulnerability: Dict) -> List[str]:
        """Get mitigation strategies for threat-vulnerability combination"""
        strategies = []
        
        threat_type = threat.get('type', '').lower()
        vuln_type = vulnerability.get('type', '').lower()
        
        if 'malware' in threat_type:
            strategies.extend(['Deploy anti-malware solutions', 'Implement email filtering', 'User awareness training'])
        
        if 'phishing' in threat_type:
            strategies.extend(['Email security controls', 'User training', 'Multi-factor authentication'])
        
        if 'access' in vuln_type:
            strategies.extend(['Access controls', 'Privilege management', 'Regular access reviews'])
        
        if 'patch' in vuln_type:
            strategies.extend(['Patch management', 'Vulnerability scanning', 'Security testing'])
        
        return strategies[:5]  # Limit to top 5
    
    def _generate_risk_recommendations(self, risk_assessment: Dict) -> List[str]:
        """Generate risk management recommendations"""
        recommendations = []
        
        risk_distribution = risk_assessment['risk_distribution']
        overall_risk_score = risk_assessment['overall_risk_score']
        
        if risk_distribution.get('CRITICAL', 0) > 0:
            recommendations.extend([
                'Immediate action required for critical risks',
                'Implement emergency risk mitigation measures',
                'Consider business continuity activation',
                'Engage executive leadership'
            ])
        
        if risk_distribution.get('HIGH', 0) > 0:
            recommendations.extend([
                'Prioritize high-risk scenarios for mitigation',
                'Implement additional security controls',
                'Increase monitoring and detection capabilities',
                'Review and update incident response procedures'
            ])
        
        if overall_risk_score > 15:
            recommendations.append('Overall risk level is high - comprehensive risk treatment required')
        elif overall_risk_score > 10:
            recommendations.append('Moderate risk level - targeted risk mitigation recommended')
        
        recommendations.extend([
            'Implement continuous risk monitoring',
            'Regular risk assessment updates',
            'Risk awareness training for staff',
            'Establish risk governance framework'
        ])
        
        return recommendations
    
    def generate_compliance_report(self, assessment_id: str) -> Dict:
        """Generate comprehensive compliance report"""
        if assessment_id not in self.assessments:
            return {'error': 'Assessment not found'}
        
        assessment = self.assessments[assessment_id]
        
        report = {
            'report_id': hashlib.md5(f"compliance_report_{assessment_id}".encode()).hexdigest()[:8],
            'generated_at': datetime.now().isoformat(),
            'assessment_summary': {
                'assessment_id': assessment.assessment_id,
                'framework': assessment.framework.value,
                'organization': assessment.organization,
                'assessed_by': assessment.assessed_by,
                'assessment_date': assessment.assessment_date.isoformat(),
                'overall_score': assessment.overall_score,
                'compliance_status': assessment.compliance_status.value
            },
            'control_summary': self._generate_control_summary(assessment.findings),
            'gap_analysis': self._generate_gap_analysis(assessment.findings),
            'risk_analysis': self._generate_compliance_risk_analysis(assessment.findings),
            'remediation_plan': assessment.remediation_plan,
            'recommendations': assessment.recommendations,
            'next_steps': self._generate_next_steps(assessment),
            'executive_summary': self._generate_executive_summary(assessment)
        }
        
        return report
    
    def _generate_control_summary(self, findings: List[Dict]) -> Dict:
        """Generate control assessment summary"""
        summary = {
            'total_controls': len(findings),
            'compliant': sum(1 for f in findings if f['status'] == ComplianceStatus.COMPLIANT),
            'partially_compliant': sum(1 for f in findings if f['status'] == ComplianceStatus.PARTIALLY_COMPLIANT),
            'non_compliant': sum(1 for f in findings if f['status'] == ComplianceStatus.NON_COMPLIANT),
            'control_categories': Counter(),
            'average_score': 0
        }
        
        if findings:
            total_score = sum(f.get('score', 0) for f in findings)
            summary['average_score'] = total_score / len(findings)
        
        for finding in findings:
            control_id = finding['control_id']
            category = control_id.split('.')[0] if '.' in control_id else 'Other'
            summary['control_categories'][category] += 1
        
        return summary
    
    def _generate_gap_analysis(self, findings: List[Dict]) -> Dict:
        """Generate gap analysis"""
        gaps = {
            'critical_gaps': [],
            'significant_gaps': [],
            'minor_gaps': [],
            'common_issues': Counter()
        }
        
        for finding in findings:
            if finding['status'] == ComplianceStatus.NON_COMPLIANT:
                gap_info = {
                    'control_id': finding['control_id'],
                    'control_title': finding['control_title'],
                    'gaps': finding.get('gaps', []),
                    'risk_level': finding.get('risk_level', RiskLevel.MEDIUM).value
                }
                
                if finding.get('risk_level') == RiskLevel.CRITICAL:
                    gaps['critical_gaps'].append(gap_info)
                elif finding.get('risk_level') == RiskLevel.HIGH:
                    gaps['significant_gaps'].append(gap_info)
                else:
                    gaps['minor_gaps'].append(gap_info)
            
            # Count common issues
            for gap in finding.get('gaps', []):
                gaps['common_issues'][gap] += 1
        
        return gaps
    
    def _generate_compliance_risk_analysis(self, findings: List[Dict]) -> Dict:
        """Generate compliance risk analysis"""
        risk_analysis = {
            'overall_risk_level': RiskLevel.MEDIUM,
            'regulatory_risks': [],
            'business_risks': [],
            'reputation_risks': [],
            'financial_risks': []
        }
        
        non_compliant_count = sum(1 for f in findings if f['status'] == ComplianceStatus.NON_COMPLIANT)
        total_controls = len(findings)
        
        if non_compliant_count > total_controls * 0.5:
            risk_analysis['overall_risk_level'] = RiskLevel.CRITICAL
        elif non_compliant_count > total_controls * 0.25:
            risk_analysis['overall_risk_level'] = RiskLevel.HIGH
        
        # Add specific risk categories based on findings
        if non_compliant_count > 0:
            risk_analysis['regulatory_risks'].extend([
                'Potential regulatory penalties',
                'Audit findings and sanctions',
                'Loss of regulatory approvals'
            ])
            
            risk_analysis['business_risks'].extend([
                'Operational disruptions',
                'Loss of customer trust',
                'Competitive disadvantage'
            ])
            
            risk_analysis['reputation_risks'].extend([
                'Negative media coverage',
                'Customer confidence loss',
                'Partner relationship impact'
            ])
            
            risk_analysis['financial_risks'].extend([
                'Regulatory fines and penalties',
                'Remediation costs',
                'Revenue impact'
            ])
        
        return risk_analysis
    
    def _generate_next_steps(self, assessment: ComplianceAssessment) -> List[str]:
        """Generate next steps for compliance program"""
        next_steps = []
        
        if assessment.compliance_status == ComplianceStatus.NON_COMPLIANT:
            next_steps.extend([
                'Immediate remediation of critical gaps',
                'Engage executive leadership',
                'Develop comprehensive improvement plan',
                'Consider external compliance consulting'
            ])
        elif assessment.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT:
            next_steps.extend([
                'Address identified gaps systematically',
                'Enhance documentation and evidence collection',
                'Improve control testing procedures',
                'Plan follow-up assessment'
            ])
        
        next_steps.extend([
            'Implement continuous compliance monitoring',
            'Provide compliance training to staff',
            'Establish regular assessment schedule',
            'Monitor regulatory changes and updates'
        ])
        
        return next_steps
    
    def _generate_executive_summary(self, assessment: ComplianceAssessment) -> str:
        """Generate executive summary of compliance assessment"""
        compliant_controls = sum(1 for f in assessment.findings if f['status'] == ComplianceStatus.COMPLIANT)
        total_controls = len(assessment.findings)
        compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        if assessment.compliance_status == ComplianceStatus.COMPLIANT:
            return f"The organization demonstrates strong compliance with {assessment.framework.value} requirements, achieving {compliance_percentage:.1f}% compliance across {total_controls} assessed controls. Continue current practices with regular monitoring."
        
        elif assessment.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return f"The organization shows {compliance_percentage:.1f}% compliance with {assessment.framework.value} requirements. Key gaps have been identified that require attention to achieve full compliance. A systematic remediation approach is recommended."
        
        else:
            return f"The organization currently achieves {compliance_percentage:.1f}% compliance with {assessment.framework.value} requirements. Significant gaps exist that pose compliance and business risks. Immediate action is required to address critical deficiencies."