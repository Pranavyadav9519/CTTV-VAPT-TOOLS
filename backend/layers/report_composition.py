"""
LAYER 4: REPORT COMPOSITION ENGINE
Template-based report generation with separation of data from presentation.

This layer provides:
- Jinja2-based template rendering
- Multiple report views (Executive, Technical, Compliance)
- Template versioning and management
- Data-to-template binding
- Support for multiple output formats (before Layer 6 rendering)
"""

from typing import Dict, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ReportCompositionEngine:
    """
    Composes reports from normalized, risk-enriched data using templates.
    Separates data from presentation for flexibility and reusability.
    """

    def __init__(self):
        """Initialize report composition engine"""
        self.available_templates = {}
        self.rendered_reports = {}
        self._register_builtin_templates()

    def compose_executive_summary_report(
        self,
        enriched_assets: List[Dict],
        enriched_vulns: List[Dict],
        risk_summary: Dict,
        recommendations: List[str],
        scan_metadata: Dict,
    ) -> Dict:
        """
        Compose executive summary report (non-technical, C-suite level).

        Focus: Business risk, quantified impact, strategic recommendations
        Audience: Management, board members, non-technical stakeholders
        """
        try:
            report_data = {
                "report_type": "executive_summary",
                "report_title": "VAPT Assessment Executive Summary",
                "template_id": "exec_summary_v1",
                "generated_at": datetime.utcnow().isoformat(),
                "scan_metadata": scan_metadata,
                "executive_summary": self._compose_executive_overview(
                    enriched_assets, enriched_vulns, risk_summary
                ),
                "key_findings": self._compose_key_findings(
                    enriched_vulns, risk_summary
                ),
                "business_impact": self._compose_business_impact(
                    enriched_assets, risk_summary
                ),
                "strategic_recommendations": self._compose_strategic_recommendations(
                    recommendations
                ),
                "timeline": self._compose_remediation_timeline(enriched_vulns),
                "metrics": {
                    "total_systems_assessed": len(enriched_assets),
                    "critical_issues": risk_summary.get("risk_distribution", {}).get(
                        "critical", 0
                    ),
                    "high_issues": risk_summary.get("risk_distribution", {}).get(
                        "high", 0
                    ),
                    "cctv_systems_assessed": len(
                        [a for a in enriched_assets if a.get("is_cctv")]
                    ),
                    "assessment_date": scan_metadata.get("started_at", "Unknown"),
                    "assessor": scan_metadata.get("operator_name", "Security Team"),
                },
            }

            logger.info("Executive summary report composed")
            return report_data

        except Exception as e:
            logger.error(f"Error composing executive summary: {str(e)}")
            return {}

    def compose_technical_report(
        self,
        enriched_assets: List[Dict],
        enriched_vulns: List[Dict],
        normalized_assets: List[Dict],
        scan_metadata: Dict,
    ) -> Dict:
        """
        Compose detailed technical vulnerability report.

        Focus: Vulnerability details, technical evidence, remediation steps
        Audience: Security team, system administrators, developers
        """
        try:
            report_data = {
                "report_type": "technical_detailed",
                "report_title": "Technical Vulnerability Assessment Report",
                "template_id": "technical_v1",
                "generated_at": datetime.utcnow().isoformat(),
                "scan_metadata": scan_metadata,
                "methodology": self._compose_methodology(),
                "asset_inventory": self._compose_asset_inventory(enriched_assets),
                "vulnerability_findings": self._compose_detailed_vulnerabilities(
                    enriched_vulns
                ),
                "port_analysis": self._compose_port_analysis(enriched_assets),
                "service_fingerprints": self._compose_service_fingerprints(
                    enriched_assets
                ),
                "remediation_procedures": self._compose_remediation_procedures(
                    enriched_vulns
                ),
                "configuration_audit": self._compose_configuration_audit(
                    enriched_assets
                ),
            }

            logger.info("Technical report composed")
            return report_data

        except Exception as e:
            logger.error(f"Error composing technical report: {str(e)}")
            return {}

    def compose_compliance_audit_report(
        self,
        enriched_assets: List[Dict],
        enriched_vulns: List[Dict],
        scan_metadata: Dict,
    ) -> Dict:
        """
        Compose compliance and audit appendix.

        Focus: Standards compliance, audit trail, evidence preservation
        Audience: Auditors, compliance officers, legal
        """
        try:
            report_data = {
                "report_type": "compliance_audit",
                "report_title": "VAPT Compliance & Audit Report",
                "template_id": "compliance_v1",
                "generated_at": datetime.utcnow().isoformat(),
                "scan_metadata": scan_metadata,
                "assessment_scope": self._compose_assessment_scope(enriched_assets),
                "compliance_framework_mapping": self._compose_compliance_mapping(
                    enriched_vulns
                ),
                "audit_trail": self._compose_audit_trail(scan_metadata),
                "evidence_preservation": self._compose_evidence_preservation(
                    enriched_vulns
                ),
                "certification": self._compose_certification_section(),
            }

            logger.info("Compliance report composed")
            return report_data

        except Exception as e:
            logger.error(f"Error composing compliance report: {str(e)}")
            return {}

    # =========================================================================
    # REPORT COMPOSITION HELPERS - EXECUTIVE
    # =========================================================================

    def _compose_executive_overview(
        self, assets: List[Dict], vulns: List[Dict], summary: Dict
    ) -> Dict:
        """Compose executive overview section"""
        return {
            "introduction": (
                "This Vulnerability Assessment & Penetration Testing (VAPT) report documents "
                "security risks identified in the CCTV/DVR system assessment. The assessment "
                "employed non-destructive scanning techniques to identify vulnerabilities without "
                "impacting system availability."
            ),
            "risk_posture": self._describe_risk_posture(summary),
            "executive_statement": self._generate_executive_statement(summary, assets),
        }

    def _describe_risk_posture(self, summary: Dict) -> str:
        """Describe overall risk posture"""
        critical = summary.get("risk_distribution", {}).get("critical", 0)
        high = summary.get("risk_distribution", {}).get("high", 0)

        if critical > 0:
            posture = "CRITICAL - Immediate action required"
        elif high > 0:
            posture = "HIGH - Urgent attention needed"
        else:
            posture = "MODERATE - Remediation recommended"

        return posture

    def _generate_executive_statement(self, summary: Dict, assets: List[Dict]) -> str:
        """Generate executive summary statement"""
        cctv_count = len([a for a in assets if a.get("is_cctv")])
        critical = summary.get("risk_distribution", {}).get("critical", 0)

        return (
            f"Assessment of {len(assets)} network hosts identified {critical} critical vulnerabilities. "
            f"Of these, {cctv_count} are CCTV/DVR systems critical to facility security operations. "
            f"Immediate remediation is recommended for all critical and high-severity findings."
        )

    def _compose_key_findings(self, vulns: List[Dict], summary: Dict) -> List[Dict]:
        """Extract top key findings"""
        # Get most critical vulnerabilities
        critical_vulns = [v for v in vulns if v["risk_rating"] == "critical"]
        high_vulns = [v for v in vulns if v["risk_rating"] == "high"]

        key_findings = []

        for vuln in (critical_vulns + high_vulns)[:5]:  # Top 5
            key_findings.append(
                {
                    "risk_rating": vuln["risk_rating"],
                    "title": vuln["title"],
                    "affected_system": vuln.get("affected_service", "Unknown"),
                    "business_impact": self._describe_business_impact(vuln),
                }
            )

        return key_findings

    def _compose_business_impact(self, assets: List[Dict], summary: Dict) -> Dict:
        """Describe business impact of vulnerabilities"""
        cctv_at_risk = summary.get("cctv_devices_at_risk", 0)
        critical = summary.get("risk_distribution", {}).get("critical", 0)
        external = summary.get("externally_exposed", 0)

        return {
            "security_operations": (
                f"{cctv_at_risk} CCTV/DVR systems with high-risk vulnerabilities could compromise "
                f"facility security monitoring capabilities"
            ),
            "business_continuity": (
                f"{critical} critical vulnerabilities could lead to system compromise, "
                f"denial of service, or data loss"
            ),
            "external_risk": (
                f"{external} systems are externally accessible and could be targeted by remote attackers"
            ),
            "compliance_risk": (
                "Unremediacted vulnerabilities may violate security standards and regulatory requirements"
            ),
        }

    def _compose_strategic_recommendations(self, recommendations: List[str]) -> Dict:
        """Organize recommendations by strategy"""
        return {
            "immediate_actions": (
                recommendations[0:2] if len(recommendations) > 0 else []
            ),
            "short_term": recommendations[2:4] if len(recommendations) > 2 else [],
            "long_term": recommendations[4:] if len(recommendations) > 4 else [],
        }

    def _compose_remediation_timeline(self, vulns: List[Dict]) -> Dict:
        """Compose remediation timeline based on risk"""
        critical = len([v for v in vulns if v["risk_rating"] == "critical"])
        high = len([v for v in vulns if v["risk_rating"] == "high"])

        return {
            "immediate_0_4_hours": {
                "count": critical,
                "description": "Critical vulnerabilities requiring immediate remediation",
            },
            "urgent_1_day": {
                "count": high,
                "description": "High-risk vulnerabilities to be addressed within 24 hours",
            },
            "short_term_7_days": {
                "count": len([v for v in vulns if v["risk_rating"] == "medium"]),
                "description": "Medium-risk vulnerabilities to be addressed within one week",
            },
            "standard_30_days": {
                "count": len([v for v in vulns if v["risk_rating"] == "low"]),
                "description": "Low-risk items to be addressed within 30 days",
            },
        }

    def _describe_business_impact(self, vuln: Dict) -> str:
        """Describe business impact of vulnerability"""
        severity = vuln["risk_rating"]

        impact_map = {
            "critical": "Could lead to complete system compromise and facility security failure",
            "high": "Could result in unauthorized access or significant security degradation",
            "medium": "Could impact specific systems or functions requiring remediation",
            "low": "Minor security issue with limited business impact",
        }

        return impact_map.get(
            severity, "See vulnerability details for impact assessment"
        )

    # =========================================================================
    # REPORT COMPOSITION HELPERS - TECHNICAL
    # =========================================================================

    def _compose_methodology(self) -> Dict:
        """Compose methodology section"""
        return {
            "phases": [
                {
                    "name": "Network Discovery",
                    "description": "ARP-based scanning to identify active hosts",
                    "tools": "Custom ARP scanner",
                },
                {
                    "name": "Device Identification",
                    "description": "Service fingerprinting and device classification",
                    "tools": "Banner collection, MAC lookup, HTTP headers",
                },
                {
                    "name": "Port Scanning",
                    "description": "Comprehensive port enumeration and service detection",
                    "tools": "Nmap-based port scanner",
                },
                {
                    "name": "Vulnerability Assessment",
                    "description": "CVE matching, misconfiguration detection, protocol analysis",
                    "tools": "Custom vulnerability scanner",
                },
                {
                    "name": "Credential Testing",
                    "description": "Read-only authentication attempts and default credential checks",
                    "tools": "Credential tester module",
                },
            ]
        }

    def _compose_asset_inventory(self, assets: List[Dict]) -> List[Dict]:
        """Compose detailed asset inventory"""
        inventory = []
        for asset in assets:
            inventory.append(
                {
                    "ip_address": asset["ip_address"],
                    "mac_address": asset["mac_address"],
                    "device_type": asset["asset_type"],
                    "hostname": asset.get("hostname"),
                    "manufacturer": asset.get("manufacturer"),
                    "model": asset.get("model"),
                    "criticality": asset["criticality"],
                    "risk_rating": asset["overall_risk_rating"],
                    "vulnerability_count": len(asset.get("vulnerabilities", [])),
                    "open_ports": len(asset.get("ports", [])),
                }
            )
        return inventory

    def _compose_detailed_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Compose detailed vulnerability findings"""
        detailed = []
        for idx, vuln in enumerate(vulns, 1):
            detailed.append(
                {
                    "id": idx,
                    "title": vuln["title"],
                    "severity": vuln["severity"],
                    "risk_rating": vuln["risk_rating"],
                    "risk_score": vuln["risk_score"],
                    "cvss_score": vuln["cvss_score"],
                    "cve_id": vuln.get("cve_id"),
                    "cwe_id": vuln.get("cwe_id"),
                    "description": vuln["description"],
                    "affected_asset": vuln["asset_id"],
                    "affected_port": vuln.get("affected_port"),
                    "evidence": vuln.get("evidence"),
                    "risk_factors": vuln.get("risk_factors"),
                    "remediation": vuln["remediation"],
                    "references": vuln.get("references", []),
                }
            )
        return detailed

    def _compose_port_analysis(self, assets: List[Dict]) -> Dict:
        """Compose port and service analysis"""
        all_ports = []
        for asset in assets:
            for port in asset.get("ports", []):
                all_ports.append(
                    {
                        "asset_ip": asset["ip_address"],
                        "port_number": port.get("port_number"),
                        "protocol": port.get("protocol"),
                        "state": port.get("state"),
                        "service": port.get("service_name"),
                        "version": port.get("service_version"),
                        "encrypted": port.get("is_encrypted"),
                    }
                )

        return {
            "total_ports_open": len(all_ports),
            "ports": all_ports[:50],  # Limit to top 50 for report
        }

    def _compose_service_fingerprints(self, assets: List[Dict]) -> List[str]:
        """Extract unique service fingerprints"""
        services = set()
        for asset in assets:
            services.update(asset.get("services", []))
        return sorted(list(services))

    def _compose_remediation_procedures(self, vulns: List[Dict]) -> List[Dict]:
        """Compile remediation procedures by vulnerability"""
        procedures = []
        for vuln in vulns:
            procedures.append(
                {
                    "vulnerability": vuln["title"],
                    "severity": vuln["risk_rating"],
                    "procedure": vuln.get("remediation", "Contact vendor for guidance"),
                    "priority": vuln.get("remediation_priority", "As soon as possible"),
                }
            )
        return procedures

    def _compose_configuration_audit(self, assets: List[Dict]) -> Dict:
        """Audit configuration findings"""
        return {
            "default_credentials_found": sum(
                1 for a in assets if a.get("risk_context", {}).get("has_default_creds")
            ),
            "services_encrypted": sum(
                1 for a in assets for p in a.get("ports", []) if p.get("is_encrypted")
            ),
            "services_unencrypted": sum(
                1
                for a in assets
                for p in a.get("ports", [])
                if not p.get("is_encrypted")
            ),
            "cctv_devices_inventoried": len([a for a in assets if a.get("is_cctv")]),
        }

    # =========================================================================
    # REPORT COMPOSITION HELPERS - COMPLIANCE
    # =========================================================================

    def _compose_assessment_scope(self, assets: List[Dict]) -> Dict:
        """Compose assessment scope"""
        return {
            "total_systems": len(assets),
            "cctv_systems": len([a for a in assets if a.get("is_cctv")]),
            "other_network_devices": len([a for a in assets if not a.get("is_cctv")]),
            "scanning_method": "Non-destructive network scanning",
            "assessment_categories": [
                "Network discovery",
                "Device identification",
                "Port scanning",
                "Vulnerability assessment",
            ],
        }

    def _compose_compliance_mapping(self, vulns: List[Dict]) -> Dict:
        """Map vulnerabilities to compliance frameworks"""
        return {
            "NIST_CSF": self._map_to_nist(vulns),
            "CIS_Controls": self._map_to_cis(vulns),
            "PCI_DSS": self._map_to_pci(vulns),
        }

    def _map_to_nist(self, vulns: List[Dict]) -> Dict:
        """Map to NIST Cybersecurity Framework"""
        return {
            "Identify": "Asset inventory and characterization completed",
            "Protect": f"{len([v for v in vulns if v['risk_rating'] == 'critical'])} critical protective measures needed",
            "Detect": "Vulnerabilities for detection implementation",
            "Respond": f"{len([v for v in vulns if v['risk_rating'] == 'high'])} incident response items",
        }

    def _map_to_cis(self, vulns: List[Dict]) -> str:
        """Map to CIS Controls"""
        return f"Assessment identifies {len(vulns)} CIS control deviations requiring remediation"

    def _map_to_pci(self, vulns: List[Dict]) -> str:
        """Map to PCI DSS"""
        return f"Assessment includes {len(vulns)} PCI DSS compliance issues to address"

    def _compose_audit_trail(self, metadata: Dict) -> Dict:
        """Compose audit trail information"""
        return {
            "scan_id": metadata.get("scan_id"),
            "assessment_start": metadata.get("started_at"),
            "assessment_end": metadata.get("completed_at"),
            "assessor": metadata.get("operator_name"),
            "network_range": metadata.get("network_range"),
            "assessment_type": "Non-destructive vulnerability assessment",
        }

    def _compose_evidence_preservation(self, vulns: List[Dict]) -> List[str]:
        """Preserve evidence for audit purposes"""
        evidence = []
        for vuln in vulns:
            if vuln.get("evidence"):
                evidence.append(
                    {
                        "vulnerability": vuln["title"],
                        "evidence": vuln["evidence"],
                        "timestamp": vuln.get("discovered_at"),
                    }
                )
        return evidence

    def _compose_certification_section(self) -> Dict:
        """Certification and attestation section"""
        return {
            "statement": (
                "This assessment was conducted using industry-standard methodologies "
                "and documented according to professional security assessment standards. "
                "All findings are presented for remediation planning and implementation."
            )
        }

    # =========================================================================
    # TEMPLATE MANAGEMENT
    # =========================================================================

    def _register_builtin_templates(self):
        """Register built-in report templates"""
        self.available_templates = {
            "exec_summary_v1": {
                "name": "Executive Summary",
                "type": "executive",
                "version": "1.0",
                "description": "Non-technical executive summary for management",
            },
            "technical_v1": {
                "name": "Technical Detailed Report",
                "type": "technical",
                "version": "1.0",
                "description": "Detailed technical vulnerability findings",
            },
            "compliance_v1": {
                "name": "Compliance & Audit Report",
                "type": "compliance",
                "version": "1.0",
                "description": "Compliance framework mapping and audit trail",
            },
        }

    def get_available_templates(self) -> Dict:
        """Get list of available templates"""
        return self.available_templates.copy()
