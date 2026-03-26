"""
COMPLETE REPORT GENERATION SYSTEM
6-Layer Enterprise Pipeline + UI Integration
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# LAYER 1: RAW SCAN DATA INGESTION
# ============================================================================

class RawScanDataIngestor:
    """Accepts and validates raw scan outputs from all modules"""
    
    def __init__(self):
        self.raw_data = {}
        self.validation_errors = []
        self.metadata = {
            "ingestion_timestamp": datetime.utcnow().isoformat(),
            "modules_processed": []
        }
    
    def ingest_all_scan_data(self, scan_result: Dict) -> Tuple[Dict, bool]:
        """Ingest complete scan result from database"""
        try:
            # Extract all data from scan result
            self.raw_data = {
                "scan_metadata": {
                    "scan_id": scan_result.get("scan_id"),
                    "operator_name": scan_result.get("operator_name"),
                    "network_range": scan_result.get("network_range"),
                    "started_at": scan_result.get("started_at"),
                    "completed_at": scan_result.get("completed_at"),
                    "status": scan_result.get("status")
                },
                "discovery": {
                    "total_hosts": scan_result.get("total_hosts_found", 0),
                    "cctv_devices": scan_result.get("cctv_devices_found", 0),
                    "vulnerabilities": scan_result.get("vulnerabilities_found", 0)
                },
                "devices": scan_result.get("devices", []),
                "severity_summary": {
                    "critical": scan_result.get("critical_count", 0),
                    "high": scan_result.get("high_count", 0),
                    "medium": scan_result.get("medium_count", 0),
                    "low": scan_result.get("low_count", 0)
                }
            }
            
            logger.info(f"Ingested scan data: {len(self.raw_data.get('devices', []))} devices")
            return self.raw_data, True
            
        except Exception as e:
            logger.error(f"Ingestion failed: {e}")
            self.validation_errors.append(str(e))
            return {}, False


# ============================================================================
# LAYER 2: DATA NORMALIZATION ENGINE  
# ============================================================================

class DataNormalizationEngine:
    """Converts raw data into unified, portable schema"""
    
    def normalize_scan_data(self, raw_data: Dict) -> Tuple[Dict, bool]:
        """Create normalized schema from raw data"""
        try:
            normalized = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "scan_id": raw_data.get("scan_metadata", {}).get("scan_id"),
                    "operator": raw_data.get("scan_metadata", {}).get("operator_name"),
                    "network": raw_data.get("scan_metadata", {}).get("network_range"),
                    "duration": self._calculate_duration(raw_data)
                },
                "assets": self._normalize_assets(raw_data.get("devices", [])),
                "vulnerabilities": self._normalize_vulnerabilities(raw_data.get("devices", [])),
                "statistics": self._calculate_statistics(raw_data),
                "risk_summary": raw_data.get("severity_summary", {})
            }
            
            logger.info(f"Normalized {len(normalized['assets'])} assets")
            return normalized, True
            
        except Exception as e:
            logger.error(f"Normalization failed: {e}")
            return {}, False
    
    def _normalize_assets(self, devices: List[Dict]) -> List[Dict]:
        """Normalize device/asset list"""
        assets = []
        for device in devices:
            asset = {
                "id": device.get("id"),
                "ip": device.get("ip_address"),
                "mac": device.get("mac_address"),
                "manufacturer": device.get("manufacturer"),
                "device_type": device.get("device_type"),
                "is_cctv": device.get("is_cctv", False),
                "confidence": device.get("confidence_score", 0),
                "ports": self._extract_ports(device),
                "vuln_count": len(device.get("vulnerabilities", []))
            }
            assets.append(asset)
        return assets
    
    def _normalize_vulnerabilities(self, devices: List[Dict]) -> List[Dict]:
        """Extract and normalize vulnerabilities"""
        vulns = []
        for device in devices:
            device_vulns = device.get("vulnerabilities", [])
            for vuln in device_vulns:
                normalized_vuln = {
                    "id": vuln.get("id"),
                    "vuln_id": vuln.get("vuln_id"),
                    "title": vuln.get("title"),
                    "severity": vuln.get("severity"),
                    "cvss": vuln.get("cvss_score"),
                    "cve": vuln.get("cve_id"),
                    "device_ip": device.get("ip_address"),
                    "remediation": vuln.get("remediation")
                }
                vulns.append(normalized_vuln)
        return vulns
    
    def _extract_ports(self, device: Dict) -> List[Dict]:
        """Extract open ports"""
        ports = []
        for port in device.get("ports", []):
            ports.append({
                "number": port.get("port_number"),
                "protocol": port.get("protocol"),
                "service": port.get("service_name"),
                "banner": port.get("banner")
            })
        return ports
    
    def _calculate_duration(self, raw_data: Dict) -> str:
        """Calculate scan duration"""
        try:
            started = raw_data.get("scan_metadata", {}).get("started_at")
            completed = raw_data.get("scan_metadata", {}).get("completed_at")
            if started and completed:
                from datetime import datetime as dt
                s = dt.fromisoformat(started)
                c = dt.fromisoformat(completed)
                duration = (c - s).total_seconds()
                return f"{int(duration)}s"
        except:
            pass
        return "N/A"
    
    def _calculate_statistics(self, raw_data: Dict) -> Dict:
        """Calculate statistics"""
        devices = raw_data.get("devices", [])
        return {
            "total_hosts": raw_data.get("discovery", {}).get("total_hosts", 0),
            "cctv_devices": raw_data.get("discovery", {}).get("cctv_devices", 0),
            "total_vulnerabilities": raw_data.get("discovery", {}).get("vulnerabilities", 0),
            "unique_services": len(set(p.get("service_name") for d in devices for p in d.get("ports", []))),
            "devices_with_vulns": len([d for d in devices if d.get("vulnerabilities")])
        }


# ============================================================================
# LAYER 3: RISK INTELLIGENCE ENGINE
# ============================================================================

class RiskIntelligenceEngine:
    """Adds risk context and scoring to normalized data"""
    
    def analyze_risk(self, normalized_data: Dict) -> Tuple[Dict, bool]:
        """Add risk analysis to normalized data"""
        try:
            enriched = normalized_data.copy()
            
            # Calculate overall risk score
            vulns = normalized_data.get("vulnerabilities", [])
            enriched["risk_assessment"] = self._calculate_risk_score(vulns)
            
            # Identify critical assets
            enriched["critical_assets"] = self._identify_critical_assets(
                normalized_data.get("assets", []),
                vulns
            )
            
            # Generate recommendations
            enriched["recommendations"] = self._generate_recommendations(vulns)
            
            logger.info("Risk analysis complete")
            return enriched, True
            
        except Exception as e:
            logger.error(f"Risk analysis failed: {e}")
            return {}, False
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return {"score": 0, "rating": "Low", "level": "green"}
        
        severity_scores = {"critical": 40, "high": 25, "medium": 10, "low": 5}
        total_score = sum(severity_scores.get(v.get("severity"), 0) for v in vulnerabilities)
        
        # Normalize to 0-100
        score = min(total_score, 100)
        
        if score >= 80:
            return {"score": score, "rating": "Critical", "level": "red"}
        elif score >= 60:
            return {"score": score, "rating": "High", "level": "orange"}
        elif score >= 40:
            return {"score": score, "rating": "Medium", "level": "yellow"}
        else:
            return {"score": score, "rating": "Low", "level": "green"}
    
    def _identify_critical_assets(self, assets: List[Dict], vulns: List[Dict]) -> List[Dict]:
        """Identify critical assets with high-severity vulnerabilities"""
        critical = []
        
        for asset in assets:
            asset_vulns = [v for v in vulns if v.get("device_ip") == asset.get("ip")]
            critical_vulns = [v for v in asset_vulns if v.get("severity") == "critical"]
            
            if critical_vulns:
                critical.append({
                    "ip": asset.get("ip"),
                    "manufacturer": asset.get("manufacturer"),
                    "critical_vuln_count": len(critical_vulns),
                    "total_vuln_count": len(asset_vulns),
                    "vulnerabilities": critical_vulns
                })
        
        return critical
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate remediation recommendations"""
        recommendations = []
        
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        if critical_vulns:
            recommendations.append({
                "priority": "CRITICAL",
                "recommendation": f"Address {len(critical_vulns)} critical vulnerabilities immediately",
                "action": "Review and patch firmware/update credentials"
            })
        
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
        if high_vulns:
            recommendations.append({
                "priority": "HIGH",
                "recommendation": f"Plan remediation for {len(high_vulns)} high-severity issues",
                "action": "Schedule updates and configuration changes"
            })
        
        return recommendations


# ============================================================================
# LAYER 4: REPORT COMPOSITION ENGINE
# ============================================================================

class ReportCompositionEngine:
    """Composes final reports from enriched data"""
    
    def compose_all_reports(self, enriched_data: Dict) -> Dict:
        """Compose executive, technical, and compliance reports"""
        return {
            "executive_summary": self._compose_executive_report(enriched_data),
            "technical_report": self._compose_technical_report(enriched_data),
            "compliance_report": self._compose_compliance_report(enriched_data)
        }
    
    def _compose_executive_report(self, data: Dict) -> Dict:
        """Business-focused executive summary"""
        return {
            "title": "CCTV VAPT Assessment - Executive Summary",
            "type": "executive",
            "sections": [
                {
                    "heading": "Assessment Overview",
                    "content": f"""
Scope: {data.get('report_metadata', {}).get('network')}
Duration: {data.get('report_metadata', {}).get('duration')}
Operator: {data.get('report_metadata', {}).get('operator')}
Generated: {data.get('report_metadata', {}).get('generated_at')}
                    """
                },
                {
                    "heading": "Risk Summary",
                    "content": f"""
Overall Risk Level: {data.get('risk_assessment', {}).get('rating')}
Total Vulnerabilities: {data.get('statistics', {}).get('total_vulnerabilities')}
Critical Issues: {data.get('risk_summary', {}).get('critical', 0)}
High Issues: {data.get('risk_summary', {}).get('high', 0)}
                    """
                },
                {
                    "heading": "Key Findings",
                    "items": self._format_key_findings(data),
                    "content": "Critical vulnerabilities identified that require immediate attention"
                },
                {
                    "heading": "Recommendations",
                    "items": [r.get("recommendation") for r in data.get("recommendations", [])],
                    "content": "Action items grouped by priority"
                },
                {
                    "heading": "Assets Assessed",
                    "content": f"""
Total Hosts Scanned: {data.get('statistics', {}).get('total_hosts')}
CCTV Devices Found: {data.get('statistics', {}).get('cctv_devices')}
Devices with Vulnerabilities: {data.get('statistics', {}).get('devices_with_vulns')}
                    """
                }
            ]
        }
    
    def _compose_technical_report(self, data: Dict) -> Dict:
        """Technical detailed report"""
        return {
            "title": "CCTV VAPT Assessment - Technical Report",
            "type": "technical",
            "sections": [
                {
                    "heading": "Network Assessment",
                    "subsections": self._format_network_details(data)
                },
                {
                    "heading": "Discovered Assets",
                    "table": self._format_asset_table(data.get("assets", []))
                },
                {
                    "heading": "Vulnerability Details",
                    "table": self._format_vulnerability_table(data.get("vulnerabilities", []))
                },
                {
                    "heading": "Service Inventory",
                    "content": f"Unique services discovered: {data.get('statistics', {}).get('unique_services')}"
                }
            ]
        }
    
    def _compose_compliance_report(self, data: Dict) -> Dict:
        """Compliance and regulatory report"""
        return {
            "title": "CCTV VAPT Assessment - Compliance Report",
            "type": "compliance",
            "sections": [
                {
                    "heading": "Assessment Scope",
                    "content": f"Network: {data.get('report_metadata', {}).get('network')}"
                },
                {
                    "heading": "Finding Severity Distribution",
                    "content": self._format_severity_distribution(data)
                },
                {
                    "heading": "Compliance Status",
                    "content": f"""
Devices with Critical Issues: {len(data.get('critical_assets', []))}
Total Vulnerabilities: {data.get('statistics', {}).get('total_vulnerabilities')}
Remediation Priority: {data.get('risk_assessment', {}).get('rating')}
                    """
                },
                {
                    "heading": "Remediation Timeline",
                    "content": """
Critical: Immediate (within 24 hours)
High: Within 7 days
Medium: Within 30 days
Low: Within 60 days
                    """
                }
            ]
        }
    
    @staticmethod
    def _format_key_findings(data: Dict) -> List[str]:
        """Format key findings"""
        critical = data.get('risk_summary', {}).get('critical', 0)
        high = data.get('risk_summary', {}).get('high', 0)
        findings = []
        if critical > 0:
            findings.append(f"{critical} critical vulnerabilities detected")
        if high > 0:
            findings.append(f"{high} high-severity issues identified")
        return findings
    
    @staticmethod
    def _format_network_details(data: Dict) -> List[Dict]:
        """Format network details for technical report"""
        return [
            {
                "title": "Scan Parameters",
                "content": f"Network: {data.get('report_metadata', {}).get('network')}"
            }
        ]
    
    @staticmethod
    def _format_asset_table(assets: List[Dict]) -> List[List[str]]:
        """Format assets as table rows"""
        rows = [["IP Address", "Manufacturer", "Type", "Vulnerabilities"]]
        for asset in assets:
            rows.append([
                asset.get("ip", "N/A"),
                asset.get("manufacturer", "Unknown"),
                asset.get("device_type", "N/A"),
                str(asset.get("vuln_count", 0))
            ])
        return rows
    
    @staticmethod
    def _format_vulnerability_table(vulns: List[Dict]) -> List[List[str]]:
        """Format vulnerabilities as table rows"""
        rows = [["Device IP", "Vulnerability", "Severity", "CVE"]]
        for vuln in vulns[:20]:  # Limit to first 20
            rows.append([
                vuln.get("device_ip", "N/A"),
                vuln.get("title", "N/A"),
                vuln.get("severity", "N/A").upper(),
                vuln.get("cve", "N/A")
            ])
        if len(vulns) > 20:
            rows.append(["...", f"+{len(vulns) - 20} more vulnerabilities", "...", "..."])
        return rows
    
    @staticmethod
    def _format_severity_distribution(data: Dict) -> str:
        """Format severity distribution"""
        summary = data.get('risk_summary', {})
        return f"""
Critical: {summary.get('critical', 0)}
High: {summary.get('high', 0)}
Medium: {summary.get('medium', 0)}
Low: {summary.get('low', 0)}
        """


# ============================================================================
# LAYER 5: AUTOMATION & ORCHESTRATION
# ============================================================================

class ReportOrchestrator:
    """Orchestrates complete 6-layer pipeline execution"""
    
    def __init__(self):
        self.layer1 = RawScanDataIngestor()
        self.layer2 = DataNormalizationEngine()
        self.layer3 = RiskIntelligenceEngine()
        self.layer4 = ReportCompositionEngine()
    
    def generate_complete_report(self, scan_result: Dict) -> Tuple[Dict, bool]:
        """Execute full 6-layer pipeline"""
        try:
            # Layer 1: Ingest
            raw_data, success = self.layer1.ingest_all_scan_data(scan_result)
            if not success:
                logger.error("Layer 1 failed")
                return {}, False
            
            # Layer 2: Normalize
            normalized, success = self.layer2.normalize_scan_data(raw_data)
            if not success:
                logger.error("Layer 2 failed")
                return {}, False
            
            # Layer 3: Analyze Risk
            enriched, success = self.layer3.analyze_risk(normalized)
            if not success:
                logger.error("Layer 3 failed")
                return {}, False
            
            # Layer 4: Compose Reports
            reports = self.layer4.compose_all_reports(enriched)
            
            result = {
                "scan_id": scan_result.get("scan_id"),
                "generated_at": datetime.utcnow().isoformat(),
                "reports": reports,
                "enriched_data": enriched,
                "status": "complete"
            }
            
            logger.info("Report generation complete")
            return result, True
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return {}, False


# ============================================================================
# LAYER 6: OUTPUT & DISTRIBUTION
# ============================================================================

class OutputDistributor:
    """Exports reports to various formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
    
    def export_json(self, report_data: Dict, scan_id: str) -> Tuple[str, bool]:
        """Export as JSON"""
        try:
            output_file = self.output_dir / f"{scan_id}_report.json"
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            logger.info(f"JSON export: {output_file}")
            return str(output_file), True
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            return "", False
    
    def export_html(self, report_data: Dict, scan_id: str) -> Tuple[str, bool]:
        """Export as HTML"""
        try:
            html_content = self._generate_html(report_data)
            output_file = self.output_dir / f"{scan_id}_report.html"
            with open(output_file, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML export: {output_file}")
            return str(output_file), True
        except Exception as e:
            logger.error(f"HTML export failed: {e}")
            return "", False
    
    def _generate_html(self, report_data: Dict) -> str:
        """Generate HTML report"""
        reports = report_data.get("reports", {})
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CCTV VAPT Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-top: 0; }}
        .content-box {{ background: #f5f5f5; padding: 15px; border-left: 4px solid #667eea; margin: 10px 0; border-radius: 4px; }}
        .statistics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; border: 1px solid #ddd; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #17a2b8; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f5f5f5; font-weight: bold; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CCTV VAPT Assessment Report</h1>
        <p>Generated: {report_data.get('generated_at', 'N/A')}</p>
    </div>
"""
        
        # Executive Summary
        exec_report = reports.get("executive_summary", {})
        html += f"""
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="statistics">
"""
        
        enriched = report_data.get("enriched_data", {})
        stats = enriched.get("statistics", {})
        
        html += f"""
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_hosts', 0)}</div>
                <div class="stat-label">Hosts Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('cctv_devices', 0)}</div>
                <div class="stat-label">CCTV Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_vulnerabilities', 0)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{enriched.get('risk_assessment', {}).get('rating', 'N/A')}</div>
                <div class="stat-label">Risk Level</div>
            </div>
        </div>
"""
        
        # Severity Summary
        risk_summary = enriched.get('risk_summary', {})
        html += f"""
    <div class="section">
        <h2>Vulnerability Summary</h2>
        <div class="statistics">
            <div class="stat-card">
                <div class="stat-value severity-critical">{risk_summary.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-high">{risk_summary.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-medium">{risk_summary.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-low">{risk_summary.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
    </div>
"""
        
        # Recommendations
        html += """
    <div class="section">
        <h2>Recommendations</h2>
"""
        for rec in enriched.get("recommendations", []):
            html += f"""
        <div class="content-box">
            <strong>[{rec.get('priority', 'INFO')}]</strong> {rec.get('recommendation', 'N/A')}
            <br><small>Action: {rec.get('action', 'N/A')}</small>
        </div>
"""
        
        html += """
    </div>
    <div class="footer">
        <p>This report was automatically generated by VAPT Tool. For questions, contact your security team.</p>
    </div>
</body>
</html>
"""
        return html
    
    def export_all_formats(self, report_data: Dict, scan_id: str) -> Dict:
        """Export to all formats"""
        results = {}
        
        json_file, success = self.export_json(report_data, scan_id)
        results['json'] = {'file': json_file, 'success': success}
        
        html_file, success = self.export_html(report_data, scan_id)
        results['html'] = {'file': html_file, 'success': success}
        
        return results
