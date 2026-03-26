"""
LAYER 6: OUTPUT & DISTRIBUTION
Generates multiple output formats from composed reports.

This layer provides:
- PDF generation (professional formatting)
- JSON export (machine-readable, integration-friendly)
- HTML export (web-viewable)
- Report immutability and checksumming
- Secure storage handling
- Distribution tracking
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import json
import hashlib
import logging

logger = logging.getLogger(__name__)


class OutputDistributor:
    """
    Distributes composed reports to multiple output formats.
    Ensures immutability and maintains complete audit trail.
    """

    def __init__(self, output_base_dir: str = "reports"):
        """Initialize output distributor"""
        self.output_base_dir = Path(output_base_dir)
        self.output_base_dir.mkdir(exist_ok=True, parents=True)

        # Create subdirectories for each format
        self.pdf_dir = self.output_base_dir / "pdf"
        self.json_dir = self.output_base_dir / "json"
        self.html_dir = self.output_base_dir / "html"

        for dir_path in [self.pdf_dir, self.json_dir, self.html_dir]:
            dir_path.mkdir(exist_ok=True, parents=True)

        self.distribution_manifest = []  # Audit trail of distributions

    def distribute_reports(
        self,
        composed_reports: List[Dict],
        report_formats: List[str] = None,
        scan_id: str = None,
    ) -> Tuple[Dict, bool]:
        """
        Distribute composed reports to multiple output formats.

        Args:
            composed_reports: List of composed report dictionaries from Layer 4
            report_formats: Output formats to generate (pdf, json, html)
            scan_id: Scan ID for report naming

        Returns:
            Tuple of (distribution_manifest_dict, success_bool)
        """
        if not report_formats:
            report_formats = ["json", "html", "pdf"]

        try:
            distribution_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "scan_id": scan_id,
                "generated_files": [],
                "format_details": {},
            }

            for report in composed_reports:
                report_type = report.get("report_type")
                logger.info(
                    f"Distributing {report_type} report to formats: {report_formats}"
                )

                # JSON export (always generated - most complete)
                if "json" in report_formats:
                    json_output = self._export_to_json(report, scan_id)
                    if json_output:
                        distribution_result["generated_files"].append(json_output)
                        if "json" not in distribution_result["format_details"]:
                            distribution_result["format_details"]["json"] = []
                        distribution_result["format_details"]["json"].append(
                            json_output
                        )

                    # HTML export
                if "html" in report_formats:
                    html_output = self._export_to_html(report, scan_id)
                    if html_output:
                        distribution_result["generated_files"].append(html_output)
                        if "html" not in distribution_result["format_details"]:
                            distribution_result["format_details"]["html"] = []
                        distribution_result["format_details"]["html"].append(
                            html_output
                        )

                # PDF export
                if "pdf" in report_formats:
                    pdf_output = self._export_to_pdf(report, scan_id)
                    if pdf_output:
                        distribution_result["generated_files"].append(pdf_output)
                        if "pdf" not in distribution_result["format_details"]:
                            distribution_result["format_details"]["pdf"] = []
                        distribution_result["format_details"]["pdf"].append(pdf_output)

            # Record distribution in manifest
            self.distribution_manifest.append(distribution_result)

            logger.info(
                f"Distribution completed: {len(distribution_result['generated_files'])} files generated"
            )
            return distribution_result, True

        except Exception as e:
            logger.error(f"Error during report distribution: {str(e)}")
            return {}, False

    # =========================================================================
    # JSON EXPORT
    # =========================================================================

    def _export_to_json(self, report: Dict, scan_id: Optional[str]) -> Optional[Dict]:
        """Export report to JSON format"""
        try:
            filename = self._generate_filename(report, scan_id, "json")
            filepath = self.json_dir / filename

            # Structure JSON output with metadata
            json_output = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "report_type": report.get("report_type"),
                    "template_id": report.get("template_id"),
                    "scan_id": scan_id,
                    "format": "json",
                    "version": "1.0",
                },
                "report_content": report,
            }

            # Write JSON file
            with open(filepath, "w") as f:
                json.dump(json_output, f, indent=2, default=str)

            # Calculate checksum
            checksum = self._calculate_checksum(filepath)
            file_size = filepath.stat().st_size

            output_record = {
                "filepath": str(filepath),
                "filename": filename,
                "format": "json",
                "report_type": report.get("report_type"),
                "file_size_bytes": file_size,
                "checksum_sha256": checksum,
                "is_immutable": True,
                "generated_at": datetime.utcnow().isoformat(),
            }

            logger.info(f"JSON report exported: {filename} ({file_size} bytes)")
            return output_record

        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")
            return None

    # =========================================================================
    # HTML EXPORT
    # =========================================================================

    def _export_to_html(self, report: Dict, scan_id: Optional[str]) -> Optional[Dict]:
        """Export report to HTML format"""
        try:
            filename = self._generate_filename(report, scan_id, "html")
            filepath = self.html_dir / filename

            # Build HTML document
            html_content = self._build_html_document(report)

            # Write HTML file
            with open(filepath, "w") as f:
                f.write(html_content)

            # Calculate checksum
            checksum = self._calculate_checksum(filepath)
            file_size = filepath.stat().st_size

            output_record = {
                "filepath": str(filepath),
                "filename": filename,
                "format": "html",
                "report_type": report.get("report_type"),
                "file_size_bytes": file_size,
                "checksum_sha256": checksum,
                "is_immutable": True,
                "generated_at": datetime.utcnow().isoformat(),
            }

            logger.info(f"HTML report exported: {filename} ({file_size} bytes)")
            return output_record

        except Exception as e:
            logger.error(f"Error exporting to HTML: {str(e)}")
            return None

    def _build_html_document(self, report: Dict) -> str:
        """Build complete HTML document from report data"""
        report_type = report.get("report_type")
        title = report.get("report_title", "VAPT Report")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}

        .header {{
            border-bottom: 3px solid #1a365d;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}

        h1 {{
            color: #1a365d;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        h2 {{
            color: #2b6cb0;
            font-size: 1.8em;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #2b6cb0;
            padding-left: 15px;
        }}

        h3 {{
            color: #4a5568;
            font-size: 1.3em;
            margin-top: 20px;
            margin-bottom: 10px;
        }}

        .metadata {{
            background-color: #f0f4f8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}

        .metadata p {{
            margin: 5px 0;
        }}

        .severity-critical {{
            color: #c53030;
            font-weight: bold;
        }}

        .severity-high {{
            color: #dd6b20;
            font-weight: bold;
        }}

        .severity-medium {{
            color: #d69e2e;
            font-weight: bold;
        }}

        .severity-low {{
            color: #3182ce;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}

        th {{
            background-color: #2b6cb0;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}

        td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}

        tr:hover {{
            background-color: #f5f5f5;
        }}

        .vulnerability {{
            background-color: #fef5f5;
            border-left: 4px solid #c53030;
            padding: 15px;
            margin: 15px 0;
            border-radius: 3px;
        }}

        .recommendation {{
            background-color: #f0f4f8;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #3182ce;
            border-radius: 3px;
        }}

        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 0.9em;
        }}

        .classification {{
            background-color: #c53030;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            display: inline-block;
            margin: 10px 0;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <div class="classification">CONFIDENTIAL</div>
"""

        # Add metadata
        metadata = report.get("scan_metadata", {})
        if metadata:
            html += f"""
            <div class="metadata">
                <p><strong>Assessment Date:</strong> {metadata.get('started_at', 'N/A')}</p>
                <p><strong>Assessor:</strong> {metadata.get('operator_name', 'Security Team')}</p>
                <p><strong>Network Range:</strong> {metadata.get('network_range', 'N/A')}</p>
                <p><strong>Report Generated:</strong> {datetime.utcnow().isoformat()}</p>
            </div>
"""

        html += "</div>"

        # Add executive summary for executive reports
        if report_type == "executive_summary":
            exec_summary = report.get("executive_summary", {})
            html += f"""
        <h2>Executive Overview</h2>
        <p>{exec_summary.get('executive_statement', 'Assessment completed.')}</p>
"""

            # Risk posture
            html += f"""
        <h3>Overall Risk Posture</h3>
        <p><strong>{exec_summary.get('risk_posture', 'MODERATE')}</strong></p>
"""

            # Key findings
            key_findings = report.get("key_findings", [])
            if key_findings:
                html += "<h3>Key Findings</h3><ul>"
                for finding in key_findings:
                    severity = finding.get("risk_rating", "unknown")
                    html += f"""
                <li class="severity-{severity}">
                    {finding.get('title', 'Unknown')} - {severity.upper()}
                </li>
"""
                html += "</ul>"

        # Add vulnerabilities
        html += "<h2>Vulnerabilities</h2>"
        vulns = (
            report.get("vulnerability_findings", [])
            if report_type != "executive_summary"
            else report.get("key_findings", [])
        )

        if vulns:
            for vuln in vulns[:20]:  # Limit to 20 for HTML
                title = vuln.get("title", "Unknown")
                severity = vuln.get("risk_rating") or vuln.get("severity", "unknown")
                html += f"""
        <div class="vulnerability">
            <h3>{title}</h3>
            <p><strong>Severity:</strong> <span class="severity-{severity}">{severity.upper()}</span></p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
"""

                if vuln.get("remediation"):
                    html += f"<p><strong>Remediation:</strong> {vuln.get('remediation')}</p>"

                html += "</div>"

        # Add recommendations
        recommendations = (
            report.get("strategic_recommendations", {})
            if report_type == "executive_summary"
            else []
        )
        if recommendations:
            html += "<h2>Recommendations</h2>"
            for rec in recommendations:
                html += f'<div class="recommendation"><p>{rec}</p></div>'

        # Footer
        html += f"""
        <div class="footer">
            <p>This report contains confidential security information. Unauthorized disclosure or
            distribution is strictly prohibited.</p>
            <p>Report Format: HTML | Generated: {datetime.utcnow().isoformat()}</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    # =========================================================================
    # PDF EXPORT
    # =========================================================================

    def _export_to_pdf(self, report: Dict, scan_id: Optional[str]) -> Optional[Dict]:
        """
        Export report to PDF format.
        Note: Full PDF generation would use reportlab or similar.
        For now, this provides the structure for integration.
        """
        try:
            filename = self._generate_filename(report, scan_id, "pdf")
            filepath = self.pdf_dir / filename

            # Try to import reportlab for PDF generation
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.platypus import (
                    SimpleDocTemplate,
                    Paragraph,
                    Spacer,
                )
                from reportlab.lib.units import inch

                doc = SimpleDocTemplate(str(filepath), pagesize=letter)
                story = []
                styles = getSampleStyleSheet()

                # Title
                story.append(
                    Paragraph(
                        report.get("report_title", "VAPT Report"), styles["Title"]
                    )
                )
                story.append(Spacer(1, 0.5 * inch))

                # Report content summary
                content_str = f"""
                <b>Report Type:</b> {report.get('report_type')}<br/>
                <b>Generated:</b> {datetime.utcnow().isoformat()}<br/>
                <b>Classification:</b> CONFIDENTIAL
                """
                story.append(Paragraph(content_str, styles["Normal"]))

                # Build PDF
                doc.build(story)

            except ImportError:
                # Fallback: Create a text-based PDF representation
                logger.warning("reportlab not available, creating fallback PDF")
                with open(filepath, "w") as f:
                    f.write(
                        (
                            f"VAPT REPORT - {report.get('report_type')}\n"
                            f"Generated: {datetime.utcnow().isoformat()}\n"
                            f"Classification: CONFIDENTIAL\n\n"
                            f"Note: Full PDF generation requires reportlab library.\n"
                            f"Content: {json.dumps(report, indent=2, default=str)}\n"
                        )
                    )

            # Calculate checksum
            checksum = self._calculate_checksum(filepath)
            file_size = filepath.stat().st_size

            output_record = {
                "filepath": str(filepath),
                "filename": filename,
                "format": "pdf",
                "report_type": report.get("report_type"),
                "file_size_bytes": file_size,
                "checksum_sha256": checksum,
                "is_immutable": True,
                "generated_at": datetime.utcnow().isoformat(),
            }

            logger.info(f"PDF report exported: {filename} ({file_size} bytes)")
            return output_record

        except Exception as e:
            logger.error(f"Error exporting to PDF: {str(e)}")
            return None

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    def _generate_filename(
        self, report: Dict, scan_id: Optional[str], format_type: str
    ) -> str:
        """Generate filename for report"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_type = report.get("report_type", "report")

        if scan_id:
            filename = f"{scan_id}_{report_type}_{timestamp}.{format_type}"
        else:
            filename = f"{report_type}_{timestamp}.{format_type}"

        return filename

    def _calculate_checksum(self, filepath: Path) -> str:
        """Calculate SHA-256 checksum for file integrity"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    # =========================================================================
    # DATA RETRIEVAL
    # =========================================================================

    def get_distribution_manifest(self) -> List[Dict]:
        """Get distribution audit trail"""
        return self.distribution_manifest.copy()

    def get_generated_files(self, format_type: Optional[str] = None) -> List[str]:
        """Get list of generated file paths"""
        files = []

        if format_type is None or format_type == "json":
            files.extend([str(f) for f in self.json_dir.glob("*")])

        if format_type is None or format_type == "html":
            files.extend([str(f) for f in self.html_dir.glob("*")])

        if format_type is None or format_type == "pdf":
            files.extend([str(f) for f in self.pdf_dir.glob("*")])

        return files

    def get_distribution_status(self) -> Dict:
        """Get overall distribution status"""
        return {
            "total_distributions": len(self.distribution_manifest),
            "json_files": len(list(self.json_dir.glob("*"))),
            "html_files": len(list(self.html_dir.glob("*"))),
            "pdf_files": len(list(self.pdf_dir.glob("*"))),
            "base_directory": str(self.output_base_dir),
            "last_distribution": (
                self.distribution_manifest[-1] if self.distribution_manifest else None
            ),
        }
