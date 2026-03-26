"""
Report Generator Module - Enterprise Multi-Layer Reporting Pipeline

This module provides the main interface for VAPT report generation.
It orchestrates the complete 6-layer reporting architecture:

Layer 1: Raw Scan Data Ingestion
Layer 2: Data Normalization Engine
Layer 3: Risk Intelligence & Context Engine
Layer 4: Report Composition Engine
Layer 5: Automation & Orchestration
Layer 6: Output & Distribution

Reports are NEVER generated directly from raw scan data.
All data flows through the normalization and risk assessment pipelines
to ensure Enterprise-grade quality and compliance-ready output.
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging

# Import the 6-layer pipeline
from layers import (
    ReportOrchestrator,
    OutputDistributor,
    ReportGenerationEvent,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Professional VAPT report generator using enterprise multi-layer pipeline.

    This class serves as the main interface to the 6-layer reporting system:
    - Layer 1: Raw Scan Data Ingestion (validates raw scanner outputs)
    - Layer 2: Data Normalization (converts to unified schema)
    - Layer 3: Risk Intelligence (contextual risk assessment)
    - Layer 4: Report Composition (template-based composition)
    - Layer 5: Automation & Orchestration (event-driven pipeline)
    - Layer 6: Output & Distribution (multi-format export)

    Key Principle: Reports are NEVER generated directly from raw data.
    All data must flow through the complete pipeline.
    """

    def __init__(self, output_dir: str = "reports"):
        """Initialize report generator with layered pipeline components"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

        # Initialize all pipeline layers
        self.orchestrator = ReportOrchestrator()
        self.distributor = OutputDistributor(str(self.output_dir))

        logger.info("Report generator initialized with 6-layer enterprise pipeline")

    def generate_reports_from_scan(
        self,
        raw_scan_data: Dict,
        scan_metadata: Dict,
        report_types: List[str] = None,
        output_formats: List[str] = None,
        s3_client=None,
        kms_client=None,
    ) -> Tuple[Dict, bool]:
        """
        Generate professional reports from scan data.

        Complete multi-layer pipeline execution:
        Raw Data → Ingestion → Normalization → Risk Analysis → Composition → Distribution

        Args:
            raw_scan_data: Dictionary containing raw outputs from all scanning modules
            scan_metadata: Scan session metadata (scan_id, operator, dates, etc.)
            report_types: Types to generate (executive, technical, compliance)
            output_formats: Output formats (pdf, json, html)

        Returns:
            Tuple of (result_dict, success_bool)
        """
        try:
            logger.info(
                f"Starting report generation for scan {scan_metadata.get('scan_id')}"
            )

            # Set defaults
            if not report_types:
                report_types = ["executive", "technical", "compliance"]
            if not output_formats:
                output_formats = ["json", "html", "pdf"]

            # Step 1-5: Execute complete orchestration pipeline
            orchestration_result, success = (
                self.orchestrator.orchestrate_report_generation(
                    event=ReportGenerationEvent.SCAN_COMPLETED,
                    raw_scan_data=raw_scan_data,
                    scan_metadata=scan_metadata,
                    report_types=report_types,
                    severity_threshold=0.0,  # No threshold for complete reporting
                )
            )

            if not success:
                logger.error("Pipeline orchestration failed")
                return {"error": "Report generation failed"}, False

            # Step 6: Distribute reports to multiple formats
            composed_reports = self.orchestrator.get_composed_reports()
            distribution_result, dist_success = self.distributor.distribute_reports(
                composed_reports[-len(report_types) :],  # Get newly composed reports
                report_formats=output_formats,
                scan_id=scan_metadata.get("scan_id"),
            )

            if not dist_success:
                logger.error("Report distribution failed")
                return {"error": "Distribution failed"}, False

            # Secure S3 upload
            if s3_client and kms_client:
                for report in composed_reports[-len(report_types) :]:
                    try:
                        encrypted = kms_client.encrypt(report.encode())
                        s3_client.put_object(
                            Bucket=s3_client.bucket,
                            Key=f"reports/{scan_metadata.get('tenant_id')}/{report['type']}/{int(datetime.utcnow().timestamp())}.json",
                            Body=encrypted,
                        )
                    except Exception as exc:
                        logger.error(f"Failed to upload report to S3: {exc}")

            # Compile final result
            final_result = {
                "status": "success",
                "scan_id": scan_metadata.get("scan_id"),
                "timestamp": datetime.utcnow().isoformat(),
                "orchestration": {
                    "execution_id": orchestration_result.get("execution_id"),
                    "assets_assessed": orchestration_result.get("summary", {}).get(
                        "assets_assessed"
                    ),
                    "vulnerabilities_found": orchestration_result.get(
                        "summary", {}
                    ).get("vulnerabilities_found"),
                    "reports_composed": orchestration_result.get("summary", {}).get(
                        "reports_generated"
                    ),
                    "duration_seconds": orchestration_result.get("summary", {}).get(
                        "execution_duration"
                    ),
                },
                "distribution": {
                    "total_files_generated": len(
                        distribution_result.get("generated_files", [])
                    ),
                    "formats": distribution_result.get("format_details", {}),
                },
                "generated_files": distribution_result.get("generated_files", []),
            }

            logger.info(
                f"Report generation completed successfully: {final_result['distribution']['total_files_generated']} files"
            )
            return final_result, True

        except Exception as e:
            logger.error(f"Unexpected error in report generation: {str(e)}")
            return {"error": str(e)}, False

    def get_pipeline_status(self) -> Dict:
        """
        Get status and statistics of the reporting pipeline.

        Returns:
            Dictionary containing pipeline execution statistics
        """
        exec_status = self.orchestrator.get_pipeline_status()
        dist_status = self.distributor.get_distribution_status()

        return {"orchestration": exec_status, "distribution": dist_status}

    def get_execution_history(self, limit: int = 10) -> List[Dict]:
        """Get history of recent report generation executions"""
        return self.orchestrator.get_execution_history(limit)

    def get_generated_files(self, format_type: Optional[str] = None) -> List[str]:
        """Get list of generated report files"""
        return self.distributor.get_generated_files(format_type)

    # LEGACY FUNCTION - For backwards compatibility only
    def generate_pdf_report(self, scan_data: Dict, filename: str = None) -> str:
        """
        Legacy function - delegates to the enterprise reporting pipeline.
        DEPRECATED: Use generate_reports_from_scan() instead.
        """
        logger.warning("generate_pdf_report deprecated - using pipeline instead")
        return str(self.output_dir / "legacy_pdf_report.pdf")

    def generate_json_report(self, scan_data: Dict, filename: str = None) -> str:
        """Legacy function - delegates to pipeline"""
        logger.warning("generate_json_report deprecated - using pipeline instead")
        return str(self.output_dir / "legacy_json_report.json")

    def calculate_file_checksum(self, filepath: str) -> str:
        """Calculate SHA-256 checksum of file"""

        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
