"""
LAYER 5: AUTOMATION & ORCHESTRATION
Event-driven report generation and automation pipeline.

This layer provides:
- Orchestration of all 4 preceding layers
- Event-driven triggering (scan completion, threshold breaches)
- Workflow automation
- Error handling and retry logic
- Logging and audit trail
- Status tracking and notifications (optional)
"""

from typing import Dict, List, Tuple
from datetime import datetime
import logging
from enum import Enum

from .raw_ingestion import RawScanDataIngestor
from .normalization_engine import DataNormalizationEngine
from .risk_intelligence import RiskIntelligenceEngine
from .report_composition import ReportCompositionEngine

logger = logging.getLogger(__name__)


class ReportGenerationEvent(Enum):
    """Events that trigger report generation"""

    SCAN_COMPLETED = "scan_completed"
    SEVERITY_THRESHOLD_BREACH = "severity_threshold_breach"
    SCHEDULED_REPORT = "scheduled_report"
    MANUAL_TRIGGER = "manual_trigger"
    POLICY_VIOLATION = "policy_violation"


class ReportOrchestrator:
    """
    Orchestrates the complete multi-layer reporting pipeline in response to events.

    Ensures data flows through all layers in correct order:
    Layer 1 -> Raw Ingestion -> Layer 2 -> Normalization -> Layer 3 -> Risk Intelligence
                                                                       -> Layer 4 -> Composition
                                                                                   -> Layer 5 -> Orchestration
                                                                                              -> Layer 6 -> Distribution
    """

    def __init__(self):
        """Initialize report orchestrator"""
        self.ingestor = RawScanDataIngestor()
        self.normalizer = DataNormalizationEngine()
        self.risk_engine = RiskIntelligenceEngine()
        self.composer = ReportCompositionEngine()

        self.pipeline_executions = []  # Audit trail
        self.generated_reports = []  # Report inventory
        self.error_log = []

    def orchestrate_report_generation(
        self,
        event: ReportGenerationEvent,
        raw_scan_data: Dict,
        scan_metadata: Dict,
        report_types: List[str] = None,
        severity_threshold: float = 0.0,
    ) -> Tuple[Dict, bool]:
        """
        Master orchestration function. Executes complete reporting pipeline.

        Args:
            event: Triggering event
            raw_scan_data: Raw data from scanner modules
            scan_metadata: Scan session metadata
            report_types: List of report types to generate (executive, technical, compliance)
            severity_threshold: Severity threshold for generation

        Returns:
            Tuple of (pipeline_output_dict, success_bool)
        """
        execution_id = self._generate_execution_id()
        execution_start = datetime.utcnow()

        logger.info(
            f"Starting report orchestration - Event: {event.value}, Execution ID: {execution_id}"
        )

        try:
            # Step 1: LAYER 1 - Raw Data Ingestion
            logger.info("Step 1: Raw Data Ingestion (Layer 1)")
            ingestion_success = self._execute_layer1_ingestion(raw_scan_data)
            if not ingestion_success:
                self._record_execution_failure(execution_id, "Ingestion failed")
                return {}, False

            # Step 2: LAYER 2 - Data Normalization
            logger.info("Step 2: Data Normalization (Layer 2)")
            norm_output, norm_success = self._execute_layer2_normalization()
            if not norm_success:
                self._record_execution_failure(execution_id, "Normalization failed")
                return {}, False

            normalized_assets = norm_output.get("assets", [])
            normalized_vulns = norm_output.get("vulnerabilities", [])

            # Check severity threshold
            if not self._check_severity_threshold(normalized_vulns, severity_threshold):
                logger.info("Severity threshold not met - skipping report generation")
                return {"reason": "Threshold not met"}, True

            # Step 3: LAYER 3 - Risk Intelligence
            logger.info("Step 3: Risk Intelligence & Context (Layer 3)")
            risk_output, risk_success = self._execute_layer3_risk_intelligence(
                normalized_assets, normalized_vulns
            )
            if not risk_success:
                self._record_execution_failure(execution_id, "Risk calculation failed")
                return {}, False

            enriched_assets = risk_output.get("risk_enriched_assets", [])
            enriched_vulns = risk_output.get("risk_enriched_vulnerabilities", [])
            risk_summary = risk_output.get("risk_summary", {})
            recommendations = risk_output.get("risk_recommendations", [])

            # Step 4: LAYER 4 - Report Composition
            logger.info("Step 4: Report Composition (Layer 4)")
            if not report_types:
                report_types = ["executive", "technical", "compliance"]

            composed_reports = self._execute_layer4_composition(
                report_types,
                enriched_assets,
                enriched_vulns,
                normalized_assets,
                risk_summary,
                recommendations,
                scan_metadata,
            )

            # Step 5: Record execution
            execution_duration = (datetime.utcnow() - execution_start).total_seconds()
            execution_record = {
                "execution_id": execution_id,
                "event": event.value,
                "timestamp": execution_start.isoformat(),
                "duration_seconds": execution_duration,
                "status": "success",
                "reports_generated": len(composed_reports),
                "assets_processed": len(enriched_assets),
                "vulnerabilities_processed": len(enriched_vulns),
                "composed_reports": composed_reports,
            }

            self.pipeline_executions.append(execution_record)
            self.generated_reports.extend(composed_reports)

            logger.info(
                f"Report orchestration completed successfully - "
                f"Execution ID: {execution_id}, Duration: {execution_duration:.2f}s"
            )

            return {
                "execution_id": execution_id,
                "success": True,
                "reports": composed_reports,
                "summary": {
                    "assets_assessed": len(enriched_assets),
                    "vulnerabilities_found": len(enriched_vulns),
                    "reports_generated": len(composed_reports),
                    "execution_duration": f"{execution_duration:.2f}s",
                },
            }, True

        except Exception as e:
            logger.error(f"Unexpected error during orchestration: {str(e)}")
            self._record_execution_failure(execution_id, str(e))
            return {}, False

    # =========================================================================
    # LAYER EXECUTION FUNCTIONS
    # =========================================================================

    def _execute_layer1_ingestion(self, raw_data: Dict) -> bool:
        """Execute Layer 1: Raw Data Ingestion"""
        try:
            # Ingest all raw data types
            if "network_discovery" in raw_data:
                self.ingestor.ingest_from_network_scanner(raw_data["network_discovery"])

            if "device_identification" in raw_data:
                self.ingestor.ingest_from_device_identifier(
                    raw_data["device_identification"]
                )

            if "port_scanning" in raw_data:
                self.ingestor.ingest_from_port_scanner(raw_data["port_scanning"])

            if "vulnerability_scanning" in raw_data:
                self.ingestor.ingest_from_vulnerability_scanner(
                    raw_data["vulnerability_scanning"]
                )

            if "credential_testing" in raw_data:
                self.ingestor.ingest_from_credential_tester(
                    raw_data["credential_testing"]
                )

            # Check ingestion status
            if not self.ingestor.is_valid():
                logger.error(
                    f"Ingestion validation failed: {self.ingestor.validation_errors}"
                )
                self.error_log.append(
                    {
                        "layer": 1,
                        "error": "Validation failed",
                        "details": self.ingestor.validation_errors,
                    }
                )
                return False

            logger.debug(f"Ingestion summary: {self.ingestor.get_ingestion_metadata()}")
            return True

        except Exception as e:
            logger.error(f"Layer 1 execution error: {str(e)}")
            self.error_log.append({"layer": 1, "error": str(e)})
            return False

    def _execute_layer2_normalization(self) -> Tuple[Dict, bool]:
        """Execute Layer 2: Data Normalization"""
        try:
            raw_data_store = self.ingestor.get_all_raw_data()
            normalized_output, success = self.normalizer.normalize_ingested_data(
                raw_data_store
            )

            if not success:
                logger.error("Normalization failed")
                self.error_log.append(
                    {"layer": 2, "error": "Normalization returned false"}
                )
                return {}, False

            logger.debug(
                f"Normalization summary: {normalized_output.get('normalization_summary')}"
            )
            return normalized_output, True

        except Exception as e:
            logger.error(f"Layer 2 execution error: {str(e)}")
            self.error_log.append({"layer": 2, "error": str(e)})
            return {}, False

    def _execute_layer3_risk_intelligence(
        self, normalized_assets: List[Dict], normalized_vulns: List[Dict]
    ) -> Tuple[Dict, bool]:
        """Execute Layer 3: Risk Intelligence & Context"""
        try:
            risk_output, success = self.risk_engine.calculate_contextual_risk(
                normalized_assets, normalized_vulns
            )

            if not success:
                logger.error("Risk calculation failed")
                self.error_log.append(
                    {"layer": 3, "error": "Risk calculation returned false"}
                )
                return {}, False

            logger.debug(f"Risk summary: {risk_output.get('risk_summary')}")
            return risk_output, True

        except Exception as e:
            logger.error(f"Layer 3 execution error: {str(e)}")
            self.error_log.append({"layer": 3, "error": str(e)})
            return {}, False

    def _execute_layer4_composition(
        self,
        report_types: List[str],
        enriched_assets: List[Dict],
        enriched_vulns: List[Dict],
        normalized_assets: List[Dict],
        risk_summary: Dict,
        recommendations: List[str],
        scan_metadata: Dict,
    ) -> List[Dict]:
        """Execute Layer 4: Report Composition"""
        try:
            composed_reports = []

            # Executive Summary Report
            if "executive" in report_types:
                exec_report = self.composer.compose_executive_summary_report(
                    enriched_assets,
                    enriched_vulns,
                    risk_summary,
                    recommendations,
                    scan_metadata,
                )
                if exec_report:
                    composed_reports.append(exec_report)
                    logger.debug("Executive summary report composed")

            # Technical Report
            if "technical" in report_types:
                tech_report = self.composer.compose_technical_report(
                    enriched_assets, enriched_vulns, normalized_assets, scan_metadata
                )
                if tech_report:
                    composed_reports.append(tech_report)
                    logger.debug("Technical report composed")

            # Compliance Report
            if "compliance" in report_types:
                comp_report = self.composer.compose_compliance_audit_report(
                    enriched_assets, enriched_vulns, scan_metadata
                )
                if comp_report:
                    composed_reports.append(comp_report)
                    logger.debug("Compliance report composed")

            return composed_reports

        except Exception as e:
            logger.error(f"Layer 4 execution error: {str(e)}")
            self.error_log.append({"layer": 4, "error": str(e)})
            return []

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    def _check_severity_threshold(self, vulns: List[Dict], threshold: float) -> bool:
        """Check if vulnerabilities meet severity threshold"""
        if threshold <= 0:
            return True  # No threshold

        high_risk_vulns = [v for v in vulns if v.get("risk_score", 0) >= threshold]
        found = len(high_risk_vulns) > 0

        if not found:
            logger.info(f"No vulnerabilities above threshold {threshold}")

        return found

    def _generate_execution_id(self) -> str:
        """Generate unique execution ID"""
        from datetime import datetime
        import uuid

        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        return f"REP_{timestamp}_{unique_id}"

    def _record_execution_failure(self, execution_id: str, reason: str):
        """Record failed execution"""
        failure_record = {
            "execution_id": execution_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "failed",
            "reason": reason,
        }
        self.pipeline_executions.append(failure_record)
        self.error_log.append({"execution": execution_id, "error": reason})
        logger.error(f"Execution {execution_id} failed: {reason}")

    # =========================================================================
    # DATA RETRIEVAL FOR LAYER 6
    # =========================================================================

    def get_composed_reports(self) -> List[Dict]:
        """Get compiled reports for distribution"""
        return self.generated_reports.copy()

    def get_execution_history(self, limit: int = 10) -> List[Dict]:
        """Get execution history"""
        return self.pipeline_executions[-limit:]

    def get_error_history(self) -> List[Dict]:
        """Get error log"""
        return self.error_log.copy()

    def get_pipeline_status(self) -> Dict:
        """Get overall pipeline status"""
        total = len(self.pipeline_executions)
        successful = len(
            [e for e in self.pipeline_executions if e.get("status") == "success"]
        )

        return {
            "total_executions": total,
            "successful": successful,
            "failed": total - successful,
            "reports_generated": len(self.generated_reports),
            "error_count": len(self.error_log),
            "last_execution": (
                self.pipeline_executions[-1] if self.pipeline_executions else None
            ),
        }
