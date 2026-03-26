"""
LAYER 1: RAW SCAN DATA INGESTION
Accepts and validates raw outputs from multiple scanning modules.
Raw data is treated as untrusted, noisy, and tool-specific.

This layer provides:
- Input validation and schema verification
- Raw data storage for audit trail
- Tool-specific raw data handling
- Normalization entry point (passes to Layer 2)
"""

from typing import Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RawScanDataIngestor:
    """
    Accepts raw scanner outputs from multiple scanning modules.

    Raw data sources:
    - Network Scanner (ARP results, host discovery)
    - Device Identifier (banner, fingerprints)
    - Port Scanner (nmap/custom port scan results)
    - Vulnerability Scanner (CVE matches, test results)
    - Credential Tester (auth attempts, results)
    """

    def __init__(self):
        """Initialize raw data ingestor"""
        self.ingestion_id = None
        self.raw_data_store = {}
        self.validation_errors = []
        self.metadata = {
            "ingestion_timestamp": datetime.utcnow().isoformat(),
            "source_modules": [],
            "total_items": 0,
        }

    def ingest_from_network_scanner(self, scanner_output: Dict) -> bool:
        """
        Accept raw output from Network Scanner module.

        Expected format (tool-specific, raw, unvalidated):
        {
            'scan_uuid': str,
            'network_range': str,
            'scan_start': timestamp,
            'scan_end': timestamp,
            'hosts': [
                {
                    'ip': str,
                    'mac': str,
                    'online': bool,
                    'response_time': float
                }
            ]
        }
        """
        try:
            if not self._validate_network_scanner_input(scanner_output):
                return False

            self.raw_data_store["network_discovery"] = {
                "tool": "NetworkScanner",
                "raw_output": scanner_output,
                "ingested_at": datetime.utcnow().isoformat(),
                "record_count": len(scanner_output.get("hosts", [])),
            }

            self.metadata["source_modules"].append("network_scanner")
            self.metadata["total_items"] += len(scanner_output.get("hosts", []))

            logger.info(
                f"Ingested raw network discovery data: "
                f"{len(scanner_output.get('hosts', []))} hosts"
            )
            return True
        except Exception as e:
            logger.error(f"Error ingesting network scanner data: {str(e)}")
            self.validation_errors.append(f"network_scanner: {str(e)}")
            return False

    def ingest_from_device_identifier(self, identifier_output: Dict) -> bool:
        """
        Accept raw output from Device Identifier module.

        Expected format (raw, tool-specific):
        {
            'identification_results': [
                {
                    'ip': str,
                    'mac': str,
                    'identified_device_type': str,
                    'manufacturer': str,
                    'model': str,
                    'confidence': float,
                    'banners': [str],
                    'fingerprints': [str],
                    'http_headers': Dict
                }
            ]
        }
        """
        try:
            if not self._validate_device_identifier_input(identifier_output):
                return False

            self.raw_data_store["device_identification"] = {
                "tool": "DeviceIdentifier",
                "raw_output": identifier_output,
                "ingested_at": datetime.utcnow().isoformat(),
                "record_count": len(
                    identifier_output.get("identification_results", [])
                ),
            }

            self.metadata["source_modules"].append("device_identifier")
            self.metadata["total_items"] += len(
                identifier_output.get("identification_results", [])
            )

            logger.info(
                f"Ingested raw device identification data: "
                f"{len(identifier_output.get('identification_results', []))} devices"
            )
            return True
        except Exception as e:
            logger.error(f"Error ingesting device identifier data: {str(e)}")
            self.validation_errors.append(f"device_identifier: {str(e)}")
            return False

    def ingest_from_port_scanner(self, port_scan_output: Dict) -> bool:
        """
        Accept raw output from Port Scanner module (nmap-based).

        Expected format (raw, tool-specific):
        {
            'scan_info': {...},
            'hosts': [
                {
                    'ip': str,
                    'mac': str,
                    'status': str,
                    'ports': [
                        {
                            'number': int,
                            'protocol': str,
                            'state': str,
                            'service': str,
                            'version': str,
                            'banner': str
                        }
                    ]
                }
            ]
        }
        """
        try:
            if not self._validate_port_scanner_input(port_scan_output):
                return False

            self.raw_data_store["port_scanning"] = {
                "tool": "PortScanner",
                "raw_output": port_scan_output,
                "ingested_at": datetime.utcnow().isoformat(),
                "record_count": len(port_scan_output.get("hosts", [])),
            }

            self.metadata["source_modules"].append("port_scanner")
            self.metadata["total_items"] += len(port_scan_output.get("hosts", []))

            logger.info(
                f"Ingested raw port scan data: "
                f"{len(port_scan_output.get('hosts', []))} hosts scanned"
            )
            return True
        except Exception as e:
            logger.error(f"Error ingesting port scanner data: {str(e)}")
            self.validation_errors.append(f"port_scanner: {str(e)}")
            return False

    def ingest_from_vulnerability_scanner(self, vuln_scan_output: Dict) -> bool:
        """
        Accept raw output from Vulnerability Scanner module.

        Expected format (raw, tool-specific):
        {
            'scan_id': str,
            'vulnerabilities': [
                {
                    'ip': str,
                    'port': int,
                    'service': str,
                    'vuln_type': str,
                    'title': str,
                    'description': str,
                    'cve_id': str,
                    'cvss': float,
                    'evidence': str,
                    'remediation': str
                }
            ]
        }
        """
        try:
            if not self._validate_vulnerability_scanner_input(vuln_scan_output):
                return False

            self.raw_data_store["vulnerability_scanning"] = {
                "tool": "VulnerabilityScanner",
                "raw_output": vuln_scan_output,
                "ingested_at": datetime.utcnow().isoformat(),
                "record_count": len(vuln_scan_output.get("vulnerabilities", [])),
            }

            self.metadata["source_modules"].append("vulnerability_scanner")
            self.metadata["total_items"] += len(
                vuln_scan_output.get("vulnerabilities", [])
            )

            logger.info(
                f"Ingested raw vulnerability scan data: "
                f"{len(vuln_scan_output.get('vulnerabilities', []))} vulnerabilities"
            )
            return True
        except Exception as e:
            logger.error(f"Error ingesting vulnerability scanner data: {str(e)}")
            self.validation_errors.append(f"vulnerability_scanner: {str(e)}")
            return False

    def ingest_from_credential_tester(self, credential_test_output: Dict) -> bool:
        """
        Accept raw output from Credential Tester module.

        Expected format (raw, tool-specific):
        {
            'test_results': [
                {
                    'ip': str,
                    'port': int,
                    'service': str,
                    'credentials_tested': [{username, password, success}],
                    'default_creds_found': bool,
                    'test_time': timestamp
                }
            ]
        }
        """
        try:
            if not self._validate_credential_tester_input(credential_test_output):
                return False

            self.raw_data_store["credential_testing"] = {
                "tool": "CredentialTester",
                "raw_output": credential_test_output,
                "ingested_at": datetime.utcnow().isoformat(),
                "record_count": len(credential_test_output.get("test_results", [])),
            }

            self.metadata["source_modules"].append("credential_tester")
            self.metadata["total_items"] += len(
                credential_test_output.get("test_results", [])
            )

            logger.info(
                f"Ingested raw credential test data: "
                f"{len(credential_test_output.get('test_results', []))} tests"
            )
            return True
        except Exception as e:
            logger.error(f"Error ingesting credential tester data: {str(e)}")
            self.validation_errors.append(f"credential_tester: {str(e)}")
            return False

    # =========================================================================
    # INPUT VALIDATION METHODS
    # =========================================================================

    def _validate_network_scanner_input(self, data: Dict) -> bool:
        """Validate structure of network scanner output"""
        if not isinstance(data, dict):
            self.validation_errors.append("Network scanner output must be a dictionary")
            return False

        if "hosts" not in data:
            self.validation_errors.append(
                "Network scanner output missing 'hosts' field"
            )
            return False

        if not isinstance(data["hosts"], list):
            self.validation_errors.append("Network scanner 'hosts' must be a list")
            return False

        return True

    def _validate_device_identifier_input(self, data: Dict) -> bool:
        """Validate structure of device identifier output"""
        if not isinstance(data, dict):
            self.validation_errors.append(
                "Device identifier output must be a dictionary"
            )
            return False

        if "identification_results" not in data:
            self.validation_errors.append(
                "Device identifier output missing 'identification_results' field"
            )
            return False

        if not isinstance(data["identification_results"], list):
            self.validation_errors.append(
                "Device identifier 'identification_results' must be a list"
            )
            return False

        return True

    def _validate_port_scanner_input(self, data: Dict) -> bool:
        """Validate structure of port scanner output"""
        if not isinstance(data, dict):
            self.validation_errors.append("Port scanner output must be a dictionary")
            return False

        if "hosts" not in data:
            self.validation_errors.append("Port scanner output missing 'hosts' field")
            return False

        if not isinstance(data["hosts"], list):
            self.validation_errors.append("Port scanner 'hosts' must be a list")
            return False

        return True

    def _validate_vulnerability_scanner_input(self, data: Dict) -> bool:
        """Validate structure of vulnerability scanner output"""
        if not isinstance(data, dict):
            self.validation_errors.append(
                "Vulnerability scanner output must be a dictionary"
            )
            return False

        if "vulnerabilities" not in data:
            self.validation_errors.append(
                "Vulnerability scanner output missing 'vulnerabilities' field"
            )
            return False

        if not isinstance(data["vulnerabilities"], list):
            self.validation_errors.append(
                "Vulnerability scanner 'vulnerabilities' must be a list"
            )
            return False

        return True

    def _validate_credential_tester_input(self, data: Dict) -> bool:
        """Validate structure of credential tester output"""
        if not isinstance(data, dict):
            self.validation_errors.append(
                "Credential tester output must be a dictionary"
            )
            return False

        if "test_results" not in data:
            self.validation_errors.append(
                "Credential tester output missing 'test_results' field"
            )
            return False

        if not isinstance(data["test_results"], list):
            self.validation_errors.append(
                "Credential tester 'test_results' must be a list"
            )
            return False

        return True

    # =========================================================================
    # DATA RETRIEVAL METHODS
    # =========================================================================

    def get_raw_data_by_source(self, source: str) -> Optional[Dict]:
        """Retrieve raw data for a specific source module"""
        return self.raw_data_store.get(source)

    def get_all_raw_data(self) -> Dict:
        """Get all ingested raw data (for Layer 2 processing)"""
        return self.raw_data_store.copy()

    def get_ingestion_metadata(self) -> Dict:
        """Get metadata about ingestion process"""
        return self.metadata.copy()

    def get_validation_summary(self) -> Dict:
        """Get summary of validation results"""
        return {
            "sources_processed": len(self.metadata["source_modules"]),
            "total_items": self.metadata["total_items"],
            "validation_errors": self.validation_errors,
            "has_errors": len(self.validation_errors) > 0,
            "ingestion_timestamp": self.metadata["ingestion_timestamp"],
        }

    def is_valid(self) -> bool:
        """Check if all ingested data is valid"""
        return len(self.validation_errors) == 0
