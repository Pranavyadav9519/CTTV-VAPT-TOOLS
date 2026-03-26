"""
LAYER 2: DATA NORMALIZATION ENGINE
Converts all raw scan outputs into a unified, tool-agnostic schema.

This layer ensures consistency regardless of scanning method or module.
The normalized schema is the ONLY input allowed for subsequent reporting layers.

Normalized schema:
- asset_id: unique asset identifier
- asset_type: camera, dvr, nvr, network_device, etc.
- ip_address: IP address
- mac_address: MAC address
- ports: list of normalized ports
- services: identified services
- vulnerabilities: list of normalized vulnerabilities
- timestamp: discovery time
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging
import hashlib

logger = logging.getLogger(__name__)


class DataNormalizationEngine:
    """
    Converts raw, tool-specific scan data into normalized, enterprise-standard schema.

    Ensures:
    - Consistent structure across all data sources
    - Tool independence (scanner-agnostic format)
    - Complete audit trail (preserves original raw data reference)
    - Deduplication and conflict resolution
    """

    def __init__(self):
        """Initialize normalization engine"""
        self.normalized_assets = {}  # keyed by asset_id
        self.normalized_vulnerabilities = []
        self.normalization_log = []
        self.deduplication_map = {}  # maps raw identifiers to normalized asset_ids
        self.conflicts_detected = []

    def normalize_ingested_data(self, raw_data_store: Dict) -> Tuple[Dict, bool]:
        """
        Master normalization function. Processes all raw data and produces normalized schema.

        Args:
            raw_data_store: Complete raw data store from Layer 1

        Returns:
            Tuple of (normalized_data_dict, success_bool)
        """
        try:
            # Phase 1: Parse network discovery and build asset inventory
            self._normalize_network_discovery(raw_data_store.get("network_discovery"))

            # Phase 2: Enrich assets with device identification
            self._normalize_device_identification(
                raw_data_store.get("device_identification")
            )

            # Phase 3: Add port information
            self._normalize_port_scanning(raw_data_store.get("port_scanning"))

            # Phase 4: Add vulnerabilities
            self._normalize_vulnerability_scanning(
                raw_data_store.get("vulnerability_scanning")
            )

            # Phase 5: Add authentication/credential information
            self._normalize_credential_testing(raw_data_store.get("credential_testing"))

            # Phase 6: Validate and finalize
            self._validate_normalized_data()

            normalized_output = {
                "assets": list(self.normalized_assets.values()),
                "vulnerabilities": self.normalized_vulnerabilities,
                "normalization_summary": self._get_normalization_summary(),
                "conflicts": self.conflicts_detected,
            }

            logger.info(
                f"Data normalization completed: {len(self.normalized_assets)} assets normalized"
            )
            return normalized_output, True

        except Exception as e:
            logger.error(f"Error during data normalization: {str(e)}")
            return {}, False

    # =========================================================================
    # NORMALIZATION PHASE FUNCTIONS
    # =========================================================================

    def _normalize_network_discovery(self, network_raw: Optional[Dict]):
        """
        Phase 1: Create normalized asset entries from network discovery results.
        """
        if not network_raw:
            self.normalization_log.append("Warning: No network discovery data provided")
            return

        raw_output = network_raw.get("raw_output", {})
        hosts = raw_output.get("hosts", [])

        for host in hosts:
            asset_id = self._generate_asset_id(host.get("ip"), host.get("mac"))

            normalized_asset = {
                "asset_id": asset_id,
                "asset_type": "unknown",  # Will be enriched in Phase 2
                "ip_address": host.get("ip"),
                "mac_address": host.get("mac"),
                "hostname": None,
                "manufacturer": None,
                "model": None,
                "firmware_version": None,
                "os_info": None,
                "criticality": "unknown",  # Will be set by risk engine (Layer 3)
                "network_segment": self._infer_network_segment(host.get("ip")),
                "authentication_state": "unknown",  # Will be enriched in Phase 5
                "ports": [],
                "services": [],
                "vulnerabilities": [],
                "discovery_time": datetime.utcnow().isoformat(),
                "raw_data_references": {"network_discovery": True},
            }

            self.normalized_assets[asset_id] = normalized_asset
            self.deduplication_map[f"network_{host.get('ip')}_{host.get('mac')}"] = (
                asset_id
            )

        self.normalization_log.append(
            f"Phase 1: Normalized {len(hosts)} hosts from network discovery"
        )

    def _normalize_device_identification(self, device_raw: Optional[Dict]):
        """
        Phase 2: Enrich normalized assets with device identification details.
        """
        if not device_raw:
            self.normalization_log.append(
                "Warning: No device identification data provided"
            )
            return

        raw_output = device_raw.get("raw_output", {})
        results = raw_output.get("identification_results", [])

        for result in results:
            asset_id = self._find_or_create_asset(result.get("ip"), result.get("mac"))
            asset = self.normalized_assets[asset_id]

            # Enrich with identification results
            asset["asset_type"] = result.get("identified_device_type", "unknown")
            asset["manufacturer"] = result.get("manufacturer")
            asset["model"] = result.get("model")
            asset["hostname"] = result.get("hostname")

            # Store confidence score for later processing
            asset["identification_confidence"] = result.get("confidence", 0.0)

            # Flag if CCTV/DVR device
            asset["is_cctv"] = asset["asset_type"].lower() in [
                "camera",
                "dvr",
                "nvr",
                "ndr",
            ]

            asset["raw_data_references"]["device_identification"] = True

        self.normalization_log.append(
            f"Phase 2: Enriched {len(results)} devices with identification data"
        )

    def _normalize_port_scanning(self, port_raw: Optional[Dict]):
        """
        Phase 3: Add normalized port and service information to assets.
        """
        if not port_raw:
            self.normalization_log.append("Warning: No port scanning data provided")
            return

        raw_output = port_raw.get("raw_output", {})
        hosts = raw_output.get("hosts", [])

        for host in hosts:
            asset_id = self._find_or_create_asset(host.get("ip"), host.get("mac"))
            asset = self.normalized_assets[asset_id]

            ports = host.get("ports", [])
            for port_info in ports:
                normalized_port = {
                    "port_number": port_info.get("number"),
                    "protocol": port_info.get("protocol", "tcp"),
                    "state": port_info.get("state", "open"),
                    "service_name": port_info.get("service"),
                    "service_version": port_info.get("version"),
                    "banner": port_info.get("banner"),
                    "is_encrypted": self._detect_encryption(
                        port_info.get("service", "")
                    ),
                }

                asset["ports"].append(normalized_port)

                # Track unique services
                if port_info.get("service") not in asset["services"]:
                    asset["services"].append(port_info.get("service", "unknown"))

            asset["raw_data_references"]["port_scanning"] = True

        self.normalization_log.append(
            f"Phase 3: Normalized ports for {len(hosts)} hosts"
        )

    def _normalize_vulnerability_scanning(self, vuln_raw: Optional[Dict]):
        """
        Phase 4: Add normalized vulnerability data.
        """
        if not vuln_raw:
            self.normalization_log.append(
                "Warning: No vulnerability scanning data provided"
            )
            return

        raw_output = vuln_raw.get("raw_output", {})
        vulnerabilities = raw_output.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            ip = vuln.get("ip")
            asset_id = self._find_asset_by_ip(ip)

            if not asset_id:
                # Create minimal asset entry if IP not already discovered
                asset_id = self._create_asset_from_vuln(vuln)

            normalized_vuln = {
                "vulnerability_id": self._generate_vuln_id(vuln),
                "asset_id": asset_id,
                "title": vuln.get("title", "Unknown Vulnerability"),
                "description": vuln.get("description"),
                "evidence": vuln.get("evidence"),
                "cve_id": vuln.get("cve_id"),
                "cvss_score": (
                    float(vuln.get("cvss", 0.0)) if vuln.get("cvss") else None
                ),
                "severity": self._normalize_severity(vuln.get("cvss", 0.0)),
                "cwe_id": vuln.get("cwe_id"),
                "affected_service": vuln.get("service"),
                "affected_port": vuln.get("port"),
                "remediation": vuln.get("remediation"),
                "references": vuln.get("references", []),
                "discovered_at": datetime.utcnow().isoformat(),
                "raw_tool": "VulnerabilityScanner",
            }

            self.normalized_vulnerabilities.append(normalized_vuln)

            # Add vulnerability reference to asset
            if asset_id in self.normalized_assets:
                self.normalized_assets[asset_id]["vulnerabilities"].append(
                    normalized_vuln["vulnerability_id"]
                )

            # Check for exploit availability
            if self._check_exploit_available(vuln.get("cve_id")):
                normalized_vuln["exploit_available"] = True

        self.normalization_log.append(
            f"Phase 4: Normalized {len(vulnerabilities)} vulnerabilities"
        )

    def _normalize_credential_testing(self, cred_raw: Optional[Dict]):
        """
        Phase 5: Enrich assets with authentication state from credential testing.
        """
        if not cred_raw:
            self.normalization_log.append(
                "Warning: No credential testing data provided"
            )
            return

        raw_output = cred_raw.get("raw_output", {})
        test_results = raw_output.get("test_results", [])

        for result in test_results:
            asset_id = self._find_or_create_asset(result.get("ip"))
            asset = self.normalized_assets[asset_id]

            if result.get("default_creds_found"):
                asset["authentication_state"] = "unauthenticated"
                asset["has_default_credentials"] = True
            else:
                asset["authentication_state"] = "authenticated"

            # Store credential test results for risk calculation
            asset["credential_test_results"] = result.get("credentials_tested", [])
            asset["raw_data_references"]["credential_testing"] = True

        self.normalization_log.append(
            f"Phase 5: Enriched {len(test_results)} assets with auth data"
        )

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    def _generate_asset_id(self, ip: str, mac: Optional[str] = None) -> str:
        """Generate unique asset ID from IP and MAC"""
        if mac:
            key = f"{ip}_{mac}"
        else:
            key = ip

        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _find_or_create_asset(self, ip: str, mac: Optional[str] = None) -> str:
        """Find existing asset by IP or create new one"""
        asset_id = self._generate_asset_id(ip, mac)

        if asset_id not in self.normalized_assets:
            self.normalized_assets[asset_id] = {
                "asset_id": asset_id,
                "asset_type": "unknown",
                "ip_address": ip,
                "mac_address": mac,
                "hostname": None,
                "manufacturer": None,
                "model": None,
                "firmware_version": None,
                "os_info": None,
                "criticality": "unknown",
                "network_segment": self._infer_network_segment(ip),
                "authentication_state": "unknown",
                "ports": [],
                "services": [],
                "vulnerabilities": [],
                "discovery_time": datetime.utcnow().isoformat(),
                "raw_data_references": {},
            }

        return asset_id

    def _find_asset_by_ip(self, ip: str) -> Optional[str]:
        """Find asset ID by IP address"""
        asset_id = self._generate_asset_id(ip)
        return asset_id if asset_id in self.normalized_assets else None

    def _create_asset_from_vuln(self, vuln: Dict) -> str:
        """Create minimal asset entry when vulnerability references new IP"""
        ip = vuln.get("ip")
        asset_id = self._find_or_create_asset(ip)
        return asset_id

    def _generate_vuln_id(self, vuln: Dict) -> str:
        """Generate unique vulnerability ID"""
        key = f"{vuln.get('ip')}_{vuln.get('port')}_{vuln.get('cve_id', 'unknown')}"
        return hashlib.sha256(key.encode()).hexdigest()[:12]

    def _infer_network_segment(self, ip: str) -> str:
        """Infer network segment from IP (external vs internal)"""
        if not ip:
            return "unknown"

        parts = ip.split(".")
        if len(parts) != 4:
            return "unknown"

        first_octet = int(parts[0])

        # RFC 1918 private ranges
        if first_octet in [10]:
            return "internal"
        elif first_octet == 172:
            second = int(parts[1])
            if 16 <= second <= 31:
                return "internal"
        elif first_octet == 192 and int(parts[1]) == 168:
            return "internal"
        elif first_octet == 127:
            return "internal"

        return "external"

    def _detect_encryption(self, service_name: str) -> bool:
        """Detect if service uses encryption"""
        encrypted_services = ["https", "rtsps", "tls", "ssl", "ssh", "sftp"]
        return (
            any(enc in service_name.lower() for enc in encrypted_services)
            if service_name
            else False
        )

    def _normalize_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score >= 0.1:
            return "low"
        else:
            return "info"

    def _check_exploit_available(self, cve_id: Optional[str]) -> bool:
        """Check if exploit is publicly available for CVE"""
        # In production, query real exploit databases (Exploit-DB, NVD, etc.)
        if not cve_id:
            return False

        # Placeholder: Common CVEs with known exploits
        common_exploits = ["CVE-2019-8943", "CVE-2020-5410", "CVE-2021-3156"]
        return cve_id in common_exploits

    def _validate_normalized_data(self):
        """Validate normalized data integrity"""
        for asset in self.normalized_assets.values():
            # Check for missing critical fields
            if not asset["ip_address"]:
                self.conflicts_detected.append(
                    {"type": "missing_ip", "asset_id": asset["asset_id"]}
                )

            # Warn about unknown asset types
            if asset["asset_type"] == "unknown":
                self.normalization_log.append(
                    f"Warning: Asset {asset['ip_address']} has unknown type"
                )

    def _get_normalization_summary(self) -> Dict:
        """Get summary of normalization process"""
        return {
            "total_assets_normalized": len(self.normalized_assets),
            "total_vulnerabilities_normalized": len(self.normalized_vulnerabilities),
            "normalization_stages": len(self.normalization_log),
            "conflicts_detected": len(self.conflicts_detected),
            "normalization_log": self.normalization_log,
        }

    # =========================================================================
    # DATA RETRIEVAL FOR DOWNSTREAM LAYERS
    # =========================================================================

    def get_normalized_assets(self) -> List[Dict]:
        """Get all normalized assets for risk calculation"""
        return list(self.normalized_assets.values())

    def get_normalized_vulnerabilities(self) -> List[Dict]:
        """Get all normalized vulnerabilities for risk calculation"""
        return self.normalized_vulnerabilities.copy()

    def get_asset_by_id(self, asset_id: str) -> Optional[Dict]:
        """Get specific asset"""
        return self.normalized_assets.get(asset_id)
