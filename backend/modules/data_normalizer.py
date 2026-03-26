"""
Layer 2: Data Normalization Engine
Converts all raw scan outputs into a unified, tool-agnostic schema
"""

import logging
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class NormalizedAsset:
    """Normalized asset data structure"""

    asset_id: str
    asset_type: str  # camera, dvr, nvr, network_device
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    os_info: Optional[str] = None
    criticality: str = "medium"  # critical, high, medium, low
    network_segment: str = "internal"  # internal, dmz, external
    authentication_state: str = "unknown"  # authenticated, unauthenticated, mixed
    ports: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NormalizedScanData:
    """Container for fully normalized scan data"""

    scan_id: str
    normalized_assets: List[NormalizedAsset] = field(default_factory=list)
    normalization_metadata: Dict[str, Any] = field(default_factory=dict)
    normalized_at: datetime = field(default_factory=datetime.utcnow)


class DataNormalizationEngine:
    """
    Layer 2: Data Normalization Engine
    Converts raw scan outputs into unified, tool-agnostic normalized schema
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Asset type mappings from various identification methods
        self.asset_type_mappings = {
            "camera": ["camera", "ip_camera", "surveillance_camera"],
            "dvr": ["dvr", "digital_video_recorder", "video_recorder"],
            "nvr": ["nvr", "network_video_recorder", "video_recorder"],
            "network_device": ["switch", "router", "access_point", "network_device"],
        }

        # Criticality assessment rules
        self.criticality_rules = {
            "high": ["camera", "dvr", "nvr"],
            "medium": ["network_device"],
            "low": [],
        }

    def normalize_scan_data(self, raw_scan_data) -> NormalizedScanData:
        """
        Normalize raw scan data into unified schema

        Args:
            raw_scan_data: RawScanData object from ingestion layer

        Returns:
            NormalizedScanData with unified schema
        """
        try:
            normalized_assets = []

            # Process each raw device
            raw_devices = raw_scan_data.device_identification.get("raw_devices", [])

            for raw_device in raw_devices:
                normalized_asset = self._normalize_device(raw_device, raw_scan_data)
                if normalized_asset:
                    normalized_assets.append(normalized_asset)

            # Create normalization metadata
            metadata = {
                "original_scan_id": raw_scan_data.scan_id,
                "normalization_timestamp": datetime.utcnow().isoformat(),
                "total_raw_devices": len(raw_devices),
                "total_normalized_assets": len(normalized_assets),
                "normalization_engine_version": "1.0",
                "data_sources_processed": list(raw_scan_data.__dict__.keys()),
            }

            normalized_data = NormalizedScanData(
                scan_id=raw_scan_data.scan_id,
                normalized_assets=normalized_assets,
                normalization_metadata=metadata,
            )

            self.logger.info(
                f"Successfully normalized {len(normalized_assets)} assets for scan {raw_scan_data.scan_id}"
            )
            return normalized_data

        except Exception as e:
            self.logger.error(
                f"Failed to normalize scan data for {raw_scan_data.scan_id}: {e}"
            )
            raise

    def _normalize_device(
        self, raw_device: Dict, raw_scan_data
    ) -> Optional[NormalizedAsset]:
        """Normalize a single device from raw data"""
        try:
            # Generate unique asset ID
            asset_id = f"ASSET-{uuid.uuid4().hex[:12].upper()}"

            # Normalize asset type
            asset_type = self._normalize_asset_type(raw_device)

            # Determine criticality
            criticality = self._assess_criticality(raw_device, asset_type)

            # Determine network segment
            network_segment = self._assess_network_segment(raw_device)

            # Determine authentication state
            auth_state = self._assess_authentication_state(raw_device, raw_scan_data)

            # Get associated ports
            ports = self._get_device_ports(raw_device["ip_address"], raw_scan_data)

            # Get associated vulnerabilities
            vulnerabilities = self._get_device_vulnerabilities(
                raw_device["ip_address"], raw_scan_data
            )

            # Create normalized asset
            normalized_asset = NormalizedAsset(
                asset_id=asset_id,
                asset_type=asset_type,
                ip_address=raw_device["ip_address"],
                hostname=raw_device.get("hostname"),
                mac_address=raw_device.get("mac_address"),
                manufacturer=raw_device.get("manufacturer"),
                model=raw_device.get("model"),
                firmware_version=raw_device.get("firmware_version"),
                os_info=self._infer_os_info(raw_device),
                criticality=criticality,
                network_segment=network_segment,
                authentication_state=auth_state,
                ports=ports,
                vulnerabilities=vulnerabilities,
            )

            return normalized_asset

        except Exception as e:
            self.logger.error(
                f"Failed to normalize device {raw_device.get('ip_address', 'unknown')}: {e}"
            )
            return None

    def _normalize_asset_type(self, raw_device: Dict) -> str:
        """Normalize asset type from various identification sources"""
        device_type = raw_device.get("device_type", "").lower()

        # Check against known mappings
        for normalized_type, raw_types in self.asset_type_mappings.items():
            if any(raw_type in device_type for raw_type in raw_types):
                return normalized_type

        # Special handling for CCTV devices
        if raw_device.get("is_cctv"):
            manufacturer = raw_device.get("manufacturer", "").lower()
            if "hikvision" in manufacturer:
                return "camera" if "camera" in device_type else "dvr"
            elif "dahua" in manufacturer:
                return "camera" if "camera" in device_type else "dvr"
            else:
                return "camera"  # Default for CCTV devices

        # Default fallback
        return "network_device"

    def _assess_criticality(self, raw_device: Dict, asset_type: str) -> str:
        """Assess asset criticality based on type and context"""
        # High criticality for surveillance equipment
        if asset_type in self.criticality_rules["high"]:
            return "high"

        # Check manufacturer for known critical vendors
        manufacturer = raw_device.get("manufacturer", "").lower()
        if any(vendor in manufacturer for vendor in ["hikvision", "dahua", "axis"]):
            return "high"

        # Medium criticality for network infrastructure
        if asset_type in self.criticality_rules["medium"]:
            return "medium"

        return "medium"  # Default

    def _assess_network_segment(self, raw_device: Dict) -> str:
        """Assess network segment based on IP address and context"""
        ip = raw_device.get("ip_address", "")

        # Simple IP-based segmentation (can be enhanced with network topology data)
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "internal"
        elif ip.startswith("172.16.") or ip.startswith("172.31."):
            return "dmz"
        else:
            return "external"

    def _assess_authentication_state(self, raw_device: Dict, raw_scan_data) -> str:
        """Assess authentication state based on vulnerability findings"""
        device_ip = raw_device["ip_address"]
        device_vulns = self._get_device_vulnerabilities(device_ip, raw_scan_data)

        # Check for authentication-related vulnerabilities
        auth_vulns = [
            v
            for v in device_vulns
            if "credential" in v.get("title", "").lower()
            or "authentication" in v.get("title", "").lower()
            or "default" in v.get("title", "").lower()
        ]

        if auth_vulns:
            return "unauthenticated"
        else:
            # Assume authenticated if no auth vulns found (conservative approach)
            return "authenticated"

    def _get_device_ports(self, device_ip: str, raw_scan_data) -> List[Dict[str, Any]]:
        """Get normalized ports for a device"""
        raw_ports = raw_scan_data.port_scanning.get("raw_ports", [])
        device_ports = [p for p in raw_ports if p.get("device_ip") == device_ip]

        normalized_ports = []
        for port in device_ports:
            normalized_port = {
                "port_number": port.get("port_number"),
                "protocol": port.get("protocol", "tcp"),
                "service_name": port.get("service_name"),
                "service_version": port.get("service_version"),
                "state": port.get("state", "unknown"),
                "banner": port.get("banner"),
                "is_encrypted": self._is_encrypted_port(port),
            }
            normalized_ports.append(normalized_port)

        return normalized_ports

    def _get_device_vulnerabilities(
        self, device_ip: str, raw_scan_data
    ) -> List[Dict[str, Any]]:
        """Get normalized vulnerabilities for a device"""
        raw_vulns = raw_scan_data.vulnerability_scanning.get("raw_vulnerabilities", [])
        device_vulns = [v for v in raw_vulns if v.get("device_ip") == device_ip]

        normalized_vulns = []
        for vuln in device_vulns:
            normalized_vuln = {
                "vulnerability_id": vuln.get(
                    "vuln_id", f"VULN-{uuid.uuid4().hex[:8].upper()}"
                ),
                "title": vuln.get("title"),
                "description": vuln.get("description"),
                "evidence": vuln.get("proof_of_concept"),
                "cvss_score": vuln.get("cvss_score"),
                "severity": vuln.get("severity", "info"),
                "cve_id": vuln.get("cve_id"),
                "cwe_id": vuln.get("cwe_id"),
                "affected_component": vuln.get("affected_component"),
                "remediation": vuln.get("remediation"),
                "references": vuln.get("references", []),
            }
            normalized_vulns.append(normalized_vuln)

        return normalized_vulns

    def _is_encrypted_port(self, port: Dict) -> bool:
        """Determine if a port uses encryption"""
        port_num = port.get("port_number")
        service = port.get("service_name", "").lower()

        # Common encrypted ports
        encrypted_ports = [443, 993, 995, 465, 989, 990]
        encrypted_services = ["https", "ssl", "tls", "ssh"]

        return port_num in encrypted_ports or any(
            svc in service for svc in encrypted_services
        )

    def _infer_os_info(self, raw_device: Dict) -> Optional[str]:
        """Infer OS information from available data"""
        # This is a simplified implementation
        # In a real system, this would use more sophisticated fingerprinting

        manufacturer = raw_device.get("manufacturer", "").lower()

        if "hikvision" in manufacturer:
            return "Embedded Linux (Hikvision)"
        elif "dahua" in manufacturer:
            return "Embedded Linux (Dahua)"
        elif "axis" in manufacturer:
            return "Embedded Linux (Axis)"

        return None

    def validate_normalized_data(self, normalized_data: NormalizedScanData) -> bool:
        """Validate normalized data structure"""
        if not normalized_data.scan_id:
            self.logger.error("Normalized data missing scan_id")
            return False

        if not normalized_data.normalized_assets:
            self.logger.warning("Normalized data contains no assets")

        # Check each asset has required fields
        for asset in normalized_data.normalized_assets:
            if not asset.asset_id or not asset.ip_address:
                self.logger.error(f"Asset missing required fields: {asset.asset_id}")
                return False

        return True

    def get_normalization_summary(
        self, normalized_data: NormalizedScanData
    ) -> Dict[str, Any]:
        """Get summary of normalization results"""
        assets_by_type = {}
        assets_by_criticality = {}
        total_vulns = 0
        total_ports = 0

        for asset in normalized_data.normalized_assets:
            # Count by type
            asset_type = asset.asset_type
            assets_by_type[asset_type] = assets_by_type.get(asset_type, 0) + 1

            # Count by criticality
            criticality = asset.criticality
            assets_by_criticality[criticality] = (
                assets_by_criticality.get(criticality, 0) + 1
            )

            # Count vulnerabilities and ports
            total_vulns += len(asset.vulnerabilities)
            total_ports += len(asset.ports)

        return {
            "scan_id": normalized_data.scan_id,
            "normalized_at": normalized_data.normalized_at.isoformat(),
            "total_assets": len(normalized_data.normalized_assets),
            "assets_by_type": assets_by_type,
            "assets_by_criticality": assets_by_criticality,
            "total_vulnerabilities": total_vulns,
            "total_ports": total_ports,
            "metadata": normalized_data.normalization_metadata,
        }
