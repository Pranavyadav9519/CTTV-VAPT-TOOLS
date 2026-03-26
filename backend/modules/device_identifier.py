"""
Device Identifier Module
Identifies CCTV/DVR/NVR devices from discovered hosts using multiple detection methods
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Device type enumeration"""

    IP_CAMERA = "ip_camera"
    DVR = "dvr"
    NVR = "nvr"
    HYBRID = "hybrid"
    ENCODER = "encoder"
    UNKNOWN = "unknown"


@dataclass
class CCTVSignature:
    """CCTV device signature for identification"""

    manufacturer: str
    patterns: List[str]
    ports: List[int]
    device_type: DeviceType
    confidence_boost: float = 0.0


class DeviceIdentifier:
    """
    Identifies CCTV/DVR devices using multiple heuristics:
    - MAC address OUI lookup
    - Service banner analysis
    - HTTP header fingerprinting
    - Port combination analysis
    """

    # Known CCTV manufacturer signatures
    CCTV_SIGNATURES = {
        "hikvision": CCTVSignature(
            manufacturer="Hikvision",
            patterns=[
                r"hikvision",
                r"hik",
                r"dvr.*web",
                r"ivms",
                r"DS-\d+",
                r"webclient",
                r"DNVRS-Webs",
            ],
            ports=[80, 443, 554, 8000, 8443, 8200, 6036],
            device_type=DeviceType.DVR,
        ),
        "dahua": CCTVSignature(
            manufacturer="Dahua",
            patterns=[
                r"dahua",
                r"dh-",
                r"DH_",
                r"web3\.0",
                r"RTSP/1\.0 DH",
                r"DHI-",
                r"XVR",
            ],
            ports=[80, 443, 554, 37777, 37778, 8080],
            device_type=DeviceType.DVR,
        ),
        "axis": CCTVSignature(
            manufacturer="Axis Communications",
            patterns=[
                r"axis",
                r"AXIS",
                r"boa/\d",
                r"vapix",
                r"networkCamera",
                r"AXIS.*Camera",
            ],
            ports=[80, 443, 554],
            device_type=DeviceType.IP_CAMERA,
        ),
        "foscam": CCTVSignature(
            manufacturer="Foscam",
            patterns=[r"foscam", r"ipcam", r"FI\d+", r"MJPG"],
            ports=[80, 443, 554, 88],
            device_type=DeviceType.IP_CAMERA,
        ),
        "uniview": CCTVSignature(
            manufacturer="Uniview",
            patterns=[r"uniview", r"unv", r"IPC.*UNV"],
            ports=[80, 443, 554, 7001],
            device_type=DeviceType.DVR,
        ),
        "xmeye": CCTVSignature(
            manufacturer="XMEye/Generic",
            patterns=[r"xmeye", r"sofia", r"jufeng", r"cloudview"],
            ports=[80, 34567, 34599],
            device_type=DeviceType.DVR,
        ),
        "hanwha": CCTVSignature(
            manufacturer="Hanwha Techwin",
            patterns=[r"samsung", r"hanwha", r"snp-", r"wisenet"],
            ports=[80, 443, 554, 4520],
            device_type=DeviceType.IP_CAMERA,
        ),
        "vivotek": CCTVSignature(
            manufacturer="Vivotek",
            patterns=[r"vivotek", r"network camera", r"IP\d+", r"Boa/.*Vivotek"],
            ports=[80, 443, 554],
            device_type=DeviceType.IP_CAMERA,
        ),
    }

    # MAC address OUI prefixes for CCTV manufacturers
    OUI_DATABASE = {
        "28:57:BE": ("Hikvision", DeviceType.DVR, 0.9),
        "C0:56:E3": ("Hikvision", DeviceType.DVR, 0.9),
        "54:C4:15": ("Hikvision", DeviceType.DVR, 0.9),
        "44:19:B6": ("Hikvision", DeviceType.DVR, 0.9),
        "C4:2F:90": ("Hikvision", DeviceType.DVR, 0.9),
        "A4:14:37": ("Hikvision", DeviceType.DVR, 0.9),
        "BC:AD:28": ("Hikvision", DeviceType.DVR, 0.9),
        "4C:BD:8F": ("Hikvision", DeviceType.DVR, 0.9),
        "E0:50:8B": ("Dahua", DeviceType.DVR, 0.9),
        "3C:EF:8C": ("Dahua", DeviceType.DVR, 0.9),
        "40:F4:FD": ("Dahua", DeviceType.DVR, 0.9),
        "90:02:A9": ("Dahua", DeviceType.DVR, 0.9),
        "A0:BD:1D": ("Dahua", DeviceType.DVR, 0.9),
        "00:40:8C": ("Axis", DeviceType.IP_CAMERA, 0.95),
        "AC:CC:8E": ("Axis", DeviceType.IP_CAMERA, 0.95),
        "B8:A4:4F": ("Axis", DeviceType.IP_CAMERA, 0.95),
        "00:0F:7C": ("ACTi", DeviceType.IP_CAMERA, 0.9),
        "C8:A7:0A": ("Foscam", DeviceType.IP_CAMERA, 0.85),
        "00:26:E2": ("Panasonic", DeviceType.IP_CAMERA, 0.7),
        "F4:CF:E2": ("Bosch", DeviceType.IP_CAMERA, 0.85),
        "00:1C:7E": ("Honeywell", DeviceType.DVR, 0.8),
        "00:30:AB": ("Pelco", DeviceType.DVR, 0.9),
    }

    # Common CCTV ports with their typical services
    CCTV_PORT_SIGNATURES = {
        554: ("RTSP", 0.7),
        8554: ("RTSP Alt", 0.6),
        10554: ("RTSP Alt", 0.6),
        37777: ("Dahua", 0.9),
        37778: ("Dahua Mobile", 0.9),
        34567: ("XMEye", 0.85),
        34599: ("XMEye", 0.85),
        6036: ("Hikvision SDK", 0.85),
        8000: ("Hikvision DVR", 0.7),
        8200: ("Hikvision NVR", 0.7),
        5000: ("Synology/NAS", 0.3),
        9000: ("DVR Service", 0.5),
    }

    def __init__(self):
        self.identified_devices = []

    def identify_device(
        self, host_info: Dict, port_info: List[Dict] = None, banner_info: Dict = None
    ) -> Dict:
        """
        Identify if a device is a CCTV device and determine its type

        Args:
            host_info: Host information including IP and MAC
            port_info: List of open ports with service information
            banner_info: Service banner information

        Returns:
            Device identification result with confidence score
        """
        result = {
            "ip_address": host_info.get("ip_address"),
            "mac_address": host_info.get("mac_address"),
            "is_cctv": False,
            "confidence_score": 0.0,
            "manufacturer": None,
            "device_type": DeviceType.UNKNOWN.value,
            "model": None,
            "identification_methods": [],
            "evidence": [],
        }

        confidence = 0.0
        methods_used = []
        evidence = []

        # Method 1: MAC OUI Analysis
        mac = host_info.get("mac_address", "")
        if mac:
            oui_result = self._analyze_mac_oui(mac)
            if oui_result:
                manufacturer, device_type, oui_confidence = oui_result
                confidence = max(confidence, oui_confidence)
                result["manufacturer"] = manufacturer
                result["device_type"] = device_type.value
                methods_used.append("mac_oui")
                evidence.append(f"MAC OUI matches {manufacturer}")

        # Method 2: Port Combination Analysis
        if port_info:
            port_result = self._analyze_ports(port_info)
            if port_result["confidence"] > 0:
                confidence = max(confidence, port_result["confidence"])
                methods_used.append("port_analysis")
                evidence.extend(port_result["evidence"])
                if port_result.get("manufacturer") and not result["manufacturer"]:
                    result["manufacturer"] = port_result["manufacturer"]

        # Method 3: Banner Analysis
        if banner_info:
            banner_result = self._analyze_banners(banner_info)
            if banner_result["confidence"] > 0:
                confidence = max(confidence, banner_result["confidence"])
                methods_used.append("banner_analysis")
                evidence.extend(banner_result["evidence"])
                if banner_result.get("manufacturer") and not result["manufacturer"]:
                    result["manufacturer"] = banner_result["manufacturer"]
                if banner_result.get("model"):
                    result["model"] = banner_result["model"]

        # Method 4: RTSP Detection
        if port_info:
            rtsp_ports = [p for p in port_info if p.get("port_number") == 554]
            if rtsp_ports:
                confidence = max(confidence, 0.6)
                methods_used.append("rtsp_detected")
                evidence.append("RTSP port 554 open (streaming protocol)")

        # Determine if device is CCTV based on confidence threshold
        result["confidence_score"] = round(confidence, 2)
        result["is_cctv"] = confidence >= 0.5
        result["identification_methods"] = methods_used
        result["evidence"] = evidence

        return result

    def _analyze_mac_oui(self, mac: str) -> Optional[Tuple[str, DeviceType, float]]:
        """Analyze MAC address OUI for manufacturer identification"""
        if not mac:
            return None

        # Normalize MAC format
        mac = mac.upper().replace("-", ":")
        oui = ":".join(mac.split(":")[:3])

        return self.OUI_DATABASE.get(oui)

    def _analyze_ports(self, ports: List[Dict]) -> Dict:
        """Analyze open ports for CCTV signatures"""
        result = {"confidence": 0.0, "manufacturer": None, "evidence": []}

        port_numbers = [p.get("port_number") for p in ports]
        cctv_port_count = 0
        max_port_confidence = 0.0

        for port_num in port_numbers:
            if port_num in self.CCTV_PORT_SIGNATURES:
                service_name, confidence = self.CCTV_PORT_SIGNATURES[port_num]
                max_port_confidence = max(max_port_confidence, confidence)
                cctv_port_count += 1
                result["evidence"].append(f"Port {port_num} ({service_name})")

                # Check for manufacturer-specific ports
                if port_num in [37777, 37778]:
                    result["manufacturer"] = "Dahua"
                elif port_num in [34567, 34599]:
                    result["manufacturer"] = "XMEye/Generic"
                elif port_num == 6036:
                    result["manufacturer"] = "Hikvision"

        # Boost confidence if multiple CCTV ports found
        if cctv_port_count >= 2:
            max_port_confidence = min(max_port_confidence + 0.15, 1.0)

        result["confidence"] = max_port_confidence
        return result

    def _analyze_banners(self, banners: Dict) -> Dict:
        """Analyze service banners for CCTV signatures"""
        result = {
            "confidence": 0.0,
            "manufacturer": None,
            "model": None,
            "evidence": [],
        }

        for port, banner in banners.items():
            if not banner:
                continue

            banner_lower = banner.lower()

            for sig_name, signature in self.CCTV_SIGNATURES.items():
                for pattern in signature.patterns:
                    if re.search(pattern, banner_lower, re.IGNORECASE):
                        result["confidence"] = max(result["confidence"], 0.85)
                        result["manufacturer"] = signature.manufacturer
                        result["evidence"].append(
                            f"Banner matches {signature.manufacturer} pattern on port {port}"
                        )

                        # Try to extract model
                        model_match = re.search(
                            r"([A-Z]{2,3}[-_][A-Z0-9]+)", banner, re.IGNORECASE
                        )
                        if model_match:
                            result["model"] = model_match.group(1)
                        break

        return result

    def bulk_identify(
        self, hosts: List[Dict], ports_data: Dict = None, banners_data: Dict = None
    ) -> List[Dict]:
        """
        Identify multiple devices in bulk

        Args:
            hosts: List of host information dictionaries
            ports_data: Dictionary mapping IP to port list
            banners_data: Dictionary mapping IP to banner dictionary
        """
        results = []
        ports_data = ports_data or {}
        banners_data = banners_data or {}

        for host in hosts:
            ip = host.get("ip_address")
            port_info = ports_data.get(ip, [])
            banner_info = banners_data.get(ip, {})

            result = self.identify_device(host, port_info, banner_info)
            results.append(result)

        # Sort by confidence score (CCTV devices first)
        results.sort(key=lambda x: x["confidence_score"], reverse=True)

        return results

    def filter_cctv_devices(
        self, identified_devices: List[Dict], min_confidence: float = 0.5
    ) -> List[Dict]:
        """Filter to return only CCTV devices above confidence threshold"""
        return [
            device
            for device in identified_devices
            if device.get("is_cctv")
            and device.get("confidence_score", 0) >= min_confidence
        ]
