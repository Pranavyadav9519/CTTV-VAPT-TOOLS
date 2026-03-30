"""
Firmware Extractor / Fingerprinter
Identifies firmware version and known CVEs from device banners,
HTTP headers, and RTSP server strings.
Operates on CRRDevice objects and enriches them in place.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

try:
    from backend.core.crr_models import CRRDevice, CRRVulnerability
except ImportError:
    from core.crr_models import CRRDevice, CRRVulnerability

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerable firmware database
# Each entry: (manufacturer_pattern, firmware_pattern, vuln metadata list)
# ---------------------------------------------------------------------------
_VULN_DB: List[Tuple[re.Pattern, re.Pattern, List[Dict]]] = [
    # Hikvision – unauthenticated RCE
    (
        re.compile(r"hikvision", re.I),
        re.compile(r"V[0-9]\.[0-9]\.[0-9]"),
        [
            {
                "vuln_id": "CVE-2021-36260",
                "title": "Hikvision Command Injection RCE",
                "severity": "critical",
                "cvss_score": 9.8,
                "cve_id": "CVE-2021-36260",
                "cwe_id": "CWE-78",
                "description": (
                    "A command injection vulnerability in the web server of Hikvision "
                    "cameras allows unauthenticated remote code execution."
                ),
                "remediation": "Upgrade firmware to V5.5.800 or later.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
                ],
            }
        ],
    ),
    # Hikvision – weak password policy
    (
        re.compile(r"hikvision", re.I),
        re.compile(r".*"),
        [
            {
                "vuln_id": "VAPT-HIK-001",
                "title": "Hikvision Weak Default Credentials",
                "severity": "high",
                "cvss_score": 8.8,
                "cve_id": None,
                "cwe_id": "CWE-521",
                "description": "Device may retain factory default credentials (admin/12345).",
                "remediation": "Change all default credentials and enforce strong password policy.",
                "references": [],
            }
        ],
    ),
    # Dahua – authentication bypass
    (
        re.compile(r"dahua", re.I),
        re.compile(r".*"),
        [
            {
                "vuln_id": "CVE-2021-33044",
                "title": "Dahua Authentication Bypass",
                "severity": "critical",
                "cvss_score": 9.8,
                "cve_id": "CVE-2021-33044",
                "cwe_id": "CWE-287",
                "description": (
                    "Identity authentication bypass vulnerability in Dahua products "
                    "allows unauthenticated access."
                ),
                "remediation": "Apply latest Dahua firmware patch.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-33044",
                ],
            }
        ],
    ),
    # Axis – VAPIX command injection
    (
        re.compile(r"axis", re.I),
        re.compile(r".*"),
        [
            {
                "vuln_id": "CVE-2018-10661",
                "title": "Axis VAPIX Command Injection",
                "severity": "high",
                "cvss_score": 8.8,
                "cve_id": "CVE-2018-10661",
                "cwe_id": "CWE-78",
                "description": (
                    "Axis cameras with firmware before 6.50.x are vulnerable "
                    "to command injection via VAPIX API."
                ),
                "remediation": "Upgrade to firmware 6.50.x or later.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-10661",
                ],
            }
        ],
    ),
    # Generic RTSP exposure
    (
        re.compile(r".*"),
        re.compile(r".*"),
        [
            {
                "vuln_id": "VAPT-GEN-001",
                "title": "Unauthenticated RTSP Stream Exposure",
                "severity": "medium",
                "cvss_score": 5.3,
                "cve_id": None,
                "cwe_id": "CWE-306",
                "description": (
                    "The RTSP stream is accessible without authentication, "
                    "allowing any user to view live footage."
                ),
                "remediation": (
                    "Enable RTSP authentication and restrict stream access "
                    "to authorized networks."
                ),
                "references": [],
            }
        ],
    ),
]

# HTTP headers and banner patterns for firmware extraction
_FIRMWARE_PATTERNS = [
    re.compile(r"firmware[/ _-]?v?([0-9]+\.[0-9]+[\w.]*)", re.I),
    re.compile(r"FW[/ _-]?([0-9]+\.[0-9]+[\w.]*)", re.I),
    re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+[\w.]*)", re.I),
]

_MANUFACTURER_PATTERNS = {
    "hikvision": re.compile(r"hikvision|HIKVISION|hik-connect", re.I),
    "dahua": re.compile(r"dahua|DH-IPC|Dahua", re.I),
    "axis": re.compile(r"\baxis\b", re.I),
    "hanwha": re.compile(r"hanwha|samsung wisenet|wisenet", re.I),
    "vivotek": re.compile(r"vivotek", re.I),
    "bosch": re.compile(r"bosch", re.I),
    "uniview": re.compile(r"uniview|UNV", re.I),
    "reolink": re.compile(r"reolink", re.I),
    "annke": re.compile(r"annke", re.I),
}


class FirmwareExtractor:
    """
    Enriches CRRDevice objects with firmware version and manufacturer
    extracted from banners and raw_attributes.
    Also matches against the vulnerable firmware database.
    """

    def enrich(self, device: CRRDevice) -> List[CRRVulnerability]:
        """
        Extract firmware/manufacturer from the device's raw_attributes
        and return a list of matching CRRVulnerability objects.
        """
        banner = self._collect_banner(device)

        if not device.manufacturer:
            device.manufacturer = self._detect_manufacturer(banner)

        if not device.firmware_version:
            device.firmware_version = self._extract_firmware(banner)

        vulns = self._match_vulnerabilities(device)

        # Only flag RTSP exposure if the device has rtsp in protocols
        if "rtsp" in device.protocols:
            rtsp_vuln = self._generic_rtsp_vuln()
            # Avoid duplicate
            existing_ids = {v.vuln_id for v in vulns}
            if rtsp_vuln.vuln_id not in existing_ids:
                vulns.append(rtsp_vuln)

        return vulns

    def _collect_banner(self, device: CRRDevice) -> str:
        parts = [
            device.manufacturer or "",
            device.model or "",
            device.firmware_version or "",
            str(device.raw_attributes.get("server", "")),
            str(device.raw_attributes.get("rtsp_server", "")),
            str(device.raw_attributes.get("scopes", "")),
            str(device.raw_attributes.get("hardware", "")),
            str(device.raw_attributes.get("server_header", "")),
        ]
        return " ".join(p for p in parts if p)

    def _detect_manufacturer(self, banner: str) -> Optional[str]:
        for name, pattern in _MANUFACTURER_PATTERNS.items():
            if pattern.search(banner):
                return name.title()
        return None

    def _extract_firmware(self, banner: str) -> Optional[str]:
        for pattern in _FIRMWARE_PATTERNS:
            match = pattern.search(banner)
            if match:
                return match.group(1)
        return None

    def _match_vulnerabilities(self, device: CRRDevice) -> List[CRRVulnerability]:
        mfr = (device.manufacturer or "").lower()
        fw = device.firmware_version or ""
        vulns: List[CRRVulnerability] = []

        for mfr_pat, fw_pat, vuln_list in _VULN_DB:
            # Skip generic RTSP rule here (handled separately)
            if mfr_pat.pattern == ".*" and fw_pat.pattern == ".*":
                continue
            if mfr_pat.search(mfr) and fw_pat.search(fw):
                for v in vuln_list:
                    vulns.append(CRRVulnerability(**v))

        return vulns

    @staticmethod
    def _generic_rtsp_vuln() -> CRRVulnerability:
        return CRRVulnerability(
            vuln_id="VAPT-GEN-001",
            title="Unauthenticated RTSP Stream Exposure",
            severity="medium",
            cvss_score=5.3,
            cwe_id="CWE-306",
            description=(
                "The RTSP stream is accessible without authentication, "
                "allowing any user to view live footage."
            ),
            remediation=(
                "Enable RTSP authentication and restrict stream access "
                "to authorized networks."
            ),
        )
