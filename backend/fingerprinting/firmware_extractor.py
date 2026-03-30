"""
Firmware Extractor Module
Extracts firmware version information from CCTV devices using:
  - HTTP response headers (Server, X-Powered-By, X-Firmware-Version)
  - RTSP Server headers
  - ONVIF GetDeviceInformation SOAP responses
  - Web page body content (HTML version strings)

Extracted versions are matched against a built-in database of known
vulnerable firmware versions to highlight high-risk devices quickly.
"""

import re
import logging
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime

import requests

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known vulnerable firmware versions database
# Each entry: (manufacturer, pattern, cve_ids, severity, description)
# ---------------------------------------------------------------------------
VULNERABLE_FIRMWARE_DB: List[Tuple[str, str, List[str], str, str]] = [
    (
        "hikvision",
        r"v(\d+\.\d+).*build\s*(\d{8})",
        ["CVE-2021-36260"],
        "critical",
        "Hikvision unauthenticated RCE via /SDK/webLanguage",
    ),
    (
        "hikvision",
        r"v5\.(3|4)\.",
        ["CVE-2017-7921"],
        "critical",
        "Hikvision authentication bypass — firmware < V5.4.0",
    ),
    (
        "dahua",
        r"v(\d+\.\d+)",
        ["CVE-2021-33044", "CVE-2021-33045"],
        "critical",
        "Dahua authentication bypass in multiple firmware lines",
    ),
    (
        "axis",
        r"(\d+\.\d+\.\d+)",
        ["CVE-2018-10660"],
        "critical",
        "Axis OS shell command injection via web interface",
    ),
    (
        "reolink",
        r"v(\d+\.\d+\.\d+\.\d+)",
        ["CVE-2020-25169"],
        "high",
        "Reolink camera lacks CSRF protection, arbitrary settings change",
    ),
]

# HTTP ports to try when extracting firmware from web interface
_HTTP_PORTS = [80, 8080, 443, 8443]

# Regex patterns for extracting version strings from headers / body
_VERSION_PATTERNS = [
    re.compile(r"[Ff]irmware[/ :]+([0-9A-Za-z._\-]+)"),
    re.compile(r"[Vv]ersion[/ :]+([0-9A-Za-z._\-]+)"),
    re.compile(r"[Bb]uild[/ :]+([0-9A-Za-z._\-]+)"),
    re.compile(r"v(\d+\.\d+[\.\d]*)"),
    re.compile(r"(\d{1,2}\.\d{1,2}(?:\.\d{1,2}){0,2})"),
]


def _extract_version_from_text(text: str) -> Optional[str]:
    """
    Apply version-extraction regex patterns against arbitrary text.

    Args:
        text: Header value, HTML body excerpt, or similar string.

    Returns:
        First matched version string, or None.
    """
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _match_against_vuln_db(
    manufacturer: str, firmware_version: str
) -> List[Dict]:
    """
    Match a firmware version against the known-vulnerable firmware database.

    Args:
        manufacturer: Lower-case manufacturer name (e.g. ``"hikvision"``).
        firmware_version: Extracted firmware version string.

    Returns:
        List of matching vulnerability dicts.
    """
    findings: List[Dict] = []
    for mfr, pattern, cves, severity, description in VULNERABLE_FIRMWARE_DB:
        if mfr not in manufacturer.lower():
            continue
        if re.search(pattern, firmware_version, re.IGNORECASE):
            findings.append(
                {
                    "cve_ids": cves,
                    "severity": severity,
                    "description": description,
                    "matched_pattern": pattern,
                    "firmware_version": firmware_version,
                }
            )
    return findings


class FirmwareExtractor:
    """
    Extracts firmware version information from CCTV devices and matches
    versions against a known-vulnerable firmware database.

    Extraction sources (tried in order):
      1. HTTP response headers from web interface
      2. RTSP Server header
      3. ONVIF GetDeviceInformation (XML response)
      4. HTML body content scan

    Usage::

        extractor = FirmwareExtractor(timeout=3)
        result = extractor.extract(ip="192.168.1.100", manufacturer="hikvision")
        print(result["firmware_version"], result["vulnerable_firmware"])
    """

    def __init__(self, timeout: float = 3.0) -> None:
        """
        Initialise the firmware extractor.

        Args:
            timeout: HTTP/socket timeout in seconds.
        """
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = False
        self._session.timeout = timeout

    # ------------------------------------------------------------------
    # Private extraction helpers
    # ------------------------------------------------------------------

    def _from_http_headers(self, ip: str) -> Optional[Tuple[str, str]]:
        """
        Try to extract firmware version from HTTP response headers.

        Args:
            ip: Target IP address.

        Returns:
            Tuple of ``(version_string, source_description)`` or None.
        """
        for port in _HTTP_PORTS:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port}/"
            try:
                resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
                headers_of_interest = [
                    ("server", resp.headers.get("Server", "")),
                    ("x-powered-by", resp.headers.get("X-Powered-By", "")),
                    ("x-firmware-version", resp.headers.get("X-Firmware-Version", "")),
                    ("x-device-version", resp.headers.get("X-Device-Version", "")),
                    ("x-app-version", resp.headers.get("X-App-Version", "")),
                ]
                for header_name, header_value in headers_of_interest:
                    if header_value:
                        version = _extract_version_from_text(header_value)
                        if version:
                            return version, f"http_header:{header_name}"
                # Also scan first 4 KB of body
                body_chunk = resp.text[:4096]
                version = _extract_version_from_text(body_chunk)
                if version:
                    return version, "http_body"
            except requests.RequestException:
                continue
        return None

    def _from_rtsp_server_header(self, ip: str, port: int = 554) -> Optional[Tuple[str, str]]:
        """
        Extract firmware version from RTSP Server header.

        Args:
            ip: Target IP address.
            port: RTSP port (default 554).

        Returns:
            Tuple of ``(version_string, source_description)`` or None.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            request = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                "User-Agent: CRR-FirmwareExtractor/1.0\r\n"
                "\r\n"
            ).encode()
            sock.sendall(request)
            raw = sock.recv(2048).decode("utf-8", errors="replace")
            sock.close()

            server_match = re.search(r"Server:\s*(.+)", raw, re.IGNORECASE)
            if server_match:
                server_value = server_match.group(1).strip()
                version = _extract_version_from_text(server_value)
                if version:
                    return version, "rtsp_server_header"
        except (OSError, socket.timeout):
            pass
        return None

    def _from_onvif(self, ip: str) -> Optional[Tuple[str, str]]:
        """
        Extract firmware version via ONVIF GetDeviceInformation SOAP call.

        Args:
            ip: Target IP address.

        Returns:
            Tuple of ``(version_string, source_description)`` or None.
        """
        soap_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            "<s:Body>"
            '<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>'
            "</s:Body>"
            "</s:Envelope>"
        )
        endpoints = [
            f"http://{ip}/onvif/device_service",
            f"http://{ip}:80/onvif/device_service",
            f"http://{ip}:8080/onvif/device_service",
        ]
        headers = {
            "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
        }
        for endpoint in endpoints:
            try:
                resp = self._session.post(
                    endpoint,
                    data=soap_body,
                    headers=headers,
                    timeout=self.timeout,
                )
                text = resp.text
                fw_match = re.search(
                    r"<[^>]*[Ff]irmware[Vv]ersion[^>]*>([^<]+)<",
                    text,
                )
                if fw_match:
                    return fw_match.group(1).strip(), "onvif_device_info"
            except requests.RequestException:
                continue
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, ip: str, manufacturer: str = "") -> Dict:
        """
        Extract firmware version for a single device and check vulnerability status.

        All extraction methods are tried in order of reliability:
        HTTP headers → RTSP Server header → ONVIF GetDeviceInformation.

        Args:
            ip: Target IPv4 address.
            manufacturer: Known or guessed manufacturer name (used for
                better vulnerability matching).

        Returns:
            Dict with keys:
              - ``ip_address``
              - ``firmware_version`` (str or None)
              - ``extraction_source`` (str describing which method succeeded)
              - ``vulnerable_firmware`` (list of matched vuln dicts)
              - ``extracted_at`` (ISO timestamp)
        """
        result: Dict = {
            "ip_address": ip,
            "firmware_version": None,
            "extraction_source": None,
            "vulnerable_firmware": [],
            "extracted_at": datetime.utcnow().isoformat(),
        }

        # Try each extraction method
        for method in [
            lambda: self._from_http_headers(ip),
            lambda: self._from_rtsp_server_header(ip),
            lambda: self._from_onvif(ip),
        ]:
            try:
                outcome = method()
                if outcome:
                    version, source = outcome
                    result["firmware_version"] = version
                    result["extraction_source"] = source
                    break
            except Exception as exc:
                logger.debug("Firmware extraction method failed for %s: %s", ip, exc)

        if result["firmware_version"]:
            result["vulnerable_firmware"] = _match_against_vuln_db(
                manufacturer, result["firmware_version"]
            )
            logger.info(
                "Firmware %s extracted from %s via %s (%d vuln match(es))",
                result["firmware_version"],
                ip,
                result["extraction_source"],
                len(result["vulnerable_firmware"]),
            )
        else:
            logger.debug("Could not extract firmware version from %s", ip)

        return result

    def extract_batch(
        self, devices: List[Dict]
    ) -> Dict[str, Dict]:
        """
        Extract firmware for a list of device dicts.

        Args:
            devices: List of device dicts, each with at minimum ``ip_address``
                and optionally ``manufacturer`` / ``manufacturer_hint``.

        Returns:
            Dict mapping IP address → extraction result.
        """
        results: Dict[str, Dict] = {}
        for device in devices:
            ip = device.get("ip_address", "")
            manufacturer = device.get("manufacturer") or device.get("manufacturer_hint", "")
            if not ip:
                continue
            results[ip] = self.extract(ip, manufacturer)
        return results
