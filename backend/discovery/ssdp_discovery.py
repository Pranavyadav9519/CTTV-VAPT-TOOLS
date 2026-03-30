"""
UPnP / SSDP Discovery Module
Discovers CCTV/DVR/NVR devices on the local network using the
Simple Service Discovery Protocol (SSDP / UPnP M-SEARCH).

Protocol Details:
  - Multicast address: 239.255.255.250:1900
  - Transport: UDP
  - Payload: HTTP-over-UDP M-SEARCH request
"""

import socket
import re
import logging
from typing import Dict, List, Optional
from datetime import datetime

import requests

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

# Search target values that indicate camera / video-related UPnP devices
_CAMERA_KEYWORDS = frozenset(
    [
        "networkcamera",
        "networkvideorecorder",
        "nvr",
        "dvr",
        "digitalvideotransmitter",
        "mediaplayer",
        "mediarenderer",
        "mediaserver",
        "hikvision",
        "dahua",
        "axis",
        "reolink",
        "foscam",
        "amcrest",
        "uniview",
        "onvif",
        "ipcam",
        "webcam",
        "videorecorder",
    ]
)

_M_SEARCH_TEMPLATE = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: {mx}\r\n"
    "ST: {st}\r\n"
    "\r\n"
)

# Search targets to probe in sequence
_SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
]


def _build_m_search(search_target: str = "ssdp:all", mx: int = 3) -> bytes:
    """
    Build an SSDP M-SEARCH request datagram.

    Args:
        search_target: UPnP Search Target (ST header value).
        mx: Maximum wait seconds (MX header value).

    Returns:
        UTF-8 encoded M-SEARCH request bytes.
    """
    return _M_SEARCH_TEMPLATE.format(st=search_target, mx=mx).encode("utf-8")


def _parse_ssdp_response(raw: str) -> Dict[str, str]:
    """
    Parse an HTTP-style SSDP response into a header dict.

    Args:
        raw: Raw SSDP response string.

    Returns:
        Dictionary of header names (lower-case) to values.
    """
    headers: Dict[str, str] = {}
    lines = raw.split("\r\n")
    for line in lines[1:]:  # Skip status line
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def _is_camera_device(headers: Dict[str, str]) -> bool:
    """
    Heuristically determine whether an SSDP response is from a camera/NVR/DVR.

    Args:
        headers: Parsed SSDP response headers.

    Returns:
        True if the device looks like a CCTV/camera device.
    """
    searchable = " ".join(headers.values()).lower()
    return any(kw in searchable for kw in _CAMERA_KEYWORDS)


def _ip_from_location(location: str) -> Optional[str]:
    """Extract IPv4 address from a URL string."""
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", location)
    return match.group(1) if match else None


def _fetch_device_description(location_url: str, timeout: float = 3.0) -> Dict:
    """
    Fetch and lightly parse a UPnP device description XML document.

    Args:
        location_url: URL from the SSDP LOCATION header.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict with keys ``manufacturer``, ``model``, ``friendly_name``,
        ``udn`` extracted from the XML, or empty strings on failure.
    """
    info: Dict[str, str] = {
        "manufacturer": "",
        "model": "",
        "friendly_name": "",
        "udn": "",
    }
    try:
        resp = requests.get(location_url, timeout=timeout, verify=False)
        if resp.status_code == 200:
            text = resp.text

            def _extract(tag: str) -> str:
                m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.IGNORECASE | re.DOTALL)
                return m.group(1).strip() if m else ""

            info["manufacturer"] = _extract("manufacturer")
            info["model"] = _extract("modelNumber") or _extract("modelName")
            info["friendly_name"] = _extract("friendlyName")
            info["udn"] = _extract("UDN")
    except requests.RequestException as exc:
        logger.debug("Failed to fetch UPnP device description from %s: %s", location_url, exc)
    return info


class SSDPDiscovery:
    """
    Discovers CCTV/DVR/NVR devices on the local network using UPnP/SSDP
    M-SEARCH multicast probes.

    Multiple search targets are probed and responses are deduplicated by IP.
    Optionally fetches UPnP device description documents for richer metadata.

    Usage::

        discovery = SSDPDiscovery(timeout=3)
        devices = discovery.discover()
        for device in devices:
            print(device["ip_address"], device.get("model"))
    """

    def __init__(
        self,
        timeout: float = 3.0,
        fetch_descriptions: bool = True,
        filter_cameras_only: bool = False,
    ) -> None:
        """
        Initialise the SSDP discovery client.

        Args:
            timeout: Seconds to wait for SSDP responses (default 3 s).
            fetch_descriptions: When True, fetch UPnP device description XML
                for each discovered device to obtain manufacturer/model info.
            filter_cameras_only: When True, only return devices that match
                camera/DVR/NVR keyword heuristics.
        """
        self.timeout = timeout
        self.fetch_descriptions = fetch_descriptions
        self.filter_cameras_only = filter_cameras_only

    def _send_and_receive(self, search_target: str) -> List[Dict]:
        """
        Send one M-SEARCH probe and collect all responses until timeout.

        Args:
            search_target: SSDP ST header value.

        Returns:
            List of parsed header dicts for each unique response.
        """
        responses: List[Dict] = []
        probe = _build_m_search(search_target)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            sock.bind(("", 0))
            sock.sendto(probe, (SSDP_ADDR, SSDP_PORT))
            logger.debug("SSDP M-SEARCH sent (ST=%s)", search_target)

            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    parsed = _parse_ssdp_response(data.decode("utf-8", errors="replace"))
                    parsed["_src_ip"] = addr[0]
                    responses.append(parsed)
                except socket.timeout:
                    break
        except OSError as exc:
            logger.warning("SSDP socket error for ST=%s: %s", search_target, exc)
        finally:
            if sock is not None:
                sock.close()

        return responses

    def discover(self) -> List[Dict]:
        """
        Perform SSDP M-SEARCH discovery across all configured search targets.

        Returns:
            List of device dictionaries, deduplicated by IP address, with keys
            ``ip_address``, ``discovery_method``, ``location``, ``server``,
            ``st``, ``usn``, ``manufacturer``, ``model``, ``friendly_name``,
            ``udn``, ``discovered_at``, and ``confidence``.
        """
        logger.info("Starting SSDP/UPnP discovery (timeout=%.1fs)", self.timeout)
        seen_ips: set = set()
        devices: List[Dict] = []

        for st in _SEARCH_TARGETS:
            raw_responses = self._send_and_receive(st)

            for headers in raw_responses:
                location = headers.get("location", "")
                ip = _ip_from_location(location) or headers.get("_src_ip", "")
                if not ip or ip in seen_ips:
                    continue

                if self.filter_cameras_only and not _is_camera_device(headers):
                    continue

                device: Dict = {
                    "ip_address": ip,
                    "mac_address": None,
                    "discovery_method": "ssdp_upnp",
                    "location": location,
                    "server": headers.get("server", ""),
                    "st": headers.get("st", st),
                    "usn": headers.get("usn", ""),
                    "is_camera_device": _is_camera_device(headers),
                    "discovered_at": datetime.utcnow().isoformat(),
                    "confidence": 0.7,
                    # Enrichment fields — filled in below if fetch_descriptions is True
                    "manufacturer": "",
                    "model": "",
                    "friendly_name": "",
                    "udn": "",
                }

                if self.fetch_descriptions and location:
                    description = _fetch_device_description(location, timeout=3.0)
                    device.update(description)
                    # Bump confidence if we got real device info
                    if description.get("manufacturer") or description.get("model"):
                        device["confidence"] = 0.85

                seen_ips.add(ip)
                devices.append(device)

        logger.info("SSDP/UPnP discovery found %d device(s)", len(devices))
        return devices
