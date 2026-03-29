"""
ONVIF WS-Discovery Module
Discovers ONVIF-compliant IP cameras and DVR/NVR devices on the local network
using the WS-Discovery multicast protocol (RFC 4795).

Protocol Details:
  - Multicast address: 239.255.255.250:3702
  - Transport: UDP
  - Payload: SOAP/XML WS-Discovery ProbeMatch
"""

import socket
import uuid
import re
import logging
import ipaddress
from typing import Dict, List, Optional
from datetime import datetime
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# WS-Discovery multicast endpoint
WS_DISCOVERY_ADDR = "239.255.255.250"
WS_DISCOVERY_PORT = 3702

# Namespaces used in WS-Discovery SOAP messages
_NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "dn": "http://www.onvif.org/ver10/network/wsdl",
}


def _build_probe_message() -> bytes:
    """
    Build a WS-Discovery Probe SOAP message targeting any ONVIF device type.

    Returns:
        UTF-8 encoded SOAP XML bytes ready to be sent as a UDP datagram.
    """
    message_id = f"urn:uuid:{uuid.uuid4()}"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        "<s:Header>"
        f"<a:MessageID>{message_id}</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "<a:Action>"
        "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
        "</a:Action>"
        "</s:Header>"
        "<s:Body>"
        "<d:Probe>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "</d:Probe>"
        "</s:Body>"
        "</s:Envelope>"
    )
    return xml.encode("utf-8")


def _extract_xaddrs(probe_match_xml: str) -> List[str]:
    """
    Parse XAddrs (service endpoint URLs) from a ProbeMatch XML element text.

    Args:
        probe_match_xml: Raw XML string of the WS-Discovery response envelope.

    Returns:
        List of XAddr URL strings found in the response.
    """
    xaddrs: List[str] = []
    try:
        root = ET.fromstring(probe_match_xml)
        for xaddr_el in root.iter("{http://schemas.xmlsoap.org/ws/2005/04/discovery}XAddrs"):
            if xaddr_el.text:
                xaddrs.extend(xaddr_el.text.strip().split())
    except ET.ParseError as exc:
        logger.debug("Failed to parse WS-Discovery response XML: %s", exc)
    return xaddrs


def _extract_scopes(probe_match_xml: str) -> List[str]:
    """
    Parse Scopes from a ProbeMatch XML response.

    Args:
        probe_match_xml: Raw XML string of the WS-Discovery response envelope.

    Returns:
        List of scope URI strings.
    """
    scopes: List[str] = []
    try:
        root = ET.fromstring(probe_match_xml)
        for scope_el in root.iter("{http://schemas.xmlsoap.org/ws/2005/04/discovery}Scopes"):
            if scope_el.text:
                scopes.extend(scope_el.text.strip().split())
    except ET.ParseError as exc:
        logger.debug("Failed to parse Scopes from WS-Discovery response: %s", exc)
    return scopes


def _ip_from_xaddrs(xaddrs: List[str]) -> Optional[str]:
    """
    Extract the first IPv4 address from a list of XAddr URLs.

    Args:
        xaddrs: List of service endpoint URLs (e.g. http://192.168.1.50/onvif/device_service).

    Returns:
        First IPv4 address found, or None.
    """
    ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    for url in xaddrs:
        match = ip_pattern.search(url)
        if match:
            try:
                ipaddress.IPv4Address(match.group(1))
                return match.group(1)
            except ValueError:
                continue
    return None


class ONVIFDiscovery:
    """
    Discovers ONVIF cameras and DVR/NVR devices on the local network using
    the WS-Discovery UDP multicast protocol.

    Usage::

        discovery = ONVIFDiscovery(timeout=3)
        devices = discovery.discover()
        for device in devices:
            print(device["ip_address"], device["xaddrs"])
    """

    def __init__(self, timeout: float = 3.0, listen_port: int = 0) -> None:
        """
        Initialise the ONVIF WS-Discovery client.

        Args:
            timeout: Seconds to wait for ProbeMatch responses (default 3 s).
            listen_port: Local UDP port to bind (0 = OS assigns an ephemeral port).
        """
        self.timeout = timeout
        self.listen_port = listen_port

    def _send_probe(self, sock: socket.socket) -> None:
        """Send the WS-Discovery Probe datagram to the multicast group."""
        probe = _build_probe_message()
        sock.sendto(probe, (WS_DISCOVERY_ADDR, WS_DISCOVERY_PORT))
        logger.debug(
            "WS-Discovery Probe sent to %s:%d (%d bytes)",
            WS_DISCOVERY_ADDR,
            WS_DISCOVERY_PORT,
            len(probe),
        )

    def _receive_responses(self, sock: socket.socket) -> List[Dict]:
        """
        Listen for ProbeMatch responses until the socket times out.

        Args:
            sock: Bound UDP socket with SO_RCVTIMEO already set.

        Returns:
            List of raw response dictionaries with keys ``raw_xml``, ``src_ip``.
        """
        responses: List[Dict] = []
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                responses.append({"raw_xml": data.decode("utf-8", errors="replace"), "src_ip": addr[0]})
            except socket.timeout:
                break
            except OSError:
                break
        return responses

    def _parse_response(self, raw: Dict) -> Optional[Dict]:
        """
        Parse a single WS-Discovery ProbeMatch response into a device record.

        Args:
            raw: Dict with keys ``raw_xml`` and ``src_ip``.

        Returns:
            Device dict or None if the response cannot be parsed.
        """
        xaddrs = _extract_xaddrs(raw["raw_xml"])
        scopes = _extract_scopes(raw["raw_xml"])
        ip = _ip_from_xaddrs(xaddrs) or raw["src_ip"]

        if not ip:
            return None

        return {
            "ip_address": ip,
            "mac_address": None,
            "discovery_method": "onvif_ws_discovery",
            "xaddrs": xaddrs,
            "scopes": scopes,
            "onvif_service_url": xaddrs[0] if xaddrs else None,
            "discovered_at": datetime.utcnow().isoformat(),
            "confidence": 0.9,
            "raw_xml": raw["raw_xml"],
        }

    def discover(self) -> List[Dict]:
        """
        Perform a WS-Discovery scan and return all discovered ONVIF devices.

        Returns:
            List of device dictionaries.  Each dict contains at minimum
            ``ip_address``, ``discovery_method``, ``xaddrs``, ``scopes``,
            ``onvif_service_url``, ``discovered_at``, and ``confidence``.

        Raises:
            OSError: If the multicast socket cannot be created (non-fatal in
                the fusion engine — the caller should catch this).
        """
        logger.info("Starting ONVIF WS-Discovery (timeout=%.1fs)", self.timeout)
        devices: List[Dict] = []
        seen_ips: set = set()

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.timeout)
            sock.bind(("", self.listen_port))

            self._send_probe(sock)
            raw_responses = self._receive_responses(sock)
        except OSError as exc:
            logger.warning("ONVIF WS-Discovery socket error: %s", exc)
            return devices
        finally:
            if sock is not None:
                sock.close()

        for raw in raw_responses:
            device = self._parse_response(raw)
            if device and device["ip_address"] not in seen_ips:
                seen_ips.add(device["ip_address"])
                devices.append(device)

        logger.info("ONVIF WS-Discovery found %d device(s)", len(devices))
        return devices
