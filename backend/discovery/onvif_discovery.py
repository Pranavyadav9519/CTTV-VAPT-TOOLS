"""
ONVIF Discovery Module
Probes for ONVIF-compatible cameras via WS-Discovery multicast
and direct HTTP probing on port 80/8080/8000.
"""

import socket
import struct
import uuid
import logging
from typing import List, Dict, Any
from urllib.request import urlopen
from urllib.error import URLError
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

_WS_DISCOVERY_ADDR = "239.255.255.250"
_WS_DISCOVERY_PORT = 3702
_PROBE_TIMEOUT = 3

_PROBE_MSG = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    '<s:Header>'
    '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
    '<a:MessageID>uuid:{msg_id}</a:MessageID>'
    '<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
    '</s:Header>'
    '<s:Body>'
    '<d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>'
    '</s:Body>'
    '</s:Envelope>'
)


class ONVIFDiscovery:
    """Discover ONVIF cameras via WS-Discovery multicast."""

    def __init__(self, timeout: int = _PROBE_TIMEOUT):
        self.timeout = timeout

    def discover(self, network_range: str = None) -> List[Dict[str, Any]]:
        """
        Send WS-Discovery probe and collect responses.
        Returns a list of device dicts with at minimum {'ip_address', 'protocols': ['onvif']}.
        Falls back gracefully if multicast is not available.
        """
        found: List[Dict[str, Any]] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            ttl = struct.pack("b", 4)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

            msg = _PROBE_MSG.format(msg_id=str(uuid.uuid4())).encode("utf-8")
            sock.sendto(msg, (_WS_DISCOVERY_ADDR, _WS_DISCOVERY_PORT))

            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    ip = addr[0]
                    device = self._parse_probe_match(data, ip)
                    found.append(device)
                    logger.debug(f"ONVIF: discovered {ip}")
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"ONVIF recv error: {e}")
                    break
        except OSError as e:
            logger.debug(f"ONVIF multicast not available: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return found

    def _parse_probe_match(self, data: bytes, ip: str) -> Dict[str, Any]:
        device: Dict[str, Any] = {
            "ip_address": ip,
            "protocols": ["onvif"],
            "is_cctv": True,
            "confidence_score": 0.9,
            "raw_attributes": {},
        }
        try:
            root = ET.fromstring(data.decode("utf-8", errors="replace"))
            ns = {
                "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
                "dn": "http://www.onvif.org/ver10/network/wsdl",
            }
            scopes = root.find(".//d:Scopes", ns)
            if scopes is not None and scopes.text:
                device["raw_attributes"]["scopes"] = scopes.text
                for scope in scopes.text.split():
                    if "/name/" in scope:
                        device["model"] = scope.split("/name/")[-1]
                    if "/hardware/" in scope:
                        device["raw_attributes"]["hardware"] = scope.split("/hardware/")[-1]
                    if "/location/" in scope:
                        pass
            xaddrs = root.find(".//d:XAddrs", ns)
            if xaddrs is not None and xaddrs.text:
                device["raw_attributes"]["xaddrs"] = xaddrs.text
        except ET.ParseError:
            pass
        return device
