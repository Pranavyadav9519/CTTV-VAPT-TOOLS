"""
SSDP Discovery Module
Discovers UPnP/SSDP devices (including IP cameras) via M-SEARCH multicast.
"""

import socket
import struct
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_TIMEOUT = 3

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)

_CCTV_KEYWORDS = frozenset([
    "camera", "dvr", "nvr", "cctv", "ipcam", "hikvision",
    "dahua", "axis", "bosch", "hanwha", "vivotek", "onvif",
])


class SSDPDiscovery:
    """Discover UPnP/SSDP devices and identify likely CCTV targets."""

    def __init__(self, timeout: int = _SSDP_TIMEOUT):
        self.timeout = timeout

    def discover(self, network_range: str = None) -> List[Dict[str, Any]]:
        """
        Send M-SEARCH broadcast and collect responses.
        Returns list of device dicts.
        """
        found: Dict[str, Dict[str, Any]] = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            ttl = struct.pack("b", 4)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.sendto(_MSEARCH.encode("utf-8"), (_SSDP_ADDR, _SSDP_PORT))

            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    ip = addr[0]
                    if ip not in found:
                        found[ip] = self._parse_response(data, ip)
                    else:
                        # Merge additional ST headers
                        parsed = self._parse_response(data, ip)
                        found[ip]["raw_attributes"].update(parsed.get("raw_attributes", {}))
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"SSDP recv error: {e}")
                    break
        except OSError as e:
            logger.debug(f"SSDP multicast not available: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return list(found.values())

    def _parse_response(self, data: bytes, ip: str) -> Dict[str, Any]:
        text = data.decode("utf-8", errors="replace")
        headers: Dict[str, str] = {}
        for line in text.splitlines()[1:]:
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()

        server = headers.get("server", "")
        usn = headers.get("usn", "")
        location = headers.get("location", "")
        st = headers.get("st", "")

        combined = (server + usn + location + st).lower()
        is_cctv = any(kw in combined for kw in _CCTV_KEYWORDS)
        confidence = 0.75 if is_cctv else 0.3

        return {
            "ip_address": ip,
            "protocols": ["ssdp"],
            "is_cctv": is_cctv,
            "confidence_score": confidence,
            "raw_attributes": {
                "server": server,
                "usn": usn,
                "location": location,
                "st": st,
            },
        }
