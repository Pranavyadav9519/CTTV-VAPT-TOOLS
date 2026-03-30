"""
RTSP Prober Module
Attempts RTSP OPTIONS / DESCRIBE on common camera stream paths
to confirm RTSP service and identify device type/manufacturer.
"""

import socket
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

_RTSP_PORTS = [554, 8554, 10554]
_RTSP_TIMEOUT = 4

# Common RTSP paths used by various manufacturers
_RTSP_PATHS = [
    "/",
    "/live/ch00_0",
    "/h264Preview_01_main",
    "/cam/realmonitor",
    "/video1",
    "/stream1",
    "/mpeg4/media.amp",
    "/Streaming/Channels/1",
    "/onvif1",
]

_CCTV_SERVER_KEYWORDS = frozenset([
    "hikvision", "dahua", "axis", "rtsp", "camera", "dvr",
    "nvr", "vivotek", "hanwha", "bosch", "samsung",
])


class RTSPProber:
    """Probe hosts for RTSP service to confirm CCTV presence."""

    def __init__(self, timeout: int = _RTSP_TIMEOUT, ports: Optional[List[int]] = None):
        self.timeout = timeout
        self.ports = ports or _RTSP_PORTS

    def probe(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Try to connect to RTSP on the given IP.
        Returns a device dict if RTSP is found, else None.
        """
        for port in self.ports:
            result = self._try_options(ip, port)
            if result:
                return result
        return None

    def probe_many(self, ip_list: List[str]) -> List[Dict[str, Any]]:
        """Probe a list of IPs and return those with RTSP."""
        found = []
        for ip in ip_list:
            result = self.probe(ip)
            if result:
                found.append(result)
        return found

    def _try_options(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Send an RTSP OPTIONS request and parse the response."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                request = (
                    f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                    "CSeq: 1\r\n"
                    "User-Agent: VAPT-Scanner/1.0\r\n"
                    "\r\n"
                )
                sock.sendall(request.encode())
                response = b""
                sock.settimeout(self.timeout)
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if b"\r\n\r\n" in response:
                            break
                except socket.timeout:
                    pass

            text = response.decode("utf-8", errors="replace")
            if not text.startswith("RTSP/"):
                return None

            server = ""
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[-1].strip()
                    break

            is_cctv = True  # All RTSP devices are treated as potential CCTV
            confidence = 0.85 if any(kw in server.lower() for kw in _CCTV_SERVER_KEYWORDS) else 0.6

            return {
                "ip_address": ip,
                "protocols": ["rtsp"],
                "is_cctv": is_cctv,
                "confidence_score": confidence,
                "rtsp_port": port,
                "raw_attributes": {"rtsp_server": server, "rtsp_port": port},
            }
        except (OSError, ConnectionRefusedError, socket.timeout):
            return None
        except Exception as e:
            logger.debug(f"RTSP probe error {ip}:{port} – {e}")
            return None
