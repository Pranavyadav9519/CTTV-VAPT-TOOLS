"""
Internet Scanner Module
Custom internet-facing CCTV device scanner (own Shodan-like logic).
Performs direct TCP connect scanning on specified IP targets,
grabs service banners, and fingerprints CCTV devices.
No third-party API required.
"""

import socket
import ssl
import ipaddress
import logging
import time
import re
from typing import Dict, List, Optional, Callable, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logger = logging.getLogger(__name__)

# CCTV-specific ports to scan
CCTV_PORTS = [554, 8000, 37777, 34567, 80, 443, 8080, 8554, 9000, 6036]

# Port → service name mapping
PORT_SERVICE_MAP = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8080: "HTTP-Alt",
    8000: "Hikvision",
    8554: "RTSP-Alt",
    9000: "DVR-Service",
    6036: "Hik-SDK",
    37777: "Dahua-DVR",
    34567: "XMEye",
}

# CCTV device fingerprint signatures (banner → brand/type)
CCTV_SIGNATURES = [
    {
        "pattern": re.compile(r"hikvision|hik-connect|webs/index\.html.*DVR", re.IGNORECASE),
        "manufacturer": "Hikvision",
        "device_type": "IP Camera / DVR",
    },
    {
        "pattern": re.compile(r"dahua|dav|ipc-h[a-z0-9]+|nvr[0-9]", re.IGNORECASE),
        "manufacturer": "Dahua",
        "device_type": "IP Camera / NVR",
    },
    {
        "pattern": re.compile(r"axis|vapix|axiscam", re.IGNORECASE),
        "manufacturer": "Axis",
        "device_type": "IP Camera",
    },
    {
        "pattern": re.compile(r"xmeye|xm530|xm710|ipc_web", re.IGNORECASE),
        "manufacturer": "XMEye",
        "device_type": "DVR / NVR",
    },
    {
        "pattern": re.compile(r"foscam|ipcam_www", re.IGNORECASE),
        "manufacturer": "Foscam",
        "device_type": "IP Camera",
    },
    {
        "pattern": re.compile(r"rtsp/1\.[01]", re.IGNORECASE),
        "manufacturer": "Generic RTSP",
        "device_type": "IP Camera / RTSP Device",
    },
    {
        "pattern": re.compile(r"server:.*camera|nvr|dvr|cctv|ipcam|webcam", re.IGNORECASE),
        "manufacturer": "Generic CCTV",
        "device_type": "IP Camera / DVR / NVR",
    },
]


class InternetScanner:
    """
    Custom internet CCTV scanner.
    Performs multi-threaded TCP connect scanning, banner grabbing,
    and CCTV device fingerprinting on user-supplied IP targets.
    """

    def __init__(
        self,
        timeout: float = 3.0,
        max_workers: int = 100,
        rate_limit_delay: float = 0.1,
        max_hosts: int = 1024,
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.max_hosts = max_hosts

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_target(self, target: str) -> bool:
        """Return True if target can be parsed into at least one IP address."""
        ips = self._parse_target(target)
        return len(ips) > 0

    def scan_target(
        self,
        target: str,
        callback: Optional[Callable] = None,
    ) -> List[Dict]:
        """
        Main entry point.  Accepts:
          - Single IP:            "203.0.113.50"
          - CIDR range:           "203.0.113.0/28"
          - Dash range:           "203.0.113.1-203.0.113.20"

        Returns a list of host_info dicts compatible with
        device_identifier.bulk_identify().
        """
        ips = self._parse_target(target)
        if not ips:
            logger.warning("internet_scanner: no IPs parsed from target %r", target)
            return []

        if len(ips) > self.max_hosts:
            logger.warning(
                "internet_scanner: target %r resolves to %d hosts which exceeds max_hosts=%d; truncating",
                target,
                len(ips),
                self.max_hosts,
            )
            ips = ips[: self.max_hosts]

        results: List[Dict] = []
        total = len(ips)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.scan_single_ip, str(ip)): str(ip)
                for ip in ips
            }

            for future in as_completed(futures):
                ip = futures[future]
                completed += 1
                try:
                    host_info = future.result()
                    if host_info:
                        results.append(host_info)
                        if callback:
                            callback(
                                {
                                    "type": "host_discovered",
                                    "host": host_info,
                                    "progress": (completed / total) * 100,
                                }
                            )
                    else:
                        if callback:
                            callback(
                                {
                                    "type": "host_skipped",
                                    "ip": ip,
                                    "progress": (completed / total) * 100,
                                }
                            )
                except Exception as exc:
                    logger.debug("internet_scanner: error scanning %s: %s", ip, exc)

                if self.rate_limit_delay:
                    time.sleep(self.rate_limit_delay)

        return results

    def scan_single_ip(self, ip: str, callback: Optional[Callable] = None) -> Optional[Dict]:
        """
        Scan one IP address for all CCTV ports.
        Returns a host_info dict if any ports are open, else None.
        """
        open_ports: List[Dict] = []
        banners: Dict[int, str] = {}

        for port in CCTV_PORTS:
            if self._is_port_open(ip, port):
                service_name = PORT_SERVICE_MAP.get(port, "unknown")
                open_ports.append(
                    {
                        "port_number": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service_name": service_name,
                    }
                )
                banner = self._grab_banner(ip, port)
                if banner:
                    banners[port] = banner

        if not open_ports:
            return None

        host_info = self._fingerprint_device(ip, open_ports, banners)

        if callback:
            callback({"type": "ip_scanned", "ip": ip, "open_ports": len(open_ports)})

        return host_info

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_target(self, target: str) -> List[ipaddress.IPv4Address]:
        """Parse target string into a flat list of IPv4Address objects."""
        target = target.strip()

        # Dash range: "x.x.x.a-x.x.x.b" or "x.x.x.a-b"
        dash_match_full = re.match(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
            target,
        )
        dash_match_short = re.match(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$",
            target,
        )

        try:
            if dash_match_full:
                start = int(ipaddress.IPv4Address(dash_match_full.group(1)))
                end = int(ipaddress.IPv4Address(dash_match_full.group(2)))
                return [ipaddress.IPv4Address(i) for i in range(start, end + 1)]

            if dash_match_short:
                prefix = dash_match_short.group(1)
                start_oct = int(dash_match_short.group(2))
                end_oct = int(dash_match_short.group(3))
                return [
                    ipaddress.IPv4Address(f"{prefix}{i}")
                    for i in range(start_oct, end_oct + 1)
                ]

            # CIDR network
            network = ipaddress.IPv4Network(target, strict=False)
            # Limit to /16 to prevent accidental huge scans
            if network.prefixlen < 16:
                logger.warning(
                    "internet_scanner: refusing to scan a range larger than /16 (%s)",
                    target,
                )
                return []
            return list(network.hosts())

        except ValueError:
            pass

        # Single IP
        try:
            return [ipaddress.IPv4Address(target)]
        except ValueError:
            logger.error("internet_scanner: cannot parse target %r", target)
            return []

    def _is_port_open(self, ip: str, port: int) -> bool:
        """Return True if the TCP port is open (connects within timeout)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except OSError:
            return False

    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab a service banner from an open port."""
        try:
            if port in (80, 8080, 8000, 8081):
                return self._grab_http_banner(ip, port)
            if port in (443, 8443):
                return self._grab_https_banner(ip, port)
            if port in (554, 8554):
                return self._grab_rtsp_banner(ip, port)
            return self._grab_generic_banner(ip, port)

        except Exception as exc:
            logger.debug("internet_scanner: banner grab %s:%d failed: %s", ip, port, exc)
            return None

    def _grab_http_banner(self, ip: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
            )
            response = sock.recv(2048).decode("utf-8", errors="ignore")
            sock.close()

            parts = []
            for line in response.split("\r\n")[:15]:
                if line.startswith("HTTP/") or any(
                    line.lower().startswith(h)
                    for h in ("server:", "www-authenticate:", "x-powered-by:", "set-cookie:")
                ):
                    parts.append(line.strip())

            return " | ".join(parts) if parts else None
        except Exception:
            return None

    def _grab_https_banner(self, ip: str, port: int) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            ssl_sock = ctx.wrap_socket(sock, server_hostname=ip)
            ssl_sock.connect((ip, port))
            ssl_sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
            )
            response = ssl_sock.recv(2048).decode("utf-8", errors="ignore")
            ssl_sock.close()
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.strip()
            return "HTTPS Service Detected"
        except Exception:
            return None

    def _grab_rtsp_banner(self, ip: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
            )
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            for line in response.split("\r\n"):
                if line.startswith("RTSP/") or line.lower().startswith("server:"):
                    return line.strip()
            return "RTSP Service Detected"
        except Exception:
            return None

    def _grab_generic_banner(self, ip: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(b"\r\n")
            response = sock.recv(512)
            sock.close()
            if response:
                return response.decode("utf-8", errors="ignore").strip()[:200]
            return None

        except Exception:
            return None

    def _fingerprint_device(
        self,
        ip: str,
        open_ports: List[Dict],
        banners: Dict[int, str],
    ) -> Dict:
        """
        Match collected banners against CCTV signatures and return
        a host_info dict compatible with device_identifier.bulk_identify().
        """
        combined_banner = " ".join(str(v) for v in banners.values())

        manufacturer = "Unknown"
        device_type = "Network Device"
        is_cctv = False
        confidence_score = 0.0

        for sig in CCTV_SIGNATURES:
            if sig["pattern"].search(combined_banner):
                manufacturer = sig["manufacturer"]
                device_type = sig["device_type"]
                is_cctv = True
                confidence_score = 0.85
                break

        # Heuristic boost: CCTV-specific ports open without banner match
        cctv_specific = {554, 8000, 37777, 34567, 6036, 8554, 9000}
        open_port_numbers = {p["port_number"] for p in open_ports}
        if not is_cctv and open_port_numbers & cctv_specific:
            is_cctv = True
            confidence_score = 0.60
            device_type = "Possible CCTV Device"

        return {
            "ip_address": ip,
            "mac_address": None,
            "manufacturer": manufacturer,
            "device_type": device_type,
            "is_cctv": is_cctv,
            "confidence_score": confidence_score,
            "open_ports": open_ports,
            "banners": banners,
            "discovery_method": "internet_scan",
            "discovered_at": datetime.utcnow().isoformat(),
        }
