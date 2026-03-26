"""
Port Scanner Module
Scans for open ports and identifies services on discovered devices
"""

import socket
import ssl
import threading
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Port scanner with service detection and banner grabbing
    Focused on CCTV/DVR specific ports and services
    """

    # Common CCTV ports with service information
    CCTV_PORTS = {
        21: {"name": "FTP", "protocol": "tcp", "description": "File Transfer"},
        22: {"name": "SSH", "protocol": "tcp", "description": "Secure Shell"},
        23: {"name": "Telnet", "protocol": "tcp", "description": "Telnet Service"},
        80: {"name": "HTTP", "protocol": "tcp", "description": "Web Interface"},
        81: {"name": "HTTP-Alt", "protocol": "tcp", "description": "Alternative Web"},
        443: {"name": "HTTPS", "protocol": "tcp", "description": "Secure Web"},
        554: {"name": "RTSP", "protocol": "tcp", "description": "Real Time Streaming"},
        8554: {
            "name": "RTSP-Alt",
            "protocol": "tcp",
            "description": "Alternative RTSP",
        },
        10554: {
            "name": "RTSP-Alt2",
            "protocol": "tcp",
            "description": "Alternative RTSP",
        },
        8080: {
            "name": "HTTP-Proxy",
            "protocol": "tcp",
            "description": "Alternative Web",
        },
        8000: {"name": "Hikvision", "protocol": "tcp", "description": "Hikvision DVR"},
        8443: {
            "name": "HTTPS-Alt",
            "protocol": "tcp",
            "description": "Alternative HTTPS",
        },
        37777: {
            "name": "Dahua-DVR",
            "protocol": "tcp",
            "description": "Dahua DVR Port",
        },
        37778: {
            "name": "Dahua-Mobile",
            "protocol": "tcp",
            "description": "Dahua Mobile",
        },
        34567: {"name": "XMEye", "protocol": "tcp", "description": "XMEye DVR"},
        34599: {"name": "XMEye-Web", "protocol": "tcp", "description": "XMEye Web"},
        5000: {"name": "UPnP", "protocol": "tcp", "description": "UPnP/SSDP"},
        6036: {"name": "Hik-SDK", "protocol": "tcp", "description": "Hikvision SDK"},
        8200: {"name": "Hik-NVR", "protocol": "tcp", "description": "Hikvision NVR"},
        9000: {"name": "DVR-Service", "protocol": "tcp", "description": "DVR Service"},
        3702: {
            "name": "WS-Discovery",
            "protocol": "udp",
            "description": "ONVIF Discovery",
        },
    }

    def __init__(self, timeout: int = 5, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self._lock = threading.Lock()

    def scan_host(
        self, ip: str, ports: List[int] = None, grab_banners: bool = True, callback=None
    ) -> Dict:
        """
        Scan a single host for open ports

        Args:
            ip: Target IP address
            ports: List of ports to scan (defaults to CCTV ports)
            grab_banners: Whether to attempt banner grabbing
            callback: Progress callback function

        Returns:
            Dictionary with scan results
        """
        if ports is None:
            ports = list(self.CCTV_PORTS.keys())

        result = {
            "ip_address": ip,
            "scan_started": datetime.utcnow().isoformat(),
            "ports_scanned": len(ports),
            "open_ports": [],
            "banners": {},
            "scan_completed": None,
        }

        open_ports = []
        banners = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_port, ip, port): port for port in ports
            }

            completed = 0
            for future in as_completed(futures):
                port = futures[future]
                completed += 1

                try:
                    port_result = future.result()
                    if port_result["state"] == "open":
                        open_ports.append(port_result)

                        # Attempt banner grabbing for open ports
                        if grab_banners:
                            banner = self._grab_banner(ip, port)
                            if banner:
                                banners[port] = banner
                                port_result["banner"] = banner

                    if callback:
                        callback(
                            {
                                "type": "port_scanned",
                                "ip": ip,
                                "port": port,
                                "state": port_result["state"],
                                "progress": (completed / len(ports)) * 100,
                            }
                        )

                except Exception as e:
                    logger.debug(f"Error scanning {ip}:{port} - {e}")

        result["open_ports"] = open_ports
        result["banners"] = banners
        result["scan_completed"] = datetime.utcnow().isoformat()

        return result

    def _check_port(self, ip: str, port: int) -> Dict:
        """Check if a single port is open with improved error handling"""
        result = {
            "port_number": port,
            "protocol": "tcp",
            "state": "closed",
            "service_name": self.CCTV_PORTS.get(port, {}).get("name", "unknown"),
            "service_version": None,
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            connection_result = sock.connect_ex((ip, port))

            if connection_result == 0:
                result["state"] = "open"

                # Get service info from our database
                port_info = self.CCTV_PORTS.get(port, {})
                result["service_name"] = port_info.get("name", "unknown")
                result["description"] = port_info.get("description", "")

            sock.close()

        except socket.timeout:
            result["state"] = "filtered"
        except socket.gaierror:
            result["state"] = "error"
            result["error"] = "DNS resolution failed"
        except socket.error as e:
            logger.debug(f"Socket error on {ip}:{port} - {e}")
            result["state"] = "error"
            result["error"] = str(e)
        except Exception as e:
            logger.debug(f"Unexpected error on {ip}:{port} - {e}")
            result["state"] = "error"
            result["error"] = str(e)

        return result

    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt to grab service banner"""
        banner = None

        try:
            # Different banner grabbing strategies based on port
            if port in [80, 8080, 8000, 8081]:
                banner = self._grab_http_banner(ip, port)
            elif port == 443 or port == 8443:
                banner = self._grab_https_banner(ip, port)
            elif port == 554:
                banner = self._grab_rtsp_banner(ip, port)
            elif port in [21]:
                banner = self._grab_ftp_banner(ip, port)
            elif port in [23]:
                banner = self._grab_telnet_banner(ip, port)
            else:
                banner = self._grab_generic_banner(ip, port)

        except Exception as e:
            logger.debug(f"Banner grab failed for {ip}:{port} - {e}")

        return banner

    def _grab_http_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab HTTP banner by sending HEAD request"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = sock.recv(2048).decode("utf-8", errors="ignore")
            sock.close()

            # Extract relevant headers
            lines = response.split("\r\n")
            banner_parts = []

            for line in lines[:15]:  # First 15 lines
                if any(
                    x in line.lower()
                    for x in [
                        "server:",
                        "www-authenticate:",
                        "x-powered-by:",
                        "set-cookie:",
                        "content-type:",
                    ]
                ):
                    banner_parts.append(line.strip())
                elif line.startswith("HTTP/"):
                    banner_parts.append(line.strip())

            return " | ".join(banner_parts) if banner_parts else None

        except Exception as e:
            logger.debug(f"HTTP banner grab failed: {e}")
            return None

    def _grab_https_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab HTTPS banner with SSL"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            ssl_sock = context.wrap_socket(sock, server_hostname=ip)
            ssl_sock.connect((ip, port))

            # Get certificate info (not used further)

            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            ssl_sock.send(request.encode())

            response = ssl_sock.recv(2048).decode("utf-8", errors="ignore")
            ssl_sock.close()

            # Extract server header
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.strip()

            return "HTTPS Service Detected"

        except Exception as e:
            logger.debug(f"HTTPS banner grab failed: {e}")
            return None

    def _grab_rtsp_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab RTSP banner using OPTIONS request"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # RTSP OPTIONS request
            request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(request.encode())

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            # Parse RTSP response
            lines = response.split("\r\n")
            for line in lines:
                if line.startswith("RTSP/") or "Server:" in line:
                    return line.strip()

            return "RTSP Service Detected"

        except Exception as e:
            logger.debug(f"RTSP banner grab failed: {e}")
            return None

    def _grab_ftp_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab FTP banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            return response.strip() if response else None

        except Exception as e:
            logger.debug(f"FTP banner grab failed: {e}")
            return None

    def _grab_telnet_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab Telnet banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            # Clean up telnet control characters
            import re

            clean_response = re.sub(r"[\x00-\x1f\x7f-\xff]", "", response)

            return (
                clean_response.strip() if clean_response.strip() else "Telnet Service"
            )

        except Exception as e:
            logger.debug(f"Telnet banner grab failed: {e}")
            return None

    def _grab_generic_banner(self, ip: str, port: int) -> Optional[str]:
        """Generic banner grab for unknown services"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send probe
            sock.send(b"\r\n")

            response = sock.recv(512)
            sock.close()

            if response:
                # Try to decode as UTF-8
                try:
                    return response.decode("utf-8", errors="ignore").strip()[:200]
                except Exception:
                    return response.hex()[:100]

            return None

        except Exception as e:
            logger.debug(f"Generic banner grab failed: {e}")
            return None

    def scan_multiple_hosts(
        self, hosts: List[str], ports: List[int] = None, callback=None
    ) -> Dict[str, Dict]:
        """Scan multiple hosts for open ports"""
        results = {}
        total = len(hosts)

        for idx, ip in enumerate(hosts):
            logger.info(f"Scanning host {idx + 1}/{total}: {ip}")

            try:
                result = self.scan_host(ip, ports)
                results[ip] = result

                if callback:
                    callback(
                        {
                            "type": "host_completed",
                            "ip": ip,
                            "open_ports": len(result["open_ports"]),
                            "progress": ((idx + 1) / total) * 100,
                        }
                    )

            except Exception as e:
                logger.error(f"Error scanning {ip}: {e}")
                results[ip] = {"error": str(e)}

        return results
