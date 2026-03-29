"""
RTSP Probe Discovery Module
Discovers CCTV cameras by actively probing common RTSP ports and sending
RTSP OPTIONS / DESCRIBE requests to validate streaming capability.

Probed ports: 554, 8554, 5554, 8080
Manufacturer-specific stream paths are tried to detect auth requirements.
"""

import socket
import re
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Default RTSP ports to probe
RTSP_PORTS = [554, 8554, 5554, 8080, 10554]

# Manufacturer-specific stream paths
STREAM_PATHS: Dict[str, List[str]] = {
    "hikvision": [
        "/Streaming/Channels/101",
        "/Streaming/Channels/1",
        "/h264/ch01/main/av_stream",
    ],
    "dahua": [
        "/cam/realmonitor?channel=1&subtype=0",
        "/cam/realmonitor?channel=1&subtype=1",
        "/live",
    ],
    "axis": [
        "/axis-media/media.amp",
        "/mpeg4/media.amp",
        "/mjpg/video.mjpg",
    ],
    "reolink": [
        "/h264Preview_01_main",
        "/h264Preview_01_sub",
        "/h265Preview_01_main",
    ],
    "generic": [
        "/live/ch00_0",
        "/stream1",
        "/media/video1",
        "/video1",
        "/live",
        "/cam/realmonitor",
        "/",
        "/1",
        "/live.sdp",
        "/h264",
        "/mpeg4",
    ],
}

# Flattened unique ordered list used when manufacturer is unknown
_ALL_PATHS: List[str] = []
_seen: set = set()
for _paths in STREAM_PATHS.values():
    for _p in _paths:
        if _p not in _seen:
            _ALL_PATHS.append(_p)
            _seen.add(_p)


def _make_rtsp_request(method: str, url: str, cseq: int = 1) -> bytes:
    """
    Build a minimal RTSP request.

    Args:
        method: RTSP method string (``OPTIONS``, ``DESCRIBE``, etc.).
        url: Full RTSP URL (e.g. ``rtsp://192.168.1.10:554/``).
        cseq: CSeq header value.

    Returns:
        UTF-8 encoded RTSP request bytes.
    """
    return (
        f"{method} {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        "User-Agent: CRR-Scanner/1.0\r\n"
        "\r\n"
    ).encode("utf-8")


def _parse_rtsp_status(response: str) -> Tuple[int, str]:
    """
    Parse the status line of an RTSP response.

    Args:
        response: Raw RTSP response string.

    Returns:
        Tuple of ``(status_code, reason_phrase)``.  Returns ``(0, "")`` on
        parse failure.
    """
    match = re.match(r"RTSP/\d\.\d\s+(\d{3})\s*(.*)", response)
    if match:
        return int(match.group(1)), match.group(2).strip()
    return 0, ""


def _parse_rtsp_headers(response: str) -> Dict[str, str]:
    """
    Parse RTSP response headers into a dict.

    Args:
        response: Raw RTSP response string.

    Returns:
        Header dict with lower-case keys.
    """
    headers: Dict[str, str] = {}
    lines = response.split("\r\n")
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def _rtsp_options(ip: str, port: int, timeout: float) -> Optional[Dict]:
    """
    Send RTSP OPTIONS to ``rtsp://<ip>:<port>/`` and return parsed info.

    Args:
        ip: Target IP address.
        port: Target RTSP port.
        timeout: Socket timeout in seconds.

    Returns:
        Dict with keys ``status_code``, ``server``, ``public_methods``, and
        ``raw_response``, or None if the connection failed.
    """
    url = f"rtsp://{ip}:{port}/"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(_make_rtsp_request("OPTIONS", url))
        raw = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()
    except (OSError, socket.timeout):
        return None

    status_code, _ = _parse_rtsp_status(raw)
    if status_code == 0:
        return None

    headers = _parse_rtsp_headers(raw)
    return {
        "status_code": status_code,
        "server": headers.get("server", ""),
        "public_methods": headers.get("public", ""),
        "raw_response": raw,
    }


def _rtsp_describe(ip: str, port: int, path: str, timeout: float) -> Optional[int]:
    """
    Send RTSP DESCRIBE for a specific stream path and return the status code.

    Args:
        ip: Target IP address.
        port: Target RTSP port.
        path: Stream path (e.g. ``/Streaming/Channels/101``).
        timeout: Socket timeout in seconds.

    Returns:
        HTTP-style status code (200, 401, 403, 404 …) or None on failure.
    """
    url = f"rtsp://{ip}:{port}{path}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(_make_rtsp_request("DESCRIBE", url))
        raw = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()
    except (OSError, socket.timeout):
        return None

    status_code, _ = _parse_rtsp_status(raw)
    return status_code if status_code else None


def _infer_manufacturer(server_header: str) -> str:
    """
    Attempt to infer the camera manufacturer from the RTSP Server header.

    Args:
        server_header: Value of the Server header.

    Returns:
        Lower-case manufacturer name or ``"unknown"``.
    """
    s = server_header.lower()
    for mfr in ["hikvision", "dahua", "axis", "reolink", "foscam", "uniview", "amcrest"]:
        if mfr in s:
            return mfr
    return "unknown"


class RTSPProber:
    """
    Discovers CCTV cameras by probing RTSP ports on target IP addresses.

    For each IP, the prober:
      1. Checks whether RTSP ports are open (TCP connect).
      2. Sends an RTSP OPTIONS request to confirm RTSP service.
      3. Tries manufacturer-specific and generic stream paths to detect
         whether authentication is required (401) or streams are open (200).

    Usage::

        prober = RTSPProber(timeout=2)
        devices = prober.probe_hosts(["192.168.1.100", "192.168.1.101"])
        for device in devices:
            print(device["ip_address"], device["rtsp_streams"])
    """

    def __init__(
        self,
        timeout: float = 2.0,
        ports: Optional[List[int]] = None,
        max_workers: int = 20,
    ) -> None:
        """
        Initialise the RTSP prober.

        Args:
            timeout: Per-connection socket timeout in seconds.
            ports: RTSP ports to probe (defaults to ``RTSP_PORTS``).
            max_workers: Thread-pool size for concurrent IP probing.
        """
        self.timeout = timeout
        self.ports = ports if ports is not None else RTSP_PORTS
        self.max_workers = max_workers

    def _probe_single_ip(self, ip: str) -> Optional[Dict]:
        """
        Probe a single IP for RTSP services across all configured ports.

        Args:
            ip: Target IPv4 address string.

        Returns:
            Device dict if at least one RTSP port responds, otherwise None.
        """
        device_ports: List[Dict] = []

        for port in self.ports:
            options = _rtsp_options(ip, port, self.timeout)
            if options is None:
                continue

            port_info: Dict = {
                "port": port,
                "status_code": options["status_code"],
                "server": options["server"],
                "public_methods": options["public_methods"],
                "streams": [],
            }

            manufacturer = _infer_manufacturer(options["server"])
            paths_to_try = (
                STREAM_PATHS.get(manufacturer, []) + STREAM_PATHS["generic"]
            )
            # Deduplicate while preserving order
            unique_paths: List[str] = list(dict.fromkeys(paths_to_try))

            for path in unique_paths[:12]:  # Cap path probes to limit noise
                status = _rtsp_describe(ip, port, path, self.timeout)
                if status in (200, 401, 403):
                    port_info["streams"].append(
                        {
                            "path": path,
                            "status_code": status,
                            "requires_auth": status in (401, 403),
                            "accessible": status == 200,
                            "url": f"rtsp://{ip}:{port}{path}",
                        }
                    )

            device_ports.append(port_info)

        if not device_ports:
            return None

        # Build summary flags
        any_open_stream = any(
            stream["accessible"]
            for p in device_ports
            for stream in p.get("streams", [])
        )
        any_auth_required = any(
            stream["requires_auth"]
            for p in device_ports
            for stream in p.get("streams", [])
        )

        # Use server header from first responding port
        server_header = next(
            (p["server"] for p in device_ports if p["server"]), ""
        )

        return {
            "ip_address": ip,
            "mac_address": None,
            "discovery_method": "rtsp_probe",
            "rtsp_ports": device_ports,
            "manufacturer_hint": _infer_manufacturer(server_header),
            "rtsp_server": server_header,
            "has_open_stream": any_open_stream,
            "has_auth_protected_stream": any_auth_required,
            "discovered_at": datetime.utcnow().isoformat(),
            "confidence": 0.85 if any_open_stream or any_auth_required else 0.6,
        }

    def probe_hosts(self, ip_list: List[str]) -> List[Dict]:
        """
        Probe a list of IP addresses for RTSP services concurrently.

        Args:
            ip_list: List of IPv4 address strings to probe.

        Returns:
            List of device dicts for hosts that responded to RTSP probes.
        """
        logger.info(
            "Starting RTSP probe on %d host(s) with %d worker(s)",
            len(ip_list),
            self.max_workers,
        )
        devices: List[Dict] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self._probe_single_ip, ip): ip for ip in ip_list}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        devices.append(result)
                except Exception as exc:
                    logger.debug("RTSP probe error for %s: %s", ip, exc)

        logger.info("RTSP probe found %d device(s) with RTSP services", len(devices))
        return devices
