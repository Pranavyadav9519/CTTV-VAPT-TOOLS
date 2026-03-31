"""
Network Scanner Module
Discovers devices on the local network using ARP scanning and service detection
"""

import socket
import threading
import ipaddress
from typing import List, Dict, Optional
from datetime import datetime
import netifaces
import logging

try:
    from scapy.all import ARP, Ether, srp, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Network scanner for discovering devices on local network
    Uses ARP scanning for reliable device discovery
    """

    def __init__(self, timeout: int = 3, retry: int = 2):
        self.timeout = timeout
        self.retry = retry
        self.discovered_hosts = []
        self._lock = threading.Lock()

        if SCAPY_AVAILABLE:
            conf.verb = 0  # Disable scapy verbosity

    def get_local_network_info(self) -> Dict:
        """
        Get information about local network interfaces
        Returns the primary interface details
        """
        interfaces = []

        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)

                # Skip loopback
                if iface == "lo" or iface.startswith("lo"):
                    continue

                # Get IPv4 address
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get("addr")
                        netmask = addr_info.get("netmask")

                        if ip and netmask and not ip.startswith("127."):
                            # Calculate network range
                            network = self._calculate_network(ip, netmask)

                            # Get MAC address
                            mac = None
                            if netifaces.AF_LINK in addrs:
                                mac = (
                                    addrs[netifaces.AF_LINK][0].get("addr", "")
                                    .upper()
                                )

                            interfaces.append(
                                {
                                    "interface": iface,
                                    "ip_address": ip,
                                    "netmask": netmask,
                                    "mac_address": mac,
                                    "network": str(network),
                                    "gateway": self._get_gateway(iface),
                                }
                            )
            except Exception as e:
                logger.debug(f"Error getting info for interface {iface}: {e}")
                continue

        # Return primary interface (prefer non-virtual interfaces)
        for iface_info in interfaces:
            if not any(
                x in iface_info["interface"].lower()
                for x in ["docker", "veth", "br-", "virbr", "vbox", "virtualbox", "vmnet", "vmware"]
            ):
                return iface_info

        return interfaces[0] if interfaces else {}

    def _calculate_network(self, ip: str, netmask: str) -> ipaddress.IPv4Network:
        """Calculate network address from IP and netmask"""
        try:
            # Convert netmask to CIDR prefix length
            netmask_bits = bin(
                int.from_bytes(socket.inet_aton(netmask), "big")
            ).count("1")
            network = ipaddress.IPv4Network(
                f"{ip}/{netmask_bits}", strict=False
            )
            return network
        except Exception as e:
            logger.error(f"Error calculating network: {e}")
            return ipaddress.IPv4Network(f"{ip}/24", strict=False)

    def _get_gateway(self, interface: str) -> Optional[str]:
        """Get default gateway for interface"""
        try:
            gateways = netifaces.gateways()
            default_gw = gateways.get("default", {}).get(netifaces.AF_INET)
            if default_gw:
                return str(default_gw[0])
        except Exception as e:
            logger.debug(f"Error getting gateway: {e}")
        return ""

    def scan_network_arp(self, network_range: str, callback=None) -> List[Dict]:
        """
        Scan network using ARP requests with privilege detection and error handling

        Args:
            network_range: CIDR notation (e.g., "192.168.1.0/24")
            callback: Optional callback function for progress updates

        Returns:
            List of discovered hosts with IP and MAC addresses
        """
        if not SCAPY_AVAILABLE:
            logger.warning(
                "Scapy not available, falling back to socket scan"
            )
            return self.scan_network_socket(network_range, callback)

        # Check privileges before attempting ARP scan
        if not self._check_privileges():
            logger.warning(
                "Insufficient privileges for ARP scanning, "
                "falling back to socket scan"
            )
            return self.scan_network_socket(network_range, callback)

        logger.info(
            f"Starting ARP scan on {network_range}"
        )
        discovered = []

        try:
            # Validate network range
            try:
                network = ipaddress.IPv4Network(
                    network_range, strict=False
                )
            except ValueError as e:
                raise ValueError(
                    f"Invalid network range: {network_range}"
                ) from e

            # Limit hosts scanned to reasonable number (exclude network/broadcast)
            # (previously assigned to `total_hosts` but unused)

            # Craft ARP request with timeout
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                pdst=str(network)
            )

            # Send and receive with retry logic
            max_attempts = 3
            for attempt in range(max_attempts):
                try:
                    answered, unanswered = srp(
                        arp_request,
                        timeout=self.timeout,
                        retry=self.retry,
                        verbose=False,
                    )
                    break
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    logger.debug(
                        f"ARP scan attempt {attempt + 1} failed, "
                        f"retrying: {e}"
                    )
                    continue

            for idx, (sent, received) in enumerate(answered):
                host_info = {
                    "ip_address": received.psrc,
                    "mac_address": received.hwsrc.upper(),
                    "discovered_at": datetime.utcnow().isoformat(),
                    "discovery_method": "arp",
                }
                discovered.append(host_info)

                if callback:
                    progress = (idx + 1) / len(answered) * 100 if answered else 0
                    callback(
                        {
                            "type": "host_discovered",
                            "host": host_info,
                            "progress": progress,
                        }
                    )

            logger.info(f"ARP scan complete. Found {len(discovered)} hosts")

        except PermissionError:
            logger.error(
                "Permission denied. Run with elevated privileges for ARP scanning"
            )
            raise PermissionError(
                "Root/Administrator privileges required for ARP scanning"
            )
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            # Return partial results instead of failing completely
            if discovered:
                logger.info(
                    f"Returning {len(discovered)} hosts discovered before failure"
                )
                return discovered
            raise

        self.discovered_hosts = discovered
        return discovered

    def _check_privileges(self) -> bool:
        """Check if we have sufficient privileges for ARP scanning"""
        try:
            import os

            if os.name == "nt":  # Windows
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix-like
                return os.geteuid() == 0
        except Exception:
            return False

    def scan_network_socket(self, network_range: str, callback=None) -> List[Dict]:
        """
        Fallback network scan using socket connections
        Less reliable than ARP but doesn't require elevated privileges
        """
        logger.info(f"Starting socket-based scan on {network_range}")
        discovered = []

        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            total = len(hosts)

            threads = []
            results = []

            def check_host(ip):
                """Check if host is alive by attempting connection"""
                ip_str = str(ip)
                ports_to_check = [
                    # Core web / RTSP
                    80, 443, 554, 8080,
                    # Manufacturer-specific CCTV ports
                    37777,   # Dahua DVR
                    34567,   # XMEye / generic DVR
                    8000,    # Hikvision SDK
                    8554,    # RTSP alternate
                    9000,    # Hikvision ISAPI
                    5000,    # Various
                    8899,    # Reolink
                    6036,    # Uniview
                    7777,    # Dahua debug
                    3702,    # ONVIF WS-Discovery
                    8443,    # HTTPS alternate
                    10554,   # RTSP alternate 2
                ]

                for port in ports_to_check:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip_str, port))
                        sock.close()

                        if result == 0:
                            with self._lock:
                                results.append(
                                    {
                                        "ip_address": ip_str,
                                        "mac_address": None,
                                        "discovered_at": datetime.utcnow().isoformat(),
                                        "discovery_method": "socket",
                                        "open_port": port,
                                    }
                                )
                            return True
                    except Exception:
                        continue
                return False

            # Scan in batches
            batch_size = 50
            for i in range(0, len(hosts), batch_size):
                batch = hosts[i : i + batch_size]
                threads = []

                for ip in batch:
                    t = threading.Thread(target=check_host, args=(ip,))
                    t.start()
                    threads.append(t)

                for t in threads:
                    t.join()

                if callback:
                    progress = min(((i + batch_size) / total) * 100, 100)
                    callback(
                        {
                            "type": "progress",
                            "progress": progress,
                            "hosts_found": len(results),
                        }
                    )

            discovered = results
            logger.info(f"Socket scan complete. Found {len(discovered)} hosts")

        except Exception as e:
            logger.error(f"Socket scan failed: {e}")
            raise

        self.discovered_hosts = discovered
        return discovered

    def get_hostname(self, ip: str) -> Optional[str]:
        """Attempt to resolve hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            return ""
        except Exception as e:
            logger.debug(f"Hostname resolution failed for {ip}: {e}")
            return ""

    def enrich_host_info(self, host: Dict) -> Dict:
        """
        Enrich host information with hostname and manufacturer
        """
        ip = host.get("ip_address")
        mac = host.get("mac_address")

        # Try to get hostname
        hostname = self.get_hostname(ip)
        if hostname:
            host["hostname"] = hostname

        # Get manufacturer from MAC OUI
        if mac:
            host["manufacturer"] = self._get_manufacturer(mac)

        return host

    def _get_manufacturer(self, mac: str) -> Optional[str]:
        """Get manufacturer from MAC address OUI"""
        from config import Config
        if not mac:
            return "Unknown"

        mac = mac.upper().replace("-", ":")
        parts = mac.split(":")
        if len(parts) < 3:
            return "Unknown"

        oui = ":".join(parts[:3])
        return Config.CCTV_OUI_PREFIXES.get(oui, "Unknown")


class NetworkInfo:
    """Utility class for network information"""

    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except Exception:
            return False
