"""
Shared Scan Engine
==================
Single point of truth for running the full CRR scan pipeline.
Both paths call this module:
  - Enterprise/Celery path: backend/enterprise/tasks/scan_worker.py
  - Socket.IO interactive path: backend/app.py::execute_scan

Public API
----------
    result = run_scan(
        scan_id        = "SCAN-ABC123",
        network_range  = "192.168.1.0/24",   # or None for auto-detection
        config         = {},                   # optional overrides
        progress_cb    = my_callback,          # fn(phase, progress, message)
    )
    # result is a ScanEngineResult

The progress_cb signature is:
    progress_cb(phase: str, progress: float, message: str) -> None
"""

import logging
import os
import sys
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import helpers – app.py uses bare module names (no package prefix)
# while the enterprise worker uses full `backend.*` prefixes.
# We detect the context and import accordingly.
# ---------------------------------------------------------------------------

def _import_scan_modules():
    """Import the existing scan modules regardless of Python path context."""
    # Try enterprise / full-package import first
    try:
        from backend.modules.network_scanner import NetworkScanner
        from backend.modules.device_identifier import DeviceIdentifier
        from backend.modules.port_scanner import PortScanner
        from backend.modules.vulnerability_scanner import VulnerabilityScanner
        return NetworkScanner, DeviceIdentifier, PortScanner, VulnerabilityScanner
    except ImportError:
        pass
    # Fall back to bare module names (used by app.py which adds backend/ to path)
    try:
        from modules.network_scanner import NetworkScanner
        from modules.device_identifier import DeviceIdentifier
        from modules.port_scanner import PortScanner
        from modules.vulnerability_scanner import VulnerabilityScanner
        return NetworkScanner, DeviceIdentifier, PortScanner, VulnerabilityScanner
    except ImportError as exc:
        raise ImportError(f"Cannot import scan modules: {exc}")


def _import_crr_modules():
    """Import CRR pipeline modules with fallback."""
    try:
        from backend.discovery import ONVIFDiscovery, SSDPDiscovery, RTSPProber, DiscoveryFusion
        from backend.fingerprinting import FirmwareExtractor
        from backend.analysis import AttackPathEngine
        return ONVIFDiscovery, SSDPDiscovery, RTSPProber, DiscoveryFusion, FirmwareExtractor, AttackPathEngine
    except ImportError:
        from discovery import ONVIFDiscovery, SSDPDiscovery, RTSPProber, DiscoveryFusion
        from fingerprinting import FirmwareExtractor
        from analysis import AttackPathEngine
        return ONVIFDiscovery, SSDPDiscovery, RTSPProber, DiscoveryFusion, FirmwareExtractor, AttackPathEngine


def _import_crr_models():
    try:
        from backend.core.crr_models import (
            CRRDevice, CRRVulnerability, ScanEngineResult,
        )
        return CRRDevice, CRRVulnerability, ScanEngineResult
    except ImportError:
        from core.crr_models import (
            CRRDevice, CRRVulnerability, ScanEngineResult,
        )
        return CRRDevice, CRRVulnerability, ScanEngineResult


# ---------------------------------------------------------------------------
# Default no-op progress callback
# ---------------------------------------------------------------------------

def _noop_progress(phase: str, progress: float, message: str) -> None:
    logger.debug(f"[{phase}] {progress:.0f}% – {message}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(
    scan_id: str,
    network_range: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
    progress_cb: Optional[Callable[[str, float, str], None]] = None,
):
    """
    Execute the full CRR scan pipeline and return a ScanEngineResult.

    Phases:
      1. Network discovery (ARP)
      2. Port scan + device identification
      3. CRR multi-protocol discovery (ONVIF / SSDP / RTSP)
      4. Discovery fusion + confidence scoring
      5. Firmware fingerprinting
      6. Vulnerability scanning (existing VulnerabilityScanner + FirmwareExtractor)
      7. Attack path construction

    Args:
        scan_id:       Identifier for this scan (used in logging).
        network_range: CIDR range to scan, or None to auto-detect local network.
        config:        Optional dict with override keys (see below).
        progress_cb:   Callable(phase, progress 0–100, message).

    Config keys (all optional):
        onvif_enabled    (bool, default True)
        ssdp_enabled     (bool, default True)
        rtsp_enabled     (bool, default True)
        crr_timeout      (int seconds, default 5)
        deep_vuln_scan   (bool, default True)
    """
    cfg = config or {}
    cb = progress_cb or _noop_progress

    CRRDevice, CRRVulnerability, ScanEngineResult = _import_crr_models()
    (
        ONVIFDiscovery, SSDPDiscovery, RTSPProber,
        DiscoveryFusion, FirmwareExtractor, AttackPathEngine,
    ) = _import_crr_modules()
    (
        NetworkScanner, DeviceIdentifier,
        PortScanner, VulnerabilityScanner,
    ) = _import_scan_modules()

    crr_timeout = int(cfg.get("crr_timeout", 5))
    onvif_enabled = cfg.get("onvif_enabled", True)
    ssdp_enabled = cfg.get("ssdp_enabled", True)
    rtsp_enabled = cfg.get("rtsp_enabled", True)
    deep_vuln_scan = cfg.get("deep_vuln_scan", True)

    result = ScanEngineResult(
        scan_id=scan_id,
        network_range=network_range,
    )

    # ---- Singletons --------------------------------------------------------
    network_scanner = NetworkScanner()
    device_identifier = DeviceIdentifier()
    port_scanner = PortScanner()
    vulnerability_scanner = VulnerabilityScanner()
    firmware_extractor = FirmwareExtractor()
    attack_path_engine = AttackPathEngine()
    fusion = DiscoveryFusion()

    raw_crr_results: List[Dict[str, Any]] = []

    # ========================================================================
    # PHASE 1 – Network Discovery (ARP)
    # ========================================================================
    cb("discovery", 0, "Starting network discovery…")
    hosts: List[Dict[str, Any]] = []
    resolved_range = network_range

    try:
        if not resolved_range:
            info = network_scanner.get_local_network_info()
            if info.get("interfaces"):
                iface = info["interfaces"][0]
                resolved_range = iface.get("cidr") or iface.get("network")
                result.network_range = resolved_range

        def _arp_callback(data: Dict[str, Any]) -> None:
            progress = data.get("progress", 0)
            ip = data.get("host", {}).get("ip_address", "")
            cb("discovery", progress * 0.9, f"Discovered host: {ip}")

        if resolved_range:
            hosts = network_scanner.scan_network_arp(resolved_range, _arp_callback)
        else:
            hosts = []
    except Exception as exc:
        logger.warning(f"[{scan_id}] ARP discovery error: {exc}")
        hosts = []

    result.total_hosts_found = len(hosts)
    cb("discovery", 100, f"Found {len(hosts)} hosts via ARP")

    # Seed CRR results from ARP hosts
    for host in hosts:
        raw_crr_results.append({
            "ip_address": host.get("ip_address"),
            "mac_address": host.get("mac_address"),
            "hostname": host.get("hostname"),
            "protocols": ["arp"],
            "confidence_score": 0.5,
            "raw_attributes": {},
        })

    # ========================================================================
    # PHASE 2 – Port Scan + Device Identification
    # ========================================================================
    cb("identification", 0, "Port scanning and device identification…")
    ports_data: Dict[str, List[Dict[str, Any]]] = {}
    banners_data: Dict[str, Dict] = {}

    for idx, host in enumerate(hosts):
        ip = host.get("ip_address")
        if not ip:
            continue
        try:
            port_result = port_scanner.scan_host(ip)
            ports_data[ip] = port_result.get("open_ports", [])
            banners_data[ip] = port_result.get("banners", {})
        except Exception as exc:
            logger.debug(f"[{scan_id}] Port scan failed for {ip}: {exc}")
            ports_data[ip] = []
            banners_data[ip] = {}

        progress = ((idx + 1) / max(len(hosts), 1)) * 100
        cb("identification", progress, f"Port scan complete for {ip}")

    try:
        identified = device_identifier.bulk_identify(hosts, ports_data, banners_data)
        cctv_devices = device_identifier.filter_cctv_devices(identified)
    except Exception as exc:
        logger.warning(f"[{scan_id}] Device identification failed: {exc}")
        identified = hosts
        cctv_devices = []

    # Enrich CRR results with identification info
    identified_by_ip: Dict[str, Dict] = {d.get("ip_address"): d for d in identified}
    for raw in raw_crr_results:
        ip = raw.get("ip_address")
        if ip and ip in identified_by_ip:
            dev = identified_by_ip[ip]
            raw["manufacturer"] = dev.get("manufacturer")
            raw["device_type"] = dev.get("device_type")
            raw["is_cctv"] = dev.get("is_cctv", False)
            raw["confidence_score"] = max(raw["confidence_score"], dev.get("confidence_score", 0))
            raw["open_ports"] = [p.get("port_number") for p in ports_data.get(ip, []) if p.get("port_number")]

    result.ports_data = ports_data
    cb("identification", 100, f"Identified {len(cctv_devices)} CCTV devices")

    # ========================================================================
    # PHASE 3 – CRR Multi-Protocol Discovery
    # ========================================================================
    cb("crr_discovery", 0, "Running CRR multi-protocol discovery…")

    if onvif_enabled:
        try:
            cb("crr_discovery", 10, "ONVIF WS-Discovery probe…")
            onvif_results = ONVIFDiscovery(timeout=crr_timeout).discover(resolved_range)
            raw_crr_results.extend(onvif_results)
            cb("crr_discovery", 35, f"ONVIF found {len(onvif_results)} devices")
        except Exception as exc:
            logger.warning(f"[{scan_id}] ONVIF discovery error: {exc}")

    if ssdp_enabled:
        try:
            cb("crr_discovery", 40, "SSDP/UPnP M-SEARCH probe…")
            ssdp_results = SSDPDiscovery(timeout=crr_timeout).discover(resolved_range)
            raw_crr_results.extend(ssdp_results)
            cb("crr_discovery", 65, f"SSDP found {len(ssdp_results)} devices")
        except Exception as exc:
            logger.warning(f"[{scan_id}] SSDP discovery error: {exc}")

    if rtsp_enabled:
        try:
            cb("crr_discovery", 70, "RTSP probing discovered hosts…")
            ip_list = [h.get("ip_address") for h in hosts if h.get("ip_address")]
            rtsp_results = RTSPProber(timeout=crr_timeout).probe_many(ip_list)
            raw_crr_results.extend(rtsp_results)
            cb("crr_discovery", 95, f"RTSP found {len(rtsp_results)} streams")
        except Exception as exc:
            logger.warning(f"[{scan_id}] RTSP probing error: {exc}")

    cb("crr_discovery", 100, "CRR multi-protocol discovery complete")

    # ========================================================================
    # PHASE 4 – Discovery Fusion
    # ========================================================================
    cb("fusion", 0, "Fusing discovery results…")
    crr_devices = fusion.fuse(raw_crr_results)
    result.cctv_devices_found = sum(1 for d in crr_devices if d.is_cctv)
    cb("fusion", 100, f"Fused {len(crr_devices)} unique devices (CCTV: {result.cctv_devices_found})")

    # ========================================================================
    # PHASE 5 – Firmware Fingerprinting
    # ========================================================================
    cb("fingerprinting", 0, "Fingerprinting device firmware…")
    firmware_vulns: Dict[str, List] = {}

    for idx, dev in enumerate(crr_devices):
        try:
            vulns = firmware_extractor.enrich(dev)
            if vulns:
                firmware_vulns[dev.ip_address] = vulns
        except Exception as exc:
            logger.debug(f"[{scan_id}] Firmware extract error {dev.ip_address}: {exc}")

        progress = ((idx + 1) / max(len(crr_devices), 1)) * 100
        cb("fingerprinting", progress, f"Fingerprinted {dev.ip_address}")

    cb("fingerprinting", 100, "Firmware fingerprinting complete")

    # ========================================================================
    # PHASE 6 – Vulnerability Scanning
    # ========================================================================
    cb("vulnerability", 0, "Scanning for vulnerabilities…")

    all_vulns: Dict[str, List] = {}
    total_vulns = 0
    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # Build a map for quick lookup
    crr_by_ip: Dict[str, Any] = {d.ip_address: d for d in crr_devices}

    for idx, dev_info in enumerate(identified):
        ip = dev_info.get("ip_address")
        if not ip:
            continue

        ip_vulns = list(firmware_vulns.get(ip, []))

        if dev_info.get("is_cctv"):
            try:
                vuln_result = vulnerability_scanner.scan_device(
                    dev_info, ports_data.get(ip, []), deep_scan=deep_vuln_scan
                )
                for vd in vuln_result.get("vulnerabilities", []):
                    ip_vulns.append(CRRVulnerability(
                        vuln_id=vd.get("vuln_id", "VAPT-UNK"),
                        title=vd.get("title", "Unknown"),
                        severity=vd.get("severity", "low"),
                        cvss_score=float(vd.get("cvss_score") or 0),
                        cve_id=vd.get("cve_id"),
                        cwe_id=vd.get("cwe_id"),
                        description=vd.get("description"),
                        affected_component=vd.get("affected_component"),
                        remediation=vd.get("remediation"),
                        proof_of_concept=vd.get("proof_of_concept"),
                        references=vd.get("references") or [],
                    ))
            except Exception as exc:
                logger.debug(f"[{scan_id}] VulnScan error {ip}: {exc}")

        if ip_vulns:
            all_vulns[ip] = ip_vulns
            for v in ip_vulns:
                total_vulns += 1
                sev = v.severity if hasattr(v, "severity") else v.get("severity", "low")
                if sev in severity_counts:
                    severity_counts[sev] += 1

        progress = ((idx + 1) / max(len(identified), 1)) * 100
        cb("vulnerability", progress, f"Vuln scan complete for {ip}")

    result.vulnerabilities = all_vulns
    result.vulnerabilities_found = total_vulns
    result.critical_count = severity_counts["critical"]
    result.high_count = severity_counts["high"]
    result.medium_count = severity_counts["medium"]
    result.low_count = severity_counts["low"]
    result.devices = crr_devices
    cb("vulnerability", 100, f"Found {total_vulns} vulnerabilities")

    # ========================================================================
    # PHASE 7 – Attack Path Construction
    # ========================================================================
    cb("attack_path", 0, "Building attack path graph…")
    try:
        result.attack_path = attack_path_engine.build(crr_devices, all_vulns)
        cb(
            "attack_path",
            100,
            f"Attack path: risk={result.attack_path.risk_score} "
            f"({result.attack_path.risk_level})",
        )
    except Exception as exc:
        logger.warning(f"[{scan_id}] Attack path error: {exc}")
        cb("attack_path", 100, "Attack path construction skipped (error)")

    logger.info(
        f"[{scan_id}] Scan complete – hosts={result.total_hosts_found}, "
        f"cctv={result.cctv_devices_found}, vulns={result.vulnerabilities_found}"
    )
    return result
