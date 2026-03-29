"""
CRR Pipeline Orchestrator
Single entry point that runs the full CCTV Recon-to-Report (CRR) pipeline.

Pipeline Phases:
  1. Multi-Protocol Discovery  (ARP + ONVIF + SSDP + RTSP)
  2. Discovery Fusion          (deduplication + confidence scoring)
  3. Port Scanning             (CCTV-specific port set)
  4. Device Fingerprinting     (firmware extraction)
  5. Vulnerability Assessment  (existing VulnerabilityScanner)
  6. Attack Path Construction  (AttackPathEngine)
  7. Narrative Generation      (NarrativeEngine)
  8. Report Generation         (ReportBuilder)

Design principles:
  - One phase failing does NOT abort the pipeline — partial results are
    preserved and reported.
  - All phases are instrumented with timing and logging.
  - The orchestrator is backward-compatible: the existing scanning modules
    (NetworkScanner, PortScanner, VulnerabilityScanner) are reused as-is.
"""

import logging
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from pathlib import Path

from backend.core.crr_models import (
    CRRDevice,
    CRRScanSession,
    CRRVulnerability,
    ScanStatus,
)
from backend.discovery.onvif_discovery import ONVIFDiscovery
from backend.discovery.ssdp_discovery import SSDPDiscovery
from backend.discovery.rtsp_prober import RTSPProber
from backend.discovery.discovery_fusion import DiscoveryFusion
from backend.fingerprinting.firmware_extractor import FirmwareExtractor
from backend.analysis.attack_path_engine import AttackPathEngine
from backend.reporting.narrative_engine import NarrativeEngine
from backend.reporting.report_builder import ReportBuilder

logger = logging.getLogger(__name__)


def _phase(name: str) -> Callable:
    """
    Decorator factory that wraps a pipeline phase method with:
      - entry / exit logging
      - elapsed-time measurement
      - exception isolation (errors are caught and logged; pipeline continues)

    Args:
        name: Human-readable phase name for log messages.

    Returns:
        Decorator that wraps a method taking (self, session, …) → Any.
    """
    def decorator(fn: Callable) -> Callable:
        def wrapper(self, session: CRRScanSession, *args, **kwargs) -> Any:
            logger.info("[CRR] ─── Phase: %s ───────────────────────────────", name)
            t0 = time.time()
            try:
                result = fn(self, session, *args, **kwargs)
                elapsed = time.time() - t0
                logger.info("[CRR] ✔ %s completed in %.2fs", name, elapsed)
                return result
            except Exception as exc:
                elapsed = time.time() - t0
                logger.error("[CRR] ✘ %s FAILED after %.2fs: %s", name, elapsed, exc, exc_info=True)
                return None
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


class CRROrchestrator:
    """
    Orchestrates the full CRR pipeline from network scan to final report.

    Usage::

        orchestrator = CRROrchestrator()
        session = orchestrator.run(network_range="192.168.1.0/24")
        print(session.report_paths)
    """

    def __init__(
        self,
        config=None,
        output_dir: str = "reports/crr",
        progress_callback: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        """
        Initialise the orchestrator with optional configuration.

        Args:
            config: CRRSettings instance (loads defaults if None).
            output_dir: Directory for generated reports.
            progress_callback: Optional function called after each phase with
                a progress dict ``{"phase": str, "progress_pct": int, …}``.
        """
        if config is None:
            try:
                from config.settings import CRRSettings
                config = CRRSettings()
            except Exception:
                config = None

        self._config = config
        self._output_dir = output_dir
        self._progress_cb = progress_callback

        # Instantiate pipeline components
        self._onvif = ONVIFDiscovery(
            timeout=self._cfg("discovery.onvif.timeout", 3.0),
        )
        self._ssdp = SSDPDiscovery(
            timeout=self._cfg("discovery.ssdp.timeout", 3.0),
            fetch_descriptions=self._cfg("discovery.ssdp.fetch_descriptions", True),
        )
        self._rtsp_prober = RTSPProber(
            timeout=self._cfg("discovery.rtsp.timeout", 2.0),
            max_workers=self._cfg("discovery.rtsp.max_workers", 20),
        )
        self._fusion = DiscoveryFusion()
        self._firmware = FirmwareExtractor(
            timeout=self._cfg("fingerprinting.firmware.timeout", 3.0),
        )
        self._attack_path = AttackPathEngine()
        self._narrative = NarrativeEngine()
        self._report_builder = ReportBuilder(output_dir=output_dir)

    def _cfg(self, dotted_key: str, default: Any = None) -> Any:
        """Safe config accessor that falls back to default."""
        if self._config is None:
            return default
        parts = dotted_key.split(".")
        obj = self._config
        for part in parts:
            obj = getattr(obj, part, None)
            if obj is None:
                return default
        return obj if obj is not None else default

    def _progress(self, phase: str, pct: int, **extra) -> None:
        """Emit a progress event via the callback, if registered."""
        if self._progress_cb:
            try:
                self._progress_cb({"phase": phase, "progress_pct": pct, **extra})
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Pipeline phases
    # ------------------------------------------------------------------

    @_phase("1 — ARP/Socket Discovery")
    def _phase_arp_discovery(
        self, session: CRRScanSession
    ) -> List[Dict]:
        """Run ARP / socket-based discovery using the existing NetworkScanner."""
        from backend.modules.network_scanner import NetworkScanner

        scanner = NetworkScanner(
            timeout=self._cfg("scan.arp_timeout", 3),
            retry=self._cfg("scan.arp_retry", 2),
        )
        self._progress("ARP Discovery", 5)
        results = scanner.scan_network_arp(session.network_range)
        logger.info("[CRR] ARP discovery found %d host(s)", len(results))
        return results

    @_phase("2 — ONVIF WS-Discovery")
    def _phase_onvif(self, session: CRRScanSession) -> List[Dict]:
        """Run ONVIF WS-Discovery multicast probe."""
        self._progress("ONVIF Discovery", 10)
        return self._onvif.discover()

    @_phase("3 — SSDP/UPnP Discovery")
    def _phase_ssdp(self, session: CRRScanSession) -> List[Dict]:
        """Run SSDP/UPnP M-SEARCH discovery."""
        self._progress("SSDP Discovery", 15)
        return self._ssdp.discover()

    @_phase("4 — RTSP Probe")
    def _phase_rtsp_probe(
        self, session: CRRScanSession, all_ips: List[str]
    ) -> List[Dict]:
        """Probe discovered IPs for RTSP services."""
        self._progress("RTSP Probe", 20)
        return self._rtsp_prober.probe_hosts(all_ips)

    @_phase("5 — Discovery Fusion")
    def _phase_fusion(
        self,
        session: CRRScanSession,
        arp: List[Dict],
        onvif: List[Dict],
        ssdp: List[Dict],
        rtsp: List[Dict],
    ) -> List[Dict]:
        """Merge and deduplicate all discovery results."""
        self._progress("Discovery Fusion", 30)
        fused = self._fusion.fuse(
            arp_results=arp,
            onvif_results=onvif,
            ssdp_results=ssdp,
            rtsp_results=rtsp,
        )
        logger.info("[CRR] Fusion complete: %d unique device(s)", len(fused))
        return fused

    @_phase("6 — Port Scanning")
    def _phase_port_scan(
        self, session: CRRScanSession, devices: List[Dict]
    ) -> List[Dict]:
        """Scan CCTV-specific ports on all fused devices."""
        from backend.modules.port_scanner import PortScanner

        port_scanner = PortScanner()
        self._progress("Port Scanning", 40)
        enriched: List[Dict] = []
        for device in devices:
            ip = device.get("ip_address", "")
            if not ip:
                enriched.append(device)
                continue
            try:
                scan_result = port_scanner.scan_host(ip)
                device["open_ports"] = scan_result.get("open_ports", [])
            except Exception as exc:
                logger.debug("Port scan failed for %s: %s", ip, exc)
            enriched.append(device)
        return enriched

    @_phase("7 — Device Identification")
    def _phase_identify(
        self, session: CRRScanSession, devices: List[Dict]
    ) -> List[Dict]:
        """Enrich devices with manufacturer and model information."""
        from backend.modules.device_identifier import DeviceIdentifier

        identifier = DeviceIdentifier()
        self._progress("Device Identification", 50)
        identified: List[Dict] = []
        for device in devices:
            try:
                enriched = identifier.identify_device(device)
                identified.append(enriched)
            except Exception as exc:
                logger.debug("Device identification failed for %s: %s",
                              device.get("ip_address"), exc)
                identified.append(device)
        return identified

    @_phase("8 — Firmware Extraction")
    def _phase_firmware(
        self, session: CRRScanSession, devices: List[Dict]
    ) -> Dict[str, Dict]:
        """Extract firmware versions from all devices."""
        self._progress("Firmware Extraction", 60)
        return self._firmware.extract_batch(devices)

    @_phase("9 — Vulnerability Assessment")
    def _phase_vuln_scan(
        self, session: CRRScanSession, devices: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Run the vulnerability scanner on all discovered devices."""
        from backend.modules.vulnerability_scanner import VulnerabilityScanner

        vuln_scanner = VulnerabilityScanner()
        self._progress("Vulnerability Scanning", 65)
        vuln_map: Dict[str, List[Dict]] = {}
        for device in devices:
            ip = device.get("ip_address", "")
            if not ip:
                continue
            try:
                result = vuln_scanner.scan_device(device)
                vulns_raw = result.get("vulnerabilities", [])
                # Normalise to plain dicts with consistent keys
                vulns: List[Dict] = []
                for v in vulns_raw:
                    if hasattr(v, "__dict__"):
                        vd = vars(v)
                    elif isinstance(v, dict):
                        vd = v
                    else:
                        continue
                    vulns.append({
                        "vuln_id": vd.get("vuln_id") or vd.get("id") or "",
                        "title": vd.get("title") or vd.get("name") or "",
                        "severity": (vd.get("severity") or "info"),
                        "description": vd.get("description") or "",
                        "cvss_score": vd.get("cvss_score") or 0.0,
                        "cve_id": vd.get("cve_id") or "",
                        "remediation": vd.get("remediation") or "",
                        "affected_port": vd.get("affected_port"),
                        "proof_of_concept": vd.get("proof") or vd.get("proof_of_concept") or "",
                    })
                vuln_map[ip] = vulns
                logger.info("[CRR] %s: %d vulnerability/ies found", ip, len(vulns))
            except Exception as exc:
                logger.debug("Vulnerability scan failed for %s: %s", ip, exc)
                vuln_map[ip] = []
        return vuln_map

    @_phase("10 — Attack Path Analysis")
    def _phase_attack_paths(
        self,
        session: CRRScanSession,
        devices: List[Dict],
        vuln_map: Dict[str, List[Dict]],
    ) -> List[Dict]:
        """Build attack path graphs for all devices."""
        self._progress("Attack Path Analysis", 78)
        return self._attack_path.analyze_all(devices, vuln_map)

    @_phase("11 — Narrative Generation")
    def _phase_narratives(
        self,
        session: CRRScanSession,
        devices: List[Dict],
        vuln_map: Dict[str, List[Dict]],
        attack_paths: List[Dict],
        firmware_map: Dict[str, Dict],
    ) -> List[Dict]:
        """Generate attack narratives for each device."""
        self._progress("Narrative Generation", 87)
        ap_by_ip = {ap["ip_address"]: ap for ap in attack_paths}
        narratives: List[Dict] = []
        for device in devices:
            ip = device.get("ip_address", "")
            vulns = vuln_map.get(ip, [])
            ap = ap_by_ip.get(ip, {"graph": {}, "risk_level": "INFO", "attack_steps": []})
            fw = firmware_map.get(ip)
            try:
                narrative = self._narrative.generate_device_narrative(
                    device=device,
                    vulnerabilities=vulns,
                    attack_path_result=ap,
                    firmware_info=fw,
                )
                narratives.append(narrative)
            except Exception as exc:
                logger.debug("Narrative generation failed for %s: %s", ip, exc)
        return narratives

    @_phase("12 — Report Generation")
    def _phase_reports(
        self,
        session: CRRScanSession,
        devices: List[Dict],
        vuln_map: Dict[str, List[Dict]],
        attack_paths: List[Dict],
        narratives: List[Dict],
        firmware_map: Dict[str, Dict],
    ) -> Dict[str, str]:
        """Build and save reports in all configured formats."""
        self._progress("Report Generation", 93)
        discovery_summary = self._fusion.get_summary(devices)
        scan_metadata = {
            "scan_id": session.scan_id,
            "network_range": session.network_range,
            "operator": session.operator,
            "start_time": session.start_time,
            "duration": session.duration,
        }
        return self._report_builder.build(
            scan_metadata=scan_metadata,
            devices=devices,
            vulnerabilities_map=vuln_map,
            attack_paths=attack_paths,
            narratives=narratives,
            firmware_map=firmware_map,
            discovery_summary=discovery_summary,
        )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        network_range: str,
        scan_id: Optional[str] = None,
        operator: str = "CTTV-VAPT-TOOLS",
    ) -> CRRScanSession:
        """
        Execute the full CRR pipeline for a given network range.

        Args:
            network_range: CIDR notation of the target network
                (e.g. ``"192.168.1.0/24"``).
            scan_id: Optional scan identifier.  Auto-generated if omitted.
            operator: Name / identifier of the person running the scan.

        Returns:
            :class:`CRRScanSession` with all results populated.  Check
            ``session.status`` for ``COMPLETED`` or ``PARTIAL``/``FAILED``.
        """
        scan_id = scan_id or ("CRR-" + datetime.utcnow().strftime("%Y%m%d%H%M%S"))
        session = CRRScanSession(
            scan_id=scan_id,
            network_range=network_range,
            operator=operator,
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow().isoformat(),
        )
        t_total = time.time()
        logger.info(
            "[CRR] ════════════════════════════════════════════════"
        )
        logger.info("[CRR] Starting CRR Pipeline  scan_id=%s  target=%s", scan_id, network_range)
        logger.info(
            "[CRR] ════════════════════════════════════════════════"
        )

        try:
            # Phase 1-3: Discovery
            arp_results = self._phase_arp_discovery(session) or []
            onvif_results = self._phase_onvif(session) or []
            ssdp_results = self._phase_ssdp(session) or []

            # Collect all IPs for RTSP probing
            all_ips = list({
                r.get("ip_address") for r in (arp_results + onvif_results + ssdp_results)
                if r.get("ip_address")
            })
            rtsp_results = self._phase_rtsp_probe(session, all_ips) or []

            # Phase 4: Fusion
            fused_devices = self._phase_fusion(session, arp_results, onvif_results, ssdp_results, rtsp_results)
            if not fused_devices:
                logger.warning("[CRR] No devices discovered — aborting pipeline.")
                session.status = ScanStatus.PARTIAL
                session.end_time = datetime.utcnow().isoformat()
                return session

            # Phase 5-6: Enrichment
            fused_devices = self._phase_port_scan(session, fused_devices) or fused_devices
            fused_devices = self._phase_identify(session, fused_devices) or fused_devices

            # Phase 7: Firmware
            firmware_map = self._phase_firmware(session, fused_devices) or {}

            # Phase 8: Vulnerability assessment
            vuln_map = self._phase_vuln_scan(session, fused_devices) or {}

            # Phase 9: Attack path analysis
            attack_paths = self._phase_attack_paths(session, fused_devices, vuln_map) or []

            # Phase 10: Narrative generation
            narratives = self._phase_narratives(
                session, fused_devices, vuln_map, attack_paths, firmware_map
            ) or []

            # Phase 11: Reports
            report_paths = self._phase_reports(
                session, fused_devices, vuln_map, attack_paths, narratives, firmware_map
            ) or {}

            # Populate session
            session.devices = [CRRDevice(**{k: v for k, v in d.items() if k in CRRDevice.__dataclass_fields__}) if isinstance(d, dict) else d for d in fused_devices]
            session.report_paths = report_paths
            session.status = ScanStatus.COMPLETED

        except Exception as exc:
            logger.critical("[CRR] Pipeline failed with unhandled exception: %s", exc, exc_info=True)
            session.status = ScanStatus.FAILED
            session.error = str(exc)

        elapsed = time.time() - t_total
        session.end_time = datetime.utcnow().isoformat()
        session.duration = f"{elapsed:.1f}s"

        logger.info(
            "[CRR] Pipeline %s in %.1fs. Status: %s. Reports: %s",
            "completed" if session.status == ScanStatus.COMPLETED else "ended",
            elapsed,
            session.status.value,
            session.report_paths,
        )
        self._progress("Complete", 100, session_status=session.status.value)
        return session
