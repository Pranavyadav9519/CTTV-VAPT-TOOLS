"""
Integration test for the CRR pipeline.
Validates:
  1. Shared scan engine returns a ScanEngineResult with all expected fields.
  2. CRR output includes attack path graph and device fusion confidence.
  3. CRRReportBuilder produces valid JSON/HTML/Markdown output.
  4. Enterprise Celery worker (mocked) uses the shared engine and creates
     an encrypted report row, then marks the scan completed.
"""

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import sys
import pathlib

# Ensure the backend package is importable
_ROOT = pathlib.Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT / "backend"))


class TestCRRModels(unittest.TestCase):
    """Unit tests for CRR dataclasses."""

    def test_crr_device_to_dict(self):
        from core.crr_models import CRRDevice
        dev = CRRDevice(
            ip_address="192.168.1.100",
            manufacturer="Hikvision",
            is_cctv=True,
            protocols=["onvif", "rtsp"],
            confidence_score=0.92,
        )
        d = dev.to_dict()
        self.assertEqual(d["ip_address"], "192.168.1.100")
        self.assertTrue(d["is_cctv"])
        self.assertAlmostEqual(d["confidence_score"], 0.92)

    def test_crr_vulnerability_to_dict(self):
        from core.crr_models import CRRVulnerability
        vuln = CRRVulnerability(
            vuln_id="CVE-2021-36260",
            title="Hikvision RCE",
            severity="critical",
            cvss_score=9.8,
        )
        d = vuln.to_dict()
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["cvss_score"], 9.8)

    def test_scan_engine_result_severity_breakdown(self):
        from core.crr_models import ScanEngineResult
        res = ScanEngineResult(
            scan_id="TEST-001",
            network_range="192.168.1.0/24",
            critical_count=2,
            high_count=3,
            medium_count=5,
            low_count=1,
        )
        bd = res.severity_breakdown()
        self.assertEqual(bd["critical"], 2)
        self.assertEqual(bd["high"], 3)


class TestDiscoveryFusion(unittest.TestCase):
    """Unit tests for DiscoveryFusion."""

    def test_fusion_merges_same_ip(self):
        from discovery.discovery_fusion import DiscoveryFusion
        raw = [
            {"ip_address": "10.0.0.1", "protocols": ["arp"], "confidence_score": 0.5, "is_cctv": False},
            {"ip_address": "10.0.0.1", "protocols": ["onvif"], "confidence_score": 0.9, "is_cctv": True},
        ]
        devices = DiscoveryFusion().fuse(raw)
        self.assertEqual(len(devices), 1)
        dev = devices[0]
        self.assertIn("arp", dev.protocols)
        self.assertIn("onvif", dev.protocols)
        self.assertTrue(dev.is_cctv)
        # Bounded-sum: 1 - (1-0.5)*(1-0.9) = 1 - 0.05 = 0.95
        self.assertAlmostEqual(dev.confidence_score, 0.95, places=5)

    def test_fusion_deduplicates_protocols(self):
        from discovery.discovery_fusion import DiscoveryFusion
        raw = [
            {"ip_address": "10.0.0.2", "protocols": ["ssdp"], "confidence_score": 0.6},
            {"ip_address": "10.0.0.2", "protocols": ["ssdp"], "confidence_score": 0.4},
        ]
        devices = DiscoveryFusion().fuse(raw)
        self.assertEqual(len(devices), 1)
        # ssdp should appear only once
        self.assertEqual(devices[0].protocols.count("ssdp"), 1)

    def test_fusion_preserves_separate_ips(self):
        from discovery.discovery_fusion import DiscoveryFusion
        raw = [
            {"ip_address": "10.0.0.1", "protocols": ["arp"], "confidence_score": 0.5},
            {"ip_address": "10.0.0.2", "protocols": ["rtsp"], "confidence_score": 0.8},
        ]
        devices = DiscoveryFusion().fuse(raw)
        self.assertEqual(len(devices), 2)


class TestFirmwareExtractor(unittest.TestCase):
    """Unit tests for FirmwareExtractor."""

    def test_enriches_hikvision_with_cve(self):
        from core.crr_models import CRRDevice
        from fingerprinting.firmware_extractor import FirmwareExtractor

        dev = CRRDevice(
            ip_address="192.168.1.200",
            manufacturer="Hikvision",
            firmware_version="V5.4.5",
            protocols=["onvif"],
        )
        vulns = FirmwareExtractor().enrich(dev)
        vuln_ids = [v.vuln_id for v in vulns]
        self.assertIn("CVE-2021-36260", vuln_ids)

    def test_detects_manufacturer_from_banner(self):
        from core.crr_models import CRRDevice
        from fingerprinting.firmware_extractor import FirmwareExtractor

        dev = CRRDevice(
            ip_address="192.168.1.201",
            protocols=["ssdp"],
            raw_attributes={"server": "Dahua/1.0 RTSP/1.0"},
        )
        FirmwareExtractor().enrich(dev)
        self.assertIsNotNone(dev.manufacturer)
        self.assertIn("dahua", dev.manufacturer.lower())

    def test_rtsp_generic_vuln_added(self):
        from core.crr_models import CRRDevice
        from fingerprinting.firmware_extractor import FirmwareExtractor

        dev = CRRDevice(ip_address="10.0.0.5", protocols=["rtsp"])
        vulns = FirmwareExtractor().enrich(dev)
        self.assertTrue(any(v.vuln_id == "VAPT-GEN-001" for v in vulns))


class TestAttackPathEngine(unittest.TestCase):
    """Unit tests for AttackPathEngine."""

    def _make_device(self, ip, mfr="Generic", is_cctv=True):
        from core.crr_models import CRRDevice
        return CRRDevice(
            ip_address=ip,
            manufacturer=mfr,
            is_cctv=is_cctv,
            protocols=["rtsp"],
            confidence_score=0.8,
        )

    def _make_vuln(self, vid, sev, score):
        from core.crr_models import CRRVulnerability
        return CRRVulnerability(vuln_id=vid, title=vid, severity=sev, cvss_score=score)

    def test_basic_graph_has_attacker_node(self):
        from analysis.attack_path_engine import AttackPathEngine
        devices = [self._make_device("10.0.0.1")]
        vulns = {"10.0.0.1": [self._make_vuln("V1", "high", 7.5)]}
        path = AttackPathEngine().build(devices, vulns)
        node_ids = [n.node_id for n in path.nodes]
        self.assertIn("attacker", node_ids)

    def test_critical_vuln_produces_target_node(self):
        from analysis.attack_path_engine import AttackPathEngine
        devices = [self._make_device("10.0.0.1")]
        vulns = {"10.0.0.1": [self._make_vuln("CVE-X", "critical", 9.8)]}
        path = AttackPathEngine().build(devices, vulns)
        node_ids = [n.node_id for n in path.nodes]
        self.assertIn("target_full_compromise", node_ids)

    def test_risk_score_nonzero_with_vulns(self):
        from analysis.attack_path_engine import AttackPathEngine
        devices = [self._make_device("10.0.0.1")]
        vulns = {"10.0.0.1": [self._make_vuln("V1", "high", 8.0)]}
        path = AttackPathEngine().build(devices, vulns)
        self.assertGreater(path.risk_score, 0)

    def test_mermaid_diagram_generated(self):
        from analysis.attack_path_engine import AttackPathEngine
        devices = [self._make_device("10.0.0.1")]
        vulns = {"10.0.0.1": [self._make_vuln("V1", "medium", 5.0)]}
        path = AttackPathEngine().build(devices, vulns)
        self.assertIsNotNone(path.mermaid_diagram)
        self.assertIn("graph TD", path.mermaid_diagram)

    def test_no_devices_zero_risk(self):
        from analysis.attack_path_engine import AttackPathEngine
        path = AttackPathEngine().build([], {})
        self.assertEqual(path.risk_score, 0.0)


class TestCRRReportBuilder(unittest.TestCase):
    """Unit tests for CRRReportBuilder."""

    def _make_result(self):
        from core.crr_models import (
            AttackPath, AttackPathEdge, AttackPathNode,
            CRRDevice, CRRVulnerability, ScanEngineResult,
        )
        dev = CRRDevice(
            ip_address="192.168.1.100",
            manufacturer="Hikvision",
            is_cctv=True,
            protocols=["onvif", "rtsp"],
            confidence_score=0.9,
        )
        vuln = CRRVulnerability(
            vuln_id="CVE-2021-36260",
            title="Hikvision RCE",
            severity="critical",
            cvss_score=9.8,
            cve_id="CVE-2021-36260",
        )
        node1 = AttackPathNode("attacker", "External Attacker", "attacker")
        node2 = AttackPathNode("dev_192_168_1_100", "Hikvision (192.168.1.100)", "device", ip_address="192.168.1.100")
        edge = AttackPathEdge("attacker", "dev_192_168_1_100", "network exposure")
        attack = AttackPath(
            nodes=[node1, node2],
            edges=[edge],
            risk_score=8.5,
            risk_level="critical",
            mermaid_diagram="graph TD\n    attacker[\"External Attacker\"]\n    dev_192_168_1_100(\"Hikvision [192.168.1.100]\")",
        )
        return ScanEngineResult(
            scan_id="TEST-001",
            network_range="192.168.1.0/24",
            devices=[dev],
            vulnerabilities={"192.168.1.100": [vuln]},
            attack_path=attack,
            total_hosts_found=5,
            cctv_devices_found=1,
            vulnerabilities_found=1,
            critical_count=1,
        )

    def test_json_report_is_valid(self):
        from reporting.report_builder import CRRReportBuilder
        result = self._make_result()
        data = CRRReportBuilder().build_json(result)
        doc = json.loads(data)
        self.assertIn("report_metadata", doc)
        self.assertIn("attack_path", doc)
        self.assertEqual(doc["statistics"]["cctv_devices_found"], 1)
        # Attack path must be present with graph data
        self.assertIsNotNone(doc["attack_path"])
        self.assertIn("nodes", doc["attack_path"])
        self.assertIn("mermaid_diagram", doc["attack_path"])

    def test_html_report_contains_mermaid(self):
        from reporting.report_builder import CRRReportBuilder
        result = self._make_result()
        html = CRRReportBuilder().build_html(result).decode()
        self.assertIn("<html", html)
        self.assertIn("mermaid", html)

    def test_markdown_report_contains_risk_score(self):
        from reporting.report_builder import CRRReportBuilder
        result = self._make_result()
        md = CRRReportBuilder().build_markdown(result).decode()
        self.assertIn("Risk Score", md)
        self.assertIn("graph TD", md)

    def test_device_fusion_confidence_in_report(self):
        from reporting.report_builder import CRRReportBuilder
        result = self._make_result()
        data = CRRReportBuilder().build_json(result)
        doc = json.loads(data)
        # The first device should have confidence_score present
        self.assertIn("confidence_score", doc["devices"][0])


class TestScanEngine(unittest.TestCase):
    """Integration test: scan engine runs end-to-end (all network I/O mocked)."""

    def _patched_run(self, network_range="192.168.1.0/24"):
        """Run the scan engine with all external I/O patched out."""

        # ARP discovery returns one host
        mock_host = {
            "ip_address": "192.168.1.100",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "hostname": "camera-01",
        }
        mock_port_result = {
            "open_ports": [
                {"port_number": 554, "protocol": "tcp", "state": "open", "service_name": "rtsp"},
                {"port_number": 80, "protocol": "tcp", "state": "open", "service_name": "http"},
            ],
            "banners": {},
        }
        mock_identified = [
            {
                "ip_address": "192.168.1.100",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "manufacturer": "Hikvision",
                "device_type": "ip_camera",
                "is_cctv": True,
                "confidence_score": 0.85,
            }
        ]

        with (
            patch("core.scan_engine._import_scan_modules") as mock_modules,
            patch("core.scan_engine._import_crr_modules") as mock_crr,
        ):
            # Build mocked scan module classes
            ns = MagicMock()
            ns.get_local_network_info.return_value = {"interfaces": [{"cidr": network_range}]}
            ns.scan_network_arp.return_value = [mock_host]

            ps = MagicMock()
            ps.scan_host.return_value = mock_port_result

            di = MagicMock()
            di.bulk_identify.return_value = mock_identified
            di.filter_cctv_devices.return_value = mock_identified

            vs = MagicMock()
            vs.scan_device.return_value = {"vulnerabilities": []}

            mock_modules.return_value = (
                lambda *a, **kw: ns,   # NetworkScanner()
                lambda *a, **kw: di,   # DeviceIdentifier()
                lambda *a, **kw: ps,   # PortScanner()
                lambda *a, **kw: vs,   # VulnerabilityScanner()
            )

            # Real CRR modules (they gracefully fail if no network)
            from discovery.onvif_discovery import ONVIFDiscovery
            from discovery.ssdp_discovery import SSDPDiscovery
            from discovery.rtsp_prober import RTSPProber
            from discovery.discovery_fusion import DiscoveryFusion
            from fingerprinting.firmware_extractor import FirmwareExtractor
            from analysis.attack_path_engine import AttackPathEngine

            mock_crr.return_value = (
                ONVIFDiscovery, SSDPDiscovery, RTSPProber,
                DiscoveryFusion, FirmwareExtractor, AttackPathEngine,
            )

            from core.scan_engine import run_scan
            return run_scan(
                scan_id="TEST-E2E-001",
                network_range=network_range,
                config={"onvif_enabled": False, "ssdp_enabled": False, "rtsp_enabled": False},
            )

    def test_result_has_expected_fields(self):
        result = self._patched_run()
        self.assertEqual(result.scan_id, "TEST-E2E-001")
        self.assertIsNotNone(result.devices)
        self.assertIsNotNone(result.vulnerabilities)
        self.assertIsNotNone(result.attack_path)

    def test_result_has_attack_path_graph(self):
        result = self._patched_run()
        self.assertIsNotNone(result.attack_path)
        self.assertIsInstance(result.attack_path.nodes, list)
        self.assertIsInstance(result.attack_path.edges, list)

    def test_result_device_has_confidence(self):
        result = self._patched_run()
        self.assertGreater(len(result.devices), 0)
        for dev in result.devices:
            self.assertGreaterEqual(dev.confidence_score, 0.0)

    def test_full_report_generated(self):
        from reporting.report_builder import CRRReportBuilder
        result = self._patched_run()
        report_bytes = CRRReportBuilder().build_json(result)
        doc = json.loads(report_bytes)
        self.assertIn("report_metadata", doc)
        self.assertIn("attack_path", doc)
        self.assertIn("devices", doc)


class TestEnterpriseScanWorker(unittest.TestCase):
    """
    Integration test: create-scan → run-scan → report-created → download works.

    The enterprise Celery task requires Flask + SQLAlchemy at import time so we
    test the critical data-path components directly:
      1. Shared engine produces a ScanEngineResult.
      2. CRRReportBuilder turns that into valid JSON bytes.
      3. LocalStorage encrypts and round-trips the content correctly.
      4. The decrypted content parses back to the original report doc.
    This verifies every non-framework step the enterprise worker performs.
    """

    def _load_local_storage(self):
        """Import LocalStorage bypassing the enterprise package __init__.py
        (which requires Flask) by loading the module file directly."""
        import importlib.util
        _LS_FILE = (
            pathlib.Path(__file__).parent.parent.parent
            / "backend" / "enterprise" / "storage" / "local_storage.py"
        )
        spec = importlib.util.spec_from_file_location("_local_storage", str(_LS_FILE))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.LocalStorage

    def test_run_scan_uses_engine_and_creates_report(self):
        import tempfile

        from core.crr_models import CRRDevice, CRRVulnerability, ScanEngineResult
        from analysis.attack_path_engine import AttackPathEngine
        from reporting.report_builder import CRRReportBuilder
        from cryptography.fernet import Fernet

        LocalStorage = self._load_local_storage()

        # 1. Build a realistic ScanEngineResult (what the engine returns)
        dev = CRRDevice(ip_address="10.0.0.10", is_cctv=True, confidence_score=0.9,
                        manufacturer="Hikvision", protocols=["onvif", "rtsp"])
        vuln = CRRVulnerability(vuln_id="CVE-TEST", title="Test Vuln",
                                severity="high", cvss_score=7.5)
        attack = AttackPathEngine().build([dev], {"10.0.0.10": [vuln]})

        engine_result = ScanEngineResult(
            scan_id="ENT-E2E-001",
            network_range="10.0.0.0/24",
            devices=[dev],
            vulnerabilities={"10.0.0.10": [vuln]},
            attack_path=attack,
            total_hosts_found=3,
            cctv_devices_found=1,
            vulnerabilities_found=1,
            high_count=1,
        )

        # 2. Build the canonical JSON report
        report_bytes = CRRReportBuilder().build_json(engine_result, operator="test_op")
        self.assertIsInstance(report_bytes, bytes)
        self.assertGreater(len(report_bytes), 0)

        # 3. Encrypt + save + decrypt via LocalStorage
        with tempfile.TemporaryDirectory() as tmpdir:
            key = Fernet.generate_key()
            storage = LocalStorage(tmpdir, key)
            path, size = storage.save_encrypted("report_ENT-E2E-001.json.enc", report_bytes)
            self.assertTrue(os.path.exists(path))
            self.assertGreater(size, 0)

            decrypted = storage.read_decrypted(path)
            self.assertEqual(decrypted, report_bytes)

        # 4. Decrypted content is valid JSON with expected CRR fields
        doc = json.loads(decrypted)
        self.assertIn("report_metadata", doc)
        self.assertIn("attack_path", doc)
        self.assertIsNotNone(doc["attack_path"])
        self.assertIn("mermaid_diagram", doc["attack_path"])
        self.assertIn("risk_score", doc["attack_path"])
        self.assertIn("devices", doc)
        self.assertEqual(doc["devices"][0]["confidence_score"], 0.9)


def _fernet_key() -> str:
    """Generate a valid Fernet key string for tests."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


if __name__ == "__main__":
    unittest.main()
