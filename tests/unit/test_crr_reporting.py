"""
Unit tests for the CRR Reporting modules:
  - NarrativeEngine
  - ReportBuilder
"""

import json
import pytest
import tempfile
from pathlib import Path

from backend.reporting.narrative_engine import NarrativeEngine, _render
from backend.reporting.report_builder import ReportBuilder, _count_by_severity, _overall_risk


# ─────────────────────────────────────────────────────────────────────────────
# Helper data factories
# ─────────────────────────────────────────────────────────────────────────────

def _make_device(ip="192.168.1.100", manufacturer="Hikvision", model="DS-2CD2142"):
    return {
        "ip_address": ip,
        "mac_address": "AA:BB:CC:11:22:33",
        "manufacturer": manufacturer,
        "model": model,
        "discovery_method": "arp",
        "discovery_methods": ["arp", "rtsp_probe"],
        "confidence": 0.95,
        "has_open_stream": True,
        "rtsp_ports": [
            {
                "port": 554,
                "streams": [{"path": "/Streaming/Channels/101", "accessible": True}],
            }
        ],
        "open_ports": [
            {"port": 80, "service": "HTTP"},
            {"port": 554, "service": "RTSP"},
        ],
    }


def _make_vuln(vuln_id="v1", title="Default credentials", severity="critical", cve=""):
    return {
        "vuln_id": vuln_id,
        "title": title,
        "severity": severity,
        "description": f"Device uses {title}",
        "cvss_score": 9.8,
        "cve_id": cve,
        "remediation": "Change default credentials immediately.",
    }


def _make_attack_path(ip="192.168.1.100", risk_level="CRITICAL", risk_score=9.0):
    return {
        "ip_address": ip,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "min_attack_complexity": 1.5,
        "shortest_path": ["entry_port_80", "vuln_defcred", "impact_config_access"],
        "attack_steps": ["Port 80/HTTP", "Default Credentials", "Config Access"],
        "mermaid_diagram": "graph LR\n    entry[\"Port 80\"] --> vuln[\"Default Creds\"]",
        "graph": {
            "nodes": [
                {"id": "entry_port_80", "type": "entry", "label": "Port 80/HTTP",
                 "metadata": {}, "description": ""},
                {"id": "vuln_defcred", "type": "vulnerability", "label": "Default Creds",
                 "metadata": {}, "description": ""},
                {"id": "impact_config_access", "type": "impact", "label": "Config Access",
                 "metadata": {"impact_type": "config_access"}, "description": ""},
            ],
            "edges": [],
        },
    }


def _make_firmware(ip="192.168.1.100"):
    return {
        "ip_address": ip,
        "firmware_version": "V5.3.0_build20170628",
        "extraction_source": "http_header:server",
        "vulnerable_firmware": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# _render helper tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRender:
    def test_basic_substitution(self):
        result = _render("Hello {name}!", name="World")
        assert result == "Hello World!"

    def test_missing_key_shows_placeholder(self):
        result = _render("Hello {name}!")
        assert "<name>" in result

    def test_extra_keys_ignored(self):
        result = _render("Hi {a}!", a="Alice", b="Bob")
        assert result == "Hi Alice!"


# ─────────────────────────────────────────────────────────────────────────────
# NarrativeEngine tests
# ─────────────────────────────────────────────────────────────────────────────

class TestNarrativeEngine:
    def test_generate_device_narrative_returns_all_keys(self):
        engine = NarrativeEngine()
        device = _make_device()
        vulns = [_make_vuln()]
        ap = _make_attack_path()
        fw = _make_firmware()
        result = engine.generate_device_narrative(device, vulns, ap, fw)
        assert "ip_address" in result
        assert "full_narrative" in result
        assert "discovery_section" in result
        assert "identification_section" in result
        assert "exploitation_sections" in result
        assert "impact_section" in result
        assert "remediation_section" in result
        assert "risk_level" in result

    def test_full_narrative_non_empty(self):
        engine = NarrativeEngine()
        result = engine.generate_device_narrative(
            _make_device(), [_make_vuln()], _make_attack_path(), _make_firmware()
        )
        assert len(result["full_narrative"]) > 100

    def test_narrative_contains_ip(self):
        engine = NarrativeEngine()
        device = _make_device(ip="10.0.0.99")
        result = engine.generate_device_narrative(device, [], _make_attack_path(ip="10.0.0.99"))
        assert "10.0.0.99" in result["full_narrative"]

    def test_exploitation_sections_count(self):
        engine = NarrativeEngine()
        vulns = [_make_vuln("v1"), _make_vuln("v2", title="No RTSP Authentication")]
        result = engine.generate_device_narrative(_make_device(), vulns, _make_attack_path())
        assert len(result["exploitation_sections"]) == 2

    def test_remediation_section_non_empty_with_vulns(self):
        engine = NarrativeEngine()
        result = engine.generate_device_narrative(
            _make_device(), [_make_vuln()], _make_attack_path()
        )
        assert len(result["remediation_section"]) > 0

    def test_narrative_with_rtsp_vuln(self):
        engine = NarrativeEngine()
        vulns = [_make_vuln(title="RTSP Authentication Bypass")]
        result = engine.generate_device_narrative(_make_device(), vulns, _make_attack_path())
        # Exploitation section should mention RTSP
        rtsp_mention = any(
            "RTSP" in s or "rtsp" in s for s in result["exploitation_sections"]
        )
        assert rtsp_mention

    def test_narrative_with_cve_vuln(self):
        engine = NarrativeEngine()
        vulns = [_make_vuln(title="Stack overflow", severity="critical", cve="CVE-2021-36260")]
        result = engine.generate_device_narrative(_make_device(), vulns, _make_attack_path())
        assert result["exploitation_sections"]

    def test_multi_protocol_discovery_in_narrative(self):
        engine = NarrativeEngine()
        device = _make_device()
        device["discovery_methods"] = ["arp", "onvif_ws_discovery", "ssdp_upnp"]
        result = engine.generate_device_narrative(device, [], _make_attack_path())
        assert "multi" in result["discovery_section"].lower() or "protocol" in result["discovery_section"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# ReportBuilder tests
# ─────────────────────────────────────────────────────────────────────────────

class TestReportBuilder:
    def _build_sample_report(self, output_dir: str) -> dict:
        builder = ReportBuilder(output_dir=output_dir)
        device = _make_device()
        vuln = _make_vuln()
        ap = _make_attack_path()
        fw = _make_firmware()
        narrative = NarrativeEngine().generate_device_narrative(device, [vuln], ap, fw)

        return builder.build(
            scan_metadata={
                "scan_id": "TEST-001",
                "network_range": "192.168.1.0/24",
                "operator": "pytest",
                "start_time": "2024-01-01T00:00:00",
                "duration": "10s",
            },
            devices=[device],
            vulnerabilities_map={"192.168.1.100": [vuln]},
            attack_paths=[ap],
            narratives=[narrative],
            firmware_map={"192.168.1.100": fw},
            formats=["html", "json", "markdown"],
        )

    def test_build_creates_all_formats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self._build_sample_report(tmpdir)
            assert "html" in paths
            assert "json" in paths
            assert "markdown" in paths

    def test_html_report_file_exists_and_non_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self._build_sample_report(tmpdir)
            html_path = Path(paths["html"])
            assert html_path.exists()
            assert html_path.stat().st_size > 1000

    def test_html_report_contains_ip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self._build_sample_report(tmpdir)
            content = Path(paths["html"]).read_text(encoding="utf-8")
            assert "192.168.1.100" in content

    def test_json_report_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self._build_sample_report(tmpdir)
            content = Path(paths["json"]).read_text(encoding="utf-8")
            data = json.loads(content)
            assert "total_devices" in data
            assert data["total_devices"] == 1

    def test_json_report_contains_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self._build_sample_report(tmpdir)
            data = json.loads(Path(paths["json"]).read_text())
            assert data["total_vulnerabilities"] == 1

    def test_markdown_report_contains_headers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = self._build_sample_report(tmpdir)
            content = Path(paths["markdown"]).read_text(encoding="utf-8")
            assert "# CCTV VAPT" in content
            assert "## Executive Summary" in content

    def test_build_empty_devices(self):
        """Report with no devices should not raise and should produce output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            builder = ReportBuilder(output_dir=tmpdir)
            paths = builder.build(
                scan_metadata={"scan_id": "T-EMPTY"},
                devices=[],
                vulnerabilities_map={},
                attack_paths=[],
                narratives=[],
                formats=["json"],
            )
            assert "json" in paths
            data = json.loads(Path(paths["json"]).read_text())
            assert data["total_devices"] == 0


class TestCountBySeverity:
    def test_basic_counts(self):
        vulns = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        counts = _count_by_severity(vulns)
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 0

    def test_empty_list(self):
        counts = _count_by_severity([])
        assert all(v == 0 for v in counts.values())


class TestOverallRisk:
    def test_critical_dominates(self):
        aps = [{"risk_level": "HIGH"}, {"risk_level": "CRITICAL"}, {"risk_level": "LOW"}]
        assert _overall_risk([], aps) == "CRITICAL"

    def test_medium_when_no_critical_or_high(self):
        aps = [{"risk_level": "MEDIUM"}, {"risk_level": "LOW"}]
        assert _overall_risk([], aps) == "MEDIUM"

    def test_info_when_empty(self):
        assert _overall_risk([], []) == "INFO"
