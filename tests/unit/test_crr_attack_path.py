"""
Unit tests for the AttackPathEngine.
"""

import pytest
from backend.analysis.attack_path_engine import (
    AttackPathEngine,
    AttackGraph,
    APNode,
    APEdge,
    NodeType,
    _port_to_entry_nodes,
    _vuln_to_node,
    _build_impact_nodes,
)


class TestAPNode:
    def test_hash_equality(self):
        n1 = APNode("entry_80", NodeType.ENTRY, "Port 80")
        n2 = APNode("entry_80", NodeType.ENTRY, "Port 80")
        assert n1 == n2
        assert hash(n1) == hash(n2)

    def test_inequality(self):
        n1 = APNode("entry_80", NodeType.ENTRY, "Port 80")
        n2 = APNode("entry_554", NodeType.ENTRY, "Port 554")
        assert n1 != n2


class TestPortToEntryNodes:
    def test_rtsp_port(self):
        nodes = _port_to_entry_nodes({"port": 554, "service": "RTSP"})
        assert len(nodes) == 1
        assert nodes[0].metadata["complexity_key"] == "rtsp_open"

    def test_http_port(self):
        nodes = _port_to_entry_nodes({"port": 80, "service": "HTTP"})
        assert nodes[0].metadata["complexity_key"] == "http_open"

    def test_telnet_port(self):
        nodes = _port_to_entry_nodes({"port": 23, "service": "Telnet"})
        assert nodes[0].metadata["complexity_key"] == "telnet_open"

    def test_unknown_port(self):
        nodes = _port_to_entry_nodes({"port": 9999, "service": "Unknown"})
        assert nodes[0].metadata["complexity_key"] == "default"


class TestVulnToNode:
    def test_default_creds_complexity(self):
        vuln = {"vuln_id": "v1", "title": "Default credentials", "severity": "critical"}
        node = _vuln_to_node(vuln)
        assert node.metadata["complexity_key"] == "default_creds"

    def test_rtsp_auth_complexity(self):
        vuln = {"vuln_id": "v2", "title": "RTSP Authentication Bypass", "severity": "critical"}
        node = _vuln_to_node(vuln)
        assert node.metadata["complexity_key"] == "no_auth_rtsp"

    def test_cve_high(self):
        vuln = {"vuln_id": "v3", "title": "Stack overflow", "severity": "high",
                "cve_id": "CVE-2021-1234"}
        node = _vuln_to_node(vuln)
        assert node.metadata["complexity_key"] == "cve_high"
        assert "CVE-2021-1234" in node.label

    def test_severity_preserved_in_metadata(self):
        vuln = {"vuln_id": "v4", "title": "Some vuln", "severity": "medium"}
        node = _vuln_to_node(vuln)
        assert node.metadata["severity"] == "medium"


class TestBuildImpactNodes:
    def test_stream_access_when_rtsp_port_open(self):
        device = {"ip_address": "1.2.3.4", "open_ports": [{"port": 554}]}
        nodes = _build_impact_nodes(device, [])
        impact_types = [n.metadata["impact_type"] for n in nodes]
        assert "stream_access" in impact_types

    def test_config_access_when_http_open(self):
        device = {"ip_address": "1.2.3.4", "open_ports": [{"port": 80}]}
        nodes = _build_impact_nodes(device, [])
        impact_types = [n.metadata["impact_type"] for n in nodes]
        assert "config_access" in impact_types

    def test_rce_when_rce_in_vuln_description(self):
        device = {"ip_address": "1.2.3.4", "open_ports": []}
        vulns = [{"title": "Command injection RCE", "description": "remote code execution via API"}]
        nodes = _build_impact_nodes(device, vulns)
        impact_types = [n.metadata["impact_type"] for n in nodes]
        assert "rce" in impact_types

    def test_default_impact_when_no_ports(self):
        device = {"ip_address": "1.2.3.4", "open_ports": []}
        nodes = _build_impact_nodes(device, [])
        assert len(nodes) >= 1


class TestAttackGraph:
    def _simple_graph(self):
        g = AttackGraph()
        entry = APNode("entry_80", NodeType.ENTRY, "Port 80", metadata={"complexity_key": "http_open"})
        vuln = APNode("vuln_defcred", NodeType.VULN, "Default Creds", metadata={"complexity_key": "default_creds"})
        impact = APNode("impact_config", NodeType.IMPACT, "Config Access", metadata={"impact_type": "config_access"})
        g.add_node(entry)
        g.add_node(vuln)
        g.add_node(impact)
        g.add_edge(APEdge(source="entry_80", target="vuln_defcred", weight=1.0))
        g.add_edge(APEdge(source="vuln_defcred", target="impact_config", weight=0.5))
        return g

    def test_dijkstra_finds_path(self):
        g = self._simple_graph()
        dist = g.dijkstra("entry_80")
        assert dist["impact_config"] == 1.5

    def test_shortest_path_to_impact(self):
        g = self._simple_graph()
        weight, path = g.shortest_path_to_impact()
        assert weight == 1.5
        assert len(path) >= 2

    def test_to_dict_has_nodes_and_edges(self):
        g = self._simple_graph()
        d = g.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == 3
        assert len(d["edges"]) == 2

    def test_to_mermaid_contains_graph_lr(self):
        g = self._simple_graph()
        mermaid = g.to_mermaid()
        assert "graph LR" in mermaid

    def test_dijkstra_no_path(self):
        g = AttackGraph()
        n1 = APNode("n1", NodeType.ENTRY, "N1")
        n2 = APNode("n2", NodeType.IMPACT, "N2")
        g.add_node(n1)
        g.add_node(n2)
        dist = g.dijkstra("n1")
        assert dist["n2"] == float("inf")


class TestAttackPathEngine:
    def _make_device(self, ip: str = "192.168.1.1") -> dict:
        return {
            "ip_address": ip,
            "open_ports": [
                {"port": 554, "service": "RTSP"},
                {"port": 80, "service": "HTTP"},
            ],
            "rtsp_ports": [],
            "has_open_stream": True,
        }

    def _make_vulns(self) -> list:
        return [
            {
                "vuln_id": "v1",
                "title": "Default credentials",
                "severity": "critical",
                "cvss_score": 9.8,
                "description": "Default admin:12345 credentials accepted",
                "cve_id": "",
            }
        ]

    def test_build_for_device_returns_required_keys(self):
        engine = AttackPathEngine()
        result = engine.build_for_device(self._make_device(), self._make_vulns())
        assert "ip_address" in result
        assert "graph" in result
        assert "risk_score" in result
        assert "risk_level" in result
        assert "mermaid_diagram" in result
        assert "attack_steps" in result

    def test_risk_score_range(self):
        engine = AttackPathEngine()
        result = engine.build_for_device(self._make_device(), self._make_vulns())
        assert 0.0 <= result["risk_score"] <= 10.0

    def test_risk_level_valid(self):
        engine = AttackPathEngine()
        result = engine.build_for_device(self._make_device(), self._make_vulns())
        assert result["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_build_for_device_no_vulns(self):
        """Should still build a graph with synthetic nodes."""
        engine = AttackPathEngine()
        result = engine.build_for_device(self._make_device(), [])
        assert result["graph"]["nodes"]

    def test_analyze_all_returns_one_result_per_device(self):
        engine = AttackPathEngine()
        devices = [self._make_device("192.168.1.1"), self._make_device("192.168.1.2")]
        vuln_map = {
            "192.168.1.1": self._make_vulns(),
            "192.168.1.2": [],
        }
        results = engine.analyze_all(devices, vuln_map)
        assert len(results) == 2

    def test_mermaid_diagram_is_string(self):
        engine = AttackPathEngine()
        result = engine.build_for_device(self._make_device(), self._make_vulns())
        assert isinstance(result["mermaid_diagram"], str)
        assert len(result["mermaid_diagram"]) > 0

    def test_shortest_path_list_not_empty(self):
        engine = AttackPathEngine()
        result = engine.build_for_device(self._make_device(), self._make_vulns())
        assert isinstance(result["shortest_path"], list)
