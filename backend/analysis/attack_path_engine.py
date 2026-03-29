"""
Attack Path Engine
Constructs a directed acyclic graph (DAG) per device representing how an
attacker could move from initial network access to full device compromise.

Graph model
-----------
Nodes
  - ENTRY: Open ports / exposed services reachable from the network.
  - VULN:  Exploitable conditions (default creds, no-auth RTSP, known CVE …).
  - IMPACT: What an attacker achieves (stream access, config dump, RCE, …).

Edges
  - Directed: ENTRY → VULN → IMPACT
  - Weight: attack complexity score (lower = easier; 0 = trivial, 10 = hard).

Algorithms
  - Shortest attack path: modified Dijkstra over the weighted DAG.
  - Risk score: inversely proportional to the minimum attack complexity path.
  - Mermaid diagram: serialised from the graph for report embedding.
"""

import heapq
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    """Type of a node in the attack path graph."""
    ENTRY = "entry"
    VULN = "vulnerability"
    IMPACT = "impact"


@dataclass
class APNode:
    """A single node in the attack path DAG."""
    node_id: str
    node_type: NodeType
    label: str
    description: str = ""
    metadata: Dict = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, APNode) and self.node_id == other.node_id


@dataclass
class APEdge:
    """A directed edge in the attack path DAG."""
    source: str       # node_id of source
    target: str       # node_id of target
    weight: float     # attack complexity (0 = trivial, 10 = hard)
    label: str = ""   # human-readable edge label


# ---------------------------------------------------------------------------
# Complexity weights for known vulnerability / service types
# ---------------------------------------------------------------------------

_ENTRY_COMPLEXITY: Dict[str, float] = {
    "rtsp_open": 0.5,       # RTSP stream accessible without auth
    "http_open": 1.0,
    "telnet_open": 0.5,
    "ftp_open": 1.0,
    "ssh_open": 2.0,
    "onvif_open": 1.0,
    "sdk_open": 1.5,
    "default": 2.0,
}

_VULN_COMPLEXITY: Dict[str, float] = {
    "default_creds": 0.5,
    "no_auth_rtsp": 0.1,
    "no_auth_web": 0.5,
    "cve_critical": 1.0,
    "cve_high": 2.0,
    "cve_medium": 3.5,
    "weak_ssl": 2.0,
    "telnet_open": 0.5,
    "ftp_anon": 0.3,
    "default": 3.0,
}

_IMPACT_WEIGHT: Dict[str, float] = {
    "stream_access": 0.1,
    "config_access": 0.2,
    "credential_dump": 0.2,
    "firmware_upload": 0.5,
    "rce": 0.5,
    "full_control": 0.1,
    "default": 0.2,
}

# Human-readable labels for each impact type
_IMPACT_LABELS: Dict[str, str] = {
    "stream_access": "Live video stream accessed",
    "config_access": "Device configuration accessed",
    "credential_dump": "Credentials retrieved",
    "firmware_upload": "Firmware can be replaced",
    "rce": "Remote code execution achieved",
    "full_control": "Full device control",
}


def _port_to_entry_nodes(port_info: Dict) -> List[APNode]:
    """
    Convert a single open-port record into one or more ENTRY nodes.

    Args:
        port_info: Dict with keys ``port``, ``service``, ``protocol``.

    Returns:
        List of ENTRY APNode objects.
    """
    port = port_info.get("port", 0)
    service = port_info.get("service", "") or port_info.get("name", "")
    s = service.lower()
    nodes: List[APNode] = []

    node_id = f"entry_port_{port}"
    label = f"Port {port}/{service.upper()}"

    if port == 554 or "rtsp" in s:
        entry_key = "rtsp_open"
    elif port in (80, 8080, 8000, 9000) or "http" in s:
        entry_key = "http_open"
    elif port == 23 or "telnet" in s:
        entry_key = "telnet_open"
    elif port == 21 or "ftp" in s:
        entry_key = "ftp_open"
    elif port == 22 or "ssh" in s:
        entry_key = "ssh_open"
    elif port == 3702 or "onvif" in s:
        entry_key = "onvif_open"
    elif port == 8000 or "hikvision" in s or "sdk" in s:
        entry_key = "sdk_open"
    else:
        entry_key = "default"

    nodes.append(
        APNode(
            node_id=node_id,
            node_type=NodeType.ENTRY,
            label=label,
            description=f"Open port {port} ({service})",
            metadata={"port": port, "service": service, "complexity_key": entry_key},
        )
    )
    return nodes


def _vuln_to_node(vuln: Dict) -> APNode:
    """
    Convert a vulnerability record into a VULN node.

    Args:
        vuln: Vulnerability dict from the vulnerability scanner.

    Returns:
        APNode of type VULN.
    """
    vuln_id = vuln.get("vuln_id") or vuln.get("id") or vuln.get("title", "vuln")
    severity = (vuln.get("severity") or "medium").lower()
    title = vuln.get("title") or vuln.get("name") or vuln_id
    cve = vuln.get("cve_id") or ""

    # Map severity to complexity key
    complexity_key_map = {
        "critical": "cve_critical",
        "high": "cve_high",
        "medium": "cve_medium",
        "low": "cve_medium",
        "info": "default",
    }
    # Check for specific well-known vulnerability types
    title_lower = title.lower()
    if "default" in title_lower and ("cred" in title_lower or "pass" in title_lower):
        complexity_key = "default_creds"
    elif "rtsp" in title_lower and "auth" in title_lower:
        complexity_key = "no_auth_rtsp"
    elif "telnet" in title_lower:
        complexity_key = "telnet_open"
    elif "ftp" in title_lower and "anon" in title_lower:
        complexity_key = "ftp_anon"
    else:
        complexity_key = complexity_key_map.get(severity, "default")

    node_id = f"vuln_{vuln_id}".replace(" ", "_")
    label_parts = [title]
    if cve:
        label_parts.append(f"({cve})")
    return APNode(
        node_id=node_id,
        node_type=NodeType.VULN,
        label=" ".join(label_parts),
        description=vuln.get("description") or "",
        metadata={
            "severity": severity,
            "cvss_score": vuln.get("cvss_score", 0),
            "cve_id": cve,
            "complexity_key": complexity_key,
        },
    )


def _build_impact_nodes(device: Dict, vulns: List[Dict]) -> List[APNode]:
    """
    Determine achievable impact nodes based on the device's vulnerabilities
    and open ports.

    Args:
        device: Unified device dict from DiscoveryFusion.
        vulns: List of vulnerability dicts from VulnerabilityScanner.

    Returns:
        List of IMPACT APNode objects.
    """
    impacts: Set[str] = set()
    vuln_texts = " ".join(
        (v.get("title", "") + " " + v.get("description", "")).lower() for v in vulns
    )
    port_nums = {p.get("port", 0) for p in device.get("open_ports", [])}

    if 554 in port_nums or device.get("has_open_stream"):
        impacts.add("stream_access")
    if any(p in port_nums for p in (80, 8080, 8000, 9000)):
        impacts.add("config_access")
    if "default" in vuln_texts and "cred" in vuln_texts:
        impacts.add("credential_dump")
    if "rce" in vuln_texts or "remote code" in vuln_texts or "command injection" in vuln_texts:
        impacts.add("rce")
    if "firmware" in vuln_texts and ("upload" in vuln_texts or "replace" in vuln_texts):
        impacts.add("firmware_upload")
    if len(impacts) >= 3 or "rce" in impacts:
        impacts.add("full_control")
    if not impacts:
        impacts.add("config_access")

    nodes: List[APNode] = []
    for impact_key in impacts:
        nodes.append(
            APNode(
                node_id=f"impact_{impact_key}",
                node_type=NodeType.IMPACT,
                label=_IMPACT_LABELS.get(impact_key, impact_key.replace("_", " ").title()),
                description=_IMPACT_LABELS.get(impact_key, ""),
                metadata={"impact_type": impact_key},
            )
        )
    return nodes


# ---------------------------------------------------------------------------
# Graph structure & Dijkstra
# ---------------------------------------------------------------------------

class AttackGraph:
    """
    Directed weighted graph representing a single device's attack surface.

    Nodes are keyed by ``node_id``.  Adjacency is stored as
    ``{source_id: [(weight, target_id, edge_label)]}``.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, APNode] = {}
        self.adjacency: Dict[str, List[Tuple[float, str, str]]] = {}

    def add_node(self, node: APNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.node_id] = node
        if node.node_id not in self.adjacency:
            self.adjacency[node.node_id] = []

    def add_edge(self, edge: APEdge) -> None:
        """Add a directed edge to the graph."""
        if edge.source not in self.adjacency:
            self.adjacency[edge.source] = []
        self.adjacency[edge.source].append((edge.weight, edge.target, edge.label))

    def dijkstra(self, source_id: str) -> Dict[str, float]:
        """
        Run Dijkstra's shortest-path algorithm from a source node.

        Args:
            source_id: Starting node ID.

        Returns:
            Dict mapping node_id → minimum cumulative weight from source.
        """
        dist: Dict[str, float] = {n: float("inf") for n in self.nodes}
        dist[source_id] = 0.0
        heap: List[Tuple[float, str]] = [(0.0, source_id)]

        while heap:
            current_dist, current = heapq.heappop(heap)
            if current_dist > dist[current]:
                continue
            for weight, neighbour, _ in self.adjacency.get(current, []):
                new_dist = current_dist + weight
                if new_dist < dist[neighbour]:
                    dist[neighbour] = new_dist
                    heapq.heappush(heap, (new_dist, neighbour))
        return dist

    def shortest_path_to_impact(self) -> Tuple[float, List[str]]:
        """
        Find the easiest (lowest total weight) path from any ENTRY node
        to any IMPACT node.

        Returns:
            Tuple of ``(min_total_weight, [node_id, …])`` representing the
            easiest attack path.  Returns ``(inf, [])`` if no path exists.
        """
        entry_ids = [n for n, node in self.nodes.items() if node.node_type == NodeType.ENTRY]
        impact_ids = {n for n, node in self.nodes.items() if node.node_type == NodeType.IMPACT}

        best: float = float("inf")
        best_path: List[str] = []

        for entry_id in entry_ids:
            dist = self.dijkstra(entry_id)
            for impact_id in impact_ids:
                d = dist.get(impact_id, float("inf"))
                if d < best:
                    best = d
                    # Reconstruct path (simplified — record just the IDs reachable)
                    best_path = self._reconstruct_path(entry_id, impact_id)

        return best, best_path

    def _reconstruct_path(self, source: str, target: str) -> List[str]:
        """
        Simple BFS path reconstruction (not weighted — just any path).

        Args:
            source: Start node ID.
            target: End node ID.

        Returns:
            List of node IDs forming a path, or ``[source, target]`` as fallback.
        """
        from collections import deque

        queue: deque = deque([[source]])
        visited: Set[str] = {source}

        while queue:
            path = queue.popleft()
            current = path[-1]
            if current == target:
                return path
            for _, neighbour, _ in self.adjacency.get(current, []):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(path + [neighbour])
        return [source, target]

    def to_dict(self) -> Dict:
        """Serialise the graph to a JSON-friendly dict."""
        return {
            "nodes": [
                {
                    "id": node.node_id,
                    "type": node.node_type.value,
                    "label": node.label,
                    "description": node.description,
                    "metadata": node.metadata,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": src,
                    "target": tgt,
                    "weight": w,
                    "label": lbl,
                }
                for src, edges in self.adjacency.items()
                for w, tgt, lbl in edges
            ],
        }

    def to_mermaid(self) -> str:
        """
        Serialise the graph as a Mermaid flowchart diagram string.

        Returns:
            Mermaid diagram syntax suitable for embedding in HTML/Markdown reports.
        """
        lines = ["graph LR"]
        type_style = {
            NodeType.ENTRY: ":::entry",
            NodeType.VULN: ":::vuln",
            NodeType.IMPACT: ":::impact",
        }
        # Node definitions
        for node_id, node in self.nodes.items():
            safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", node_id)
            shape_open, shape_close = "[", "]"
            if node.node_type == NodeType.VULN:
                shape_open, shape_close = "(", ")"
            elif node.node_type == NodeType.IMPACT:
                shape_open, shape_close = "([", "])"
            label = node.label.replace('"', "'")
            lines.append(f'    {safe_id}{shape_open}"{label}"{shape_close}')
        # Edges
        for src, edges in self.adjacency.items():
            safe_src = re.sub(r"[^a-zA-Z0-9_]", "_", src)
            for weight, tgt, lbl in edges:
                safe_tgt = re.sub(r"[^a-zA-Z0-9_]", "_", tgt)
                edge_label = lbl or f"w={weight:.1f}"
                lines.append(f'    {safe_src} -->|"{edge_label}"| {safe_tgt}')
        # Style classes
        lines.append("    classDef entry fill:#ff9900,stroke:#cc6600,color:#000")
        lines.append("    classDef vuln fill:#ff4444,stroke:#cc0000,color:#fff")
        lines.append("    classDef impact fill:#00aa44,stroke:#007722,color:#fff")
        return "\n".join(lines)


import re  # noqa: E402 — needed inside to_mermaid


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class AttackPathEngine:
    """
    Constructs attack path graphs for discovered CCTV devices and computes
    risk scores, shortest attack paths, and Mermaid diagram representations.

    Usage::

        engine = AttackPathEngine()
        result = engine.build_for_device(device_dict, vulnerability_list)
        print(result["risk_score"], result["mermaid_diagram"])
    """

    # Risk score thresholds
    _RISK_LEVELS = [
        (2.0, "CRITICAL"),
        (4.0, "HIGH"),
        (6.0, "MEDIUM"),
        (8.0, "LOW"),
        (float("inf"), "INFO"),
    ]

    def _complexity_weight(self, key: str, lookup: Dict[str, float]) -> float:
        return lookup.get(key, lookup.get("default", 3.0))

    def build_graph(self, device: Dict, vulnerabilities: List[Dict]) -> AttackGraph:
        """
        Build the attack path graph for a single device.

        Args:
            device: Unified device dict (from DiscoveryFusion or scan results).
            vulnerabilities: List of vulnerability dicts from VulnerabilityScanner.

        Returns:
            Populated :class:`AttackGraph` for the device.
        """
        graph = AttackGraph()
        ip = device.get("ip_address", "unknown")

        # --- ENTRY nodes from open ports ---
        for port_info in device.get("open_ports", []):
            for node in _port_to_entry_nodes(port_info):
                graph.add_node(node)

        # Also add entry nodes from RTSP probe data
        for port_data in device.get("rtsp_ports", []):
            port = port_data.get("port", 0)
            if not any(p.node_id == f"entry_port_{port}" for p in graph.nodes.values()):
                entry_node = APNode(
                    node_id=f"entry_port_{port}",
                    node_type=NodeType.ENTRY,
                    label=f"Port {port}/RTSP",
                    description=f"RTSP service on port {port}",
                    metadata={"port": port, "service": "RTSP", "complexity_key": "rtsp_open"},
                )
                graph.add_node(entry_node)

        # Ensure we have at least one entry node
        if not any(n.node_type == NodeType.ENTRY for n in graph.nodes.values()):
            default_entry = APNode(
                node_id="entry_network",
                node_type=NodeType.ENTRY,
                label=f"Network Access ({ip})",
                description="Device is reachable from the network",
                metadata={"complexity_key": "default"},
            )
            graph.add_node(default_entry)

        # --- VULN nodes ---
        for vuln in vulnerabilities:
            vuln_node = _vuln_to_node(vuln)
            graph.add_node(vuln_node)

        # If no explicit vulns but we have open stream / default creds hint
        if not any(n.node_type == NodeType.VULN for n in graph.nodes.values()):
            if device.get("has_open_stream"):
                graph.add_node(APNode(
                    node_id="vuln_no_auth_rtsp",
                    node_type=NodeType.VULN,
                    label="No RTSP Authentication",
                    description="RTSP stream accessible without credentials",
                    metadata={"severity": "critical", "complexity_key": "no_auth_rtsp"},
                ))
            else:
                graph.add_node(APNode(
                    node_id="vuln_unknown",
                    node_type=NodeType.VULN,
                    label="Potential Misconfiguration",
                    description="Device may have default or weak settings",
                    metadata={"severity": "medium", "complexity_key": "default"},
                ))

        # --- IMPACT nodes ---
        impact_nodes = _build_impact_nodes(device, vulnerabilities)
        for node in impact_nodes:
            graph.add_node(node)

        # --- Edges: ENTRY → VULN ---
        entry_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.ENTRY]
        vuln_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.VULN]
        impact_nodes_list = [n for n in graph.nodes.values() if n.node_type == NodeType.IMPACT]

        for entry_node in entry_nodes:
            entry_key = entry_node.metadata.get("complexity_key", "default")
            entry_weight = self._complexity_weight(entry_key, _ENTRY_COMPLEXITY)
            for vuln_node in vuln_nodes:
                vuln_key = vuln_node.metadata.get("complexity_key", "default")
                vuln_weight = self._complexity_weight(vuln_key, _VULN_COMPLEXITY)
                graph.add_edge(APEdge(
                    source=entry_node.node_id,
                    target=vuln_node.node_id,
                    weight=entry_weight,
                    label=f"exploit via port {entry_node.metadata.get('port', '?')}",
                ))
                # --- Edges: VULN → IMPACT ---
                for impact_node in impact_nodes_list:
                    impact_key = impact_node.metadata.get("impact_type", "default")
                    impact_weight = self._complexity_weight(impact_key, _IMPACT_WEIGHT)
                    graph.add_edge(APEdge(
                        source=vuln_node.node_id,
                        target=impact_node.node_id,
                        weight=vuln_weight + impact_weight,
                        label=f"achieve {impact_node.metadata.get('impact_type', 'impact')}",
                    ))

        return graph

    def _risk_score_from_path_weight(self, min_weight: float) -> Tuple[float, str]:
        """
        Convert minimum attack path weight into a 0-10 risk score and level.

        Lower path weight = easier attack = higher risk score.

        Args:
            min_weight: Minimum total weight from Dijkstra.

        Returns:
            Tuple of ``(risk_score_0_to_10, risk_level_string)``.
        """
        if min_weight == float("inf"):
            return 0.0, "INFO"
        # Invert: max reachable complexity ~= 20, trivial = 0
        score = max(0.0, min(10.0, 10.0 - min_weight * 0.5))
        for threshold, level in self._RISK_LEVELS:
            if min_weight <= threshold:
                return round(score, 2), level
        return round(score, 2), "INFO"

    def build_for_device(self, device: Dict, vulnerabilities: List[Dict]) -> Dict:
        """
        Full attack path analysis for a single device.

        Args:
            device: Unified device dict.
            vulnerabilities: Vulnerability list for this device.

        Returns:
            Dict with keys:
              - ``ip_address``
              - ``graph`` (JSON-serialisable graph dict)
              - ``mermaid_diagram`` (Mermaid syntax string)
              - ``shortest_path`` (list of node IDs)
              - ``min_attack_complexity`` (float)
              - ``risk_score`` (0–10 float)
              - ``risk_level`` (string)
              - ``attack_steps`` (human-readable list)
              - ``analyzed_at`` (ISO timestamp)
        """
        ip = device.get("ip_address", "unknown")
        graph = self.build_graph(device, vulnerabilities)
        min_weight, shortest_path = graph.shortest_path_to_impact()
        risk_score, risk_level = self._risk_score_from_path_weight(min_weight)

        # Human-readable attack steps
        attack_steps = [
            graph.nodes[node_id].label
            for node_id in shortest_path
            if node_id in graph.nodes
        ]

        return {
            "ip_address": ip,
            "graph": graph.to_dict(),
            "mermaid_diagram": graph.to_mermaid(),
            "shortest_path": shortest_path,
            "min_attack_complexity": round(min_weight, 3) if min_weight != float("inf") else None,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "attack_steps": attack_steps,
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    def analyze_all(
        self,
        devices: List[Dict],
        vulnerabilities_map: Dict[str, List[Dict]],
    ) -> List[Dict]:
        """
        Run attack path analysis on a list of devices.

        Args:
            devices: List of device dicts.
            vulnerabilities_map: Dict mapping IP address → list of vulns.

        Returns:
            List of attack path result dicts (one per device).
        """
        results: List[Dict] = []
        for device in devices:
            ip = device.get("ip_address", "")
            vulns = vulnerabilities_map.get(ip, [])
            try:
                result = self.build_for_device(device, vulns)
                results.append(result)
            except Exception as exc:
                logger.error("Attack path analysis failed for %s: %s", ip, exc)
        return results
