"""
Attack Path Engine
Constructs a directed acyclic attack graph from discovered devices and
their vulnerabilities, then computes an overall risk score.
"""

import logging
from typing import Dict, List

try:
    from backend.core.crr_models import (
        AttackPath,
        AttackPathEdge,
        AttackPathNode,
        CRRDevice,
        CRRVulnerability,
    )
except ImportError:
    from core.crr_models import (
        AttackPath,
        AttackPathEdge,
        AttackPathNode,
        CRRDevice,
        CRRVulnerability,
    )

logger = logging.getLogger(__name__)

_SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
    "info": 0.5,
}

_RISK_LEVELS = [
    (8.0, "critical"),
    (6.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]


def _risk_level(score: float) -> str:
    for threshold, level in _RISK_LEVELS:
        if score >= threshold:
            return level
    return "low"


class AttackPathEngine:
    """
    Builds an attack graph where:
    - Each device is a node
    - Each vulnerability is a node linked from its device
    - High/critical vulns create pivot edges toward the "internal network" target
    - A final "full network compromise" target node is added if critical vulns exist
    """

    def build(
        self,
        devices: List[CRRDevice],
        vulnerabilities: Dict[str, List[CRRVulnerability]],
    ) -> AttackPath:
        """
        Build an AttackPath from CRR results.

        Args:
            devices: Fused list of CRRDevice objects.
            vulnerabilities: Mapping of ip_address → list of CRRVulnerability.
        Returns:
            AttackPath with nodes, edges, risk_score, risk_level, mermaid_diagram.
        """
        nodes: List[AttackPathNode] = []
        edges: List[AttackPathEdge] = []
        total_weight = 0.0
        max_possible = 0.0

        # --- Attacker entry node ---
        attacker_node = AttackPathNode(
            node_id="attacker",
            label="External Attacker",
            node_type="attacker",
        )
        nodes.append(attacker_node)

        has_critical = False
        cctv_node_ids: List[str] = []

        for device in devices:
            ip = device.ip_address
            dev_node_id = f"dev_{ip.replace('.', '_')}"
            dev_node = AttackPathNode(
                node_id=dev_node_id,
                label=f"{device.manufacturer or 'Device'} ({ip})",
                node_type="device",
                ip_address=ip,
            )
            nodes.append(dev_node)

            # Attacker → device (exposure edge if CCTV or open ports)
            if device.is_cctv or device.open_ports:
                edges.append(AttackPathEdge(
                    source="attacker",
                    target=dev_node_id,
                    label="network exposure",
                ))
                cctv_node_ids.append(dev_node_id)

            device_vulns = vulnerabilities.get(ip, [])
            for vuln in device_vulns:
                vuln_node_id = f"vuln_{ip.replace('.', '_')}_{vuln.vuln_id}"
                weight = _SEVERITY_WEIGHT.get(vuln.severity, 1.0)
                total_weight += weight
                max_possible += _SEVERITY_WEIGHT["critical"]

                sev = vuln.severity
                if sev == "critical":
                    has_critical = True

                vuln_node = AttackPathNode(
                    node_id=vuln_node_id,
                    label=vuln.title,
                    node_type="vulnerability",
                    ip_address=ip,
                    severity=sev,
                )
                nodes.append(vuln_node)
                edges.append(AttackPathEdge(
                    source=dev_node_id,
                    target=vuln_node_id,
                    label=f"exploits ({sev})",
                ))

                # High/critical vulns allow pivot
                if sev in ("critical", "high"):
                    pivot_node_id = f"pivot_{ip.replace('.', '_')}"
                    pivot_label = f"Pivot via {ip}"
                    # Add pivot node only once per device
                    existing_ids = {n.node_id for n in nodes}
                    if pivot_node_id not in existing_ids:
                        nodes.append(AttackPathNode(
                            node_id=pivot_node_id,
                            label=pivot_label,
                            node_type="pivot",
                            ip_address=ip,
                        ))
                    edges.append(AttackPathEdge(
                        source=vuln_node_id,
                        target=pivot_node_id,
                        label="lateral movement",
                    ))

        # --- Target node ---
        if has_critical:
            target_node = AttackPathNode(
                node_id="target_full_compromise",
                label="Full Network Compromise",
                node_type="target",
            )
            nodes.append(target_node)
            for n in nodes:
                if n.node_type == "pivot":
                    edges.append(AttackPathEdge(
                        source=n.node_id,
                        target="target_full_compromise",
                        label="escalation",
                    ))

        # --- Risk score (0–10) ---
        if max_possible > 0:
            raw = (total_weight / max_possible) * 10.0
        else:
            raw = 0.0
        risk_score = min(round(raw, 2), 10.0)
        level = _risk_level(risk_score)

        path = AttackPath(
            nodes=nodes,
            edges=edges,
            risk_score=risk_score,
            risk_level=level,
        )
        path.mermaid_diagram = self._to_mermaid(path)
        logger.info(
            f"Attack path built: {len(nodes)} nodes, {len(edges)} edges, "
            f"risk={risk_score}/{level}"
        )
        return path

    def _to_mermaid(self, path: AttackPath) -> str:
        """Generate a Mermaid flowchart diagram string."""
        lines = ["graph TD"]
        node_map = {n.node_id: n for n in path.nodes}
        defined: set = set()

        def _safe(s: str) -> str:
            return s.replace('"', "'").replace("(", "[").replace(")", "]")

        for node in path.nodes:
            nid = node.node_id
            label = _safe(node.label)
            if node.node_type == "attacker":
                shape = f'["{label}"]'
            elif node.node_type == "device":
                shape = f'("{label}")'
            elif node.node_type == "vulnerability":
                severity = node.severity or ""
                shape = f'["{label} [{severity}]"]'
            elif node.node_type == "pivot":
                shape = f'>"{label}"]'
            elif node.node_type == "target":
                shape = f'{{"{label}"}}'
            else:
                shape = f'["{label}"]'
            lines.append(f"    {nid}{shape}")
            defined.add(nid)

        for edge in path.edges:
            label = _safe(edge.label)
            if edge.source in defined and edge.target in defined:
                lines.append(f'    {edge.source} -->|"{label}"| {edge.target}')

        return "\n".join(lines)
