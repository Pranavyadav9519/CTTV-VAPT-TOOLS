"""
CRR (CCTV Recon-to-Report) Data Models
Shared dataclasses used by the scan engine, discovery modules,
fingerprinting, attack-path engine, and report builder.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class CRRDevice:
    """A device discovered or confirmed via multi-protocol CRR discovery."""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    device_type: Optional[str] = None
    is_cctv: bool = False
    # Protocols confirmed (onvif / ssdp / rtsp / arp / port)
    protocols: List[str] = field(default_factory=list)
    # 0.0–1.0 fusion confidence
    confidence_score: float = 0.0
    open_ports: List[int] = field(default_factory=list)
    # Raw attributes from individual probes
    raw_attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "device_type": self.device_type,
            "is_cctv": self.is_cctv,
            "protocols": self.protocols,
            "confidence_score": self.confidence_score,
            "open_ports": self.open_ports,
        }


@dataclass
class CRRVulnerability:
    """A vulnerability found during the CRR scan pipeline."""
    vuln_id: str
    title: str
    severity: str  # critical / high / medium / low / info
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    description: Optional[str] = None
    affected_component: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    proof_of_concept: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "references": self.references,
            "proof_of_concept": self.proof_of_concept,
        }


@dataclass
class AttackPathNode:
    """Single node in the attack graph."""
    node_id: str
    label: str
    node_type: str  # device / vulnerability / pivot / target
    ip_address: Optional[str] = None
    severity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "node_type": self.node_type,
            "ip_address": self.ip_address,
            "severity": self.severity,
        }


@dataclass
class AttackPathEdge:
    """Directed edge in the attack graph."""
    source: str
    target: str
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "target": self.target, "label": self.label}


@dataclass
class AttackPath:
    """Complete attack-path graph with risk score."""
    nodes: List[AttackPathNode] = field(default_factory=list)
    edges: List[AttackPathEdge] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"  # critical / high / medium / low
    mermaid_diagram: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "mermaid_diagram": self.mermaid_diagram,
        }


@dataclass
class ScanEngineResult:
    """
    Normalized output from the shared scan engine.
    Consumed by both the Enterprise Celery worker and the Socket.IO path
    to persist DB records and generate reports.
    """
    scan_id: str
    network_range: Optional[str]
    # All discovered hosts (CRR-enriched)
    devices: List[CRRDevice] = field(default_factory=list)
    # Vulnerabilities keyed by device IP
    vulnerabilities: Dict[str, List[CRRVulnerability]] = field(default_factory=dict)
    # Attack path graph
    attack_path: Optional[AttackPath] = None
    # High-level statistics
    total_hosts_found: int = 0
    cctv_devices_found: int = 0
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    # Per-device port data: { ip -> [{port_number, protocol, service_name, …}] }
    ports_data: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    error: Optional[str] = None

    def severity_breakdown(self) -> Dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "network_range": self.network_range,
            "total_hosts_found": self.total_hosts_found,
            "cctv_devices_found": self.cctv_devices_found,
            "vulnerabilities_found": self.vulnerabilities_found,
            "severity_breakdown": self.severity_breakdown(),
            "devices": [d.to_dict() for d in self.devices],
            "vulnerabilities": {
                ip: [v.to_dict() for v in vulns]
                for ip, vulns in self.vulnerabilities.items()
            },
            "attack_path": self.attack_path.to_dict() if self.attack_path else None,
        }
