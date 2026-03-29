"""
CRR Pipeline Data Models
Dataclasses representing the core entities used throughout the CRR pipeline.

These are pure data containers (no ORM, no I/O) designed for in-memory
processing.  Persistence is handled separately by the database layer.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime


class ScanStatus(str, Enum):
    """Lifecycle status of a CRR scan session."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class RiskLevel(str, Enum):
    """Device / finding risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CRRDevice:
    """
    Represents a single CCTV/IoT device discovered on the network.

    Populated progressively as the pipeline phases execute — earlier phases
    fill basic fields, later phases enrich with manufacturer, firmware, etc.
    """
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    discovery_method: str = "unknown"
    discovery_methods: List[str] = field(default_factory=list)
    confidence: float = 0.0
    open_ports: List[Dict] = field(default_factory=list)
    rtsp_ports: List[Dict] = field(default_factory=list)
    onvif_service_url: Optional[str] = None
    xaddrs: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    has_open_stream: bool = False
    has_auth_protected_stream: bool = False
    is_camera_device: bool = True
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    extra: Dict = field(default_factory=dict)


@dataclass
class CRRVulnerability:
    """
    Represents a single vulnerability finding on a device.
    """
    vuln_id: str
    title: str
    severity: str
    description: str
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    affected_ip: str = ""
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    remediation: str = ""
    proof_of_concept: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CRRAttackPath:
    """
    Represents the attack path analysis result for a single device.
    """
    ip_address: str
    risk_score: float
    risk_level: str
    min_attack_complexity: Optional[float]
    shortest_path: List[str] = field(default_factory=list)
    attack_steps: List[str] = field(default_factory=list)
    graph: Dict = field(default_factory=dict)
    mermaid_diagram: str = ""
    analyzed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CRRScanSession:
    """
    Top-level container for a complete CRR pipeline scan session.
    """
    scan_id: str
    network_range: str
    status: ScanStatus = ScanStatus.PENDING
    operator: str = "CTTV-VAPT-TOOLS"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: Optional[str] = None
    devices: List[CRRDevice] = field(default_factory=list)
    vulnerabilities: Dict[str, List[CRRVulnerability]] = field(default_factory=dict)
    attack_paths: List[CRRAttackPath] = field(default_factory=list)
    report_paths: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Serialise the session to a JSON-friendly dict."""
        import dataclasses
        return dataclasses.asdict(self)
