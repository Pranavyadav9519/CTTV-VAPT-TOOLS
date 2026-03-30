"""
Discovery Fusion Module
Merges results from ARP, ONVIF, SSDP, and RTSP probers into a
single de-duplicated CRRDevice list with confidence scores.
"""

import logging
from typing import Any, Dict, List, Optional

try:
    from backend.core.crr_models import CRRDevice
except ImportError:
    from core.crr_models import CRRDevice

logger = logging.getLogger(__name__)


def _merge_value(current: Optional[str], incoming: Optional[str]) -> Optional[str]:
    """Prefer the first non-None / non-empty value."""
    return current if current else incoming


class DiscoveryFusion:
    """
    Fuses raw device dicts from multiple probers into CRRDevice objects.
    Devices are keyed by IP address; repeated entries are merged and their
    confidence scores are combined using a bounded-sum formula so that
    evidence from multiple protocols increases confidence without exceeding 1.0.
    """

    def fuse(self, raw_results: List[Dict[str, Any]]) -> List[CRRDevice]:
        """
        Merge a flat list of raw device dicts into CRRDevice objects.

        Each dict may contain:
          ip_address, mac_address, hostname, manufacturer, model,
          firmware_version, device_type, is_cctv, protocols (list),
          confidence_score, open_ports (list), raw_attributes (dict).
        """
        fused: Dict[str, CRRDevice] = {}

        for raw in raw_results:
            ip = raw.get("ip_address")
            if not ip:
                continue

            if ip not in fused:
                fused[ip] = CRRDevice(
                    ip_address=ip,
                    mac_address=raw.get("mac_address"),
                    hostname=raw.get("hostname"),
                    manufacturer=raw.get("manufacturer"),
                    model=raw.get("model"),
                    firmware_version=raw.get("firmware_version"),
                    device_type=raw.get("device_type"),
                    is_cctv=bool(raw.get("is_cctv", False)),
                    protocols=list(raw.get("protocols") or []),
                    confidence_score=float(raw.get("confidence_score", 0.0)),
                    open_ports=list(raw.get("open_ports") or []),
                    raw_attributes=dict(raw.get("raw_attributes") or {}),
                )
            else:
                dev = fused[ip]
                # Merge scalar fields (first non-None wins)
                dev.mac_address = _merge_value(dev.mac_address, raw.get("mac_address"))
                dev.hostname = _merge_value(dev.hostname, raw.get("hostname"))
                dev.manufacturer = _merge_value(dev.manufacturer, raw.get("manufacturer"))
                dev.model = _merge_value(dev.model, raw.get("model"))
                dev.firmware_version = _merge_value(dev.firmware_version, raw.get("firmware_version"))
                dev.device_type = _merge_value(dev.device_type, raw.get("device_type"))
                # CCTV flag is sticky – once true, stays true
                if raw.get("is_cctv"):
                    dev.is_cctv = True
                # Merge protocol list (unique)
                for proto in raw.get("protocols") or []:
                    if proto not in dev.protocols:
                        dev.protocols.append(proto)
                # Merge open ports
                for port in raw.get("open_ports") or []:
                    if port not in dev.open_ports:
                        dev.open_ports.append(port)
                # Combine confidence: bounded sum  c = 1 - (1-c1)*(1-c2)
                incoming = float(raw.get("confidence_score", 0.0))
                dev.confidence_score = 1.0 - (1.0 - dev.confidence_score) * (1.0 - incoming)
                # Merge raw attributes
                dev.raw_attributes.update(raw.get("raw_attributes") or {})

        devices = list(fused.values())
        logger.info(
            f"Discovery fusion: {len(raw_results)} raw entries → {len(devices)} unique devices"
        )
        return devices
