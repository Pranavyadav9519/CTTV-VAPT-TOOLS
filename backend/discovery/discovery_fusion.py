"""
Discovery Fusion Engine
Merges results from ARP scan, ONVIF WS-Discovery, UPnP/SSDP, and RTSP probing
into a unified, deduplicated device list with confidence scoring.

Confidence score is boosted for every additional protocol that confirms the
same device (convergent evidence principle).
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Per-protocol base confidence values
_BASE_CONFIDENCE: Dict[str, float] = {
    "arp": 1.0,
    "socket": 0.6,
    "onvif_ws_discovery": 0.9,
    "ssdp_upnp": 0.7,
    "rtsp_probe": 0.85,
    "unknown": 0.5,
}

# Bonus added for each additional protocol that corroborates the same device
_CORROBORATION_BONUS = 0.05


def _normalise_method(method: str) -> str:
    """
    Normalise a discovery_method string to one of the recognised base keys.

    Args:
        method: Raw discovery_method string from a scanner module.

    Returns:
        Canonical method key.
    """
    m = method.lower()
    if "arp" in m:
        return "arp"
    if "socket" in m:
        return "socket"
    if "onvif" in m:
        return "onvif_ws_discovery"
    if "ssdp" in m or "upnp" in m:
        return "ssdp_upnp"
    if "rtsp" in m:
        return "rtsp_probe"
    return "unknown"


def _merge_device_records(records: List[Dict]) -> Dict:
    """
    Merge multiple device records (all for the same IP) into one.

    Fields are merged with a "latest non-empty wins" strategy; lists and
    dicts from richer records are preserved.  The confidence score is
    calculated from the base value of the highest-confidence source plus
    a corroboration bonus for each additional confirming source.

    Args:
        records: Non-empty list of device dicts for the same IP address.

    Returns:
        Single merged device dict.
    """
    # Start with the record that has the highest base confidence
    methods = [_normalise_method(r.get("discovery_method", "")) for r in records]
    base_confidences = [_BASE_CONFIDENCE.get(m, 0.5) for m in methods]
    primary_idx = base_confidences.index(max(base_confidences))
    merged = dict(records[primary_idx])

    # Collect discovery methods used
    merged["discovery_methods"] = sorted(set(methods))
    merged["discovery_method"] = "multi_protocol"

    # Corroboration bonus
    n_protocols = len(set(methods))
    confidence = max(base_confidences) + _CORROBORATION_BONUS * max(n_protocols - 1, 0)
    merged["confidence"] = min(round(confidence, 3), 1.0)

    # Merge supplementary fields from all records (non-empty wins)
    merge_fields = [
        "mac_address",
        "hostname",
        "manufacturer",
        "model",
        "friendly_name",
        "onvif_service_url",
        "xaddrs",
        "scopes",
        "location",
        "server",
        "rtsp_server",
        "manufacturer_hint",
        "firmware_version",
        "udn",
    ]
    for field in merge_fields:
        current = merged.get(field)
        if current:
            continue
        for record in records:
            value = record.get(field)
            if value:
                merged[field] = value
                break

    # Merge RTSP port data
    rtsp_ports: List[Dict] = []
    seen_ports: set = set()
    for record in records:
        for port_info in record.get("rtsp_ports", []):
            port = port_info.get("port")
            if port and port not in seen_ports:
                rtsp_ports.append(port_info)
                seen_ports.add(port)
    if rtsp_ports:
        merged["rtsp_ports"] = rtsp_ports

    # Boolean flags — True if any source reports True
    for flag in ["has_open_stream", "has_auth_protected_stream", "is_camera_device"]:
        merged[flag] = any(r.get(flag, False) for r in records)

    merged["fused_at"] = datetime.utcnow().isoformat()
    return merged


class DiscoveryFusion:
    """
    Merges and deduplicates device discoveries from multiple scanner sources.

    All input lists are expected to be lists of device dicts, each containing
    at minimum an ``ip_address`` key.  Records with the same IP are merged
    into a single canonical device record with an adjusted confidence score
    reflecting how many independent protocols confirmed the device.

    Usage::

        fusion = DiscoveryFusion()
        devices = fusion.fuse(
            arp_results=arp_devices,
            onvif_results=onvif_devices,
            ssdp_results=ssdp_devices,
            rtsp_results=rtsp_devices,
        )
    """

    def fuse(
        self,
        arp_results: Optional[List[Dict]] = None,
        onvif_results: Optional[List[Dict]] = None,
        ssdp_results: Optional[List[Dict]] = None,
        rtsp_results: Optional[List[Dict]] = None,
    ) -> List[Dict]:
        """
        Merge device lists from up to four discovery sources.

        Args:
            arp_results: Devices from ARP / socket scan.
            onvif_results: Devices from ONVIF WS-Discovery.
            ssdp_results: Devices from SSDP/UPnP discovery.
            rtsp_results: Devices from RTSP probing.

        Returns:
            Unified, deduplicated, and enriched list of device dicts sorted
            by confidence (descending) then IP address.
        """
        all_records: Dict[str, List[Dict]] = {}  # ip -> list of records

        for source in [arp_results, onvif_results, ssdp_results, rtsp_results]:
            if not source:
                continue
            for record in source:
                ip = record.get("ip_address")
                if not ip:
                    continue
                all_records.setdefault(ip, []).append(record)

        fused: List[Dict] = []
        for ip, records in all_records.items():
            merged = _merge_device_records(records)
            fused.append(merged)

        # Sort: highest confidence first, then by IP for determinism
        fused.sort(key=lambda d: (-d.get("confidence", 0), d.get("ip_address", "")))

        logger.info(
            "Discovery fusion complete: %d unique device(s) from %d total records",
            len(fused),
            sum(len(v) for v in all_records.values()),
        )
        return fused

    def get_summary(self, fused_devices: List[Dict]) -> Dict:
        """
        Build a discovery summary dict for reporting purposes.

        Args:
            fused_devices: Output from :meth:`fuse`.

        Returns:
            Summary dict with ``total_devices``, ``high_confidence``,
            ``multi_protocol``, ``protocol_breakdown``.
        """
        summary: Dict = {
            "total_devices": len(fused_devices),
            "high_confidence": sum(1 for d in fused_devices if d.get("confidence", 0) >= 0.8),
            "multi_protocol": sum(
                1 for d in fused_devices if len(d.get("discovery_methods", [])) > 1
            ),
            "has_open_stream": sum(1 for d in fused_devices if d.get("has_open_stream")),
            "protocol_breakdown": {},
        }
        for device in fused_devices:
            for method in device.get("discovery_methods", [device.get("discovery_method", "unknown")]):
                summary["protocol_breakdown"][method] = (
                    summary["protocol_breakdown"].get(method, 0) + 1
                )
        return summary
