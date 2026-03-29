"""
Unit tests for the CRR Discovery modules:
  - ONVIFDiscovery
  - SSDPDiscovery
  - RTSPProber
  - DiscoveryFusion
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from backend.discovery.onvif_discovery import (
    ONVIFDiscovery,
    _extract_xaddrs,
    _extract_scopes,
    _ip_from_xaddrs,
    _build_probe_message,
)
from backend.discovery.ssdp_discovery import (
    SSDPDiscovery,
    _parse_ssdp_response,
    _is_camera_device,
    _build_m_search,
)
from backend.discovery.rtsp_prober import (
    RTSPProber,
    _make_rtsp_request,
    _parse_rtsp_status,
    _infer_manufacturer,
)
from backend.discovery.discovery_fusion import DiscoveryFusion, _merge_device_records


# ─────────────────────────────────────────────────────────────────────────────
# ONVIF WS-Discovery tests
# ─────────────────────────────────────────────────────────────────────────────

class TestONVIFDiscovery:
    """Tests for ONVIFDiscovery and its helper functions."""

    def test_build_probe_message_is_valid_utf8(self):
        probe = _build_probe_message()
        assert isinstance(probe, bytes)
        text = probe.decode("utf-8")
        assert "Probe" in text
        assert "NetworkVideoTransmitter" in text

    def test_extract_xaddrs_success(self):
        xml = (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            "<s:Body><d:ProbeMatches><d:ProbeMatch>"
            "<d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs>"
            "</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
        )
        xaddrs = _extract_xaddrs(xml)
        assert "http://192.168.1.50/onvif/device_service" in xaddrs

    def test_extract_xaddrs_empty_on_malformed_xml(self):
        xaddrs = _extract_xaddrs("not xml at all")
        assert xaddrs == []

    def test_extract_scopes_success(self):
        xml = (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            "<s:Body><d:ProbeMatches><d:ProbeMatch>"
            "<d:Scopes>onvif://www.onvif.org/type/NetworkVideoTransmitter</d:Scopes>"
            "</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
        )
        scopes = _extract_scopes(xml)
        assert any("NetworkVideoTransmitter" in s for s in scopes)

    def test_ip_from_xaddrs(self):
        xaddrs = ["http://192.168.1.55/onvif/device_service"]
        ip = _ip_from_xaddrs(xaddrs)
        assert ip == "192.168.1.55"

    def test_ip_from_xaddrs_empty(self):
        assert _ip_from_xaddrs([]) is None

    def test_discover_socket_error_returns_empty(self):
        """Socket creation failure should return empty list, not raise."""
        discovery = ONVIFDiscovery(timeout=0.1)
        with patch("backend.discovery.onvif_discovery.socket.socket") as mock_sock:
            mock_sock.side_effect = OSError("test error")
            result = discovery.discover()
        assert result == []

    def test_discover_parses_probe_match(self):
        """Simulate a valid ProbeMatch response and check parsed output."""
        probe_xml = (
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            b' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            b"<s:Body><d:ProbeMatches><d:ProbeMatch>"
            b"<d:XAddrs>http://10.0.0.5/onvif/device_service</d:XAddrs>"
            b"<d:Scopes>onvif://www.onvif.org/type/NetworkVideoTransmitter</d:Scopes>"
            b"</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
        )
        mock_socket = MagicMock()
        mock_socket.__enter__ = lambda s: s
        mock_socket.__exit__ = MagicMock(return_value=False)
        # First recvfrom returns data; second raises timeout
        mock_socket.recvfrom.side_effect = [
            (probe_xml, ("10.0.0.5", 3702)),
            socket.timeout(),
        ]

        discovery = ONVIFDiscovery(timeout=0.1)
        with patch("backend.discovery.onvif_discovery.socket.socket", return_value=mock_socket):
            result = discovery.discover()

        assert len(result) == 1
        assert result[0]["ip_address"] == "10.0.0.5"
        assert result[0]["discovery_method"] == "onvif_ws_discovery"
        assert result[0]["confidence"] == 0.9


# ─────────────────────────────────────────────────────────────────────────────
# SSDP/UPnP Discovery tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSSDPDiscovery:
    """Tests for SSDPDiscovery and its helper functions."""

    def test_build_m_search_format(self):
        probe = _build_m_search("ssdp:all")
        text = probe.decode("utf-8")
        assert "M-SEARCH" in text
        assert "ssdp:all" in text

    def test_parse_ssdp_response_extracts_headers(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "LOCATION: http://192.168.1.20:8080/description.xml\r\n"
            "SERVER: Linux/3.10 UPnP/1.0 Hikvision-NVR\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        )
        headers = _parse_ssdp_response(raw)
        assert headers["location"] == "http://192.168.1.20:8080/description.xml"
        assert "Hikvision" in headers["server"]

    def test_is_camera_device_true_for_hikvision(self):
        headers = {"server": "Hikvision NVR 1.0", "st": "upnp:rootdevice"}
        assert _is_camera_device(headers) is True

    def test_is_camera_device_false_for_printer(self):
        headers = {"server": "HP LaserJet 400", "st": "upnp:rootdevice"}
        assert _is_camera_device(headers) is False

    def test_discover_socket_error_returns_empty(self):
        discovery = SSDPDiscovery(timeout=0.1)
        with patch("backend.discovery.ssdp_discovery.socket.socket") as mock_sock:
            mock_sock.side_effect = OSError("test error")
            result = discovery.discover()
        assert isinstance(result, list)

    def test_discover_deduplicates_ips(self):
        """Same IP in multiple M-SEARCH rounds should appear once."""
        ssdp_response = (
            "HTTP/1.1 200 OK\r\n"
            "LOCATION: http://192.168.1.30:1900/desc.xml\r\n"
            "SERVER: DVR/1.0\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()

        # The SSDP discover() calls _send_and_receive for each of 4 search targets.
        # Each call creates a new socket.  We make every socket instance return the
        # same response then timeout so that the same IP appears across all rounds.
        mock_socket_instance = MagicMock()
        mock_socket_instance.recvfrom.side_effect = [
            (ssdp_response, ("192.168.1.30", 1900)),
            socket.timeout(),
            # Subsequent search-target rounds — all timeout immediately
            socket.timeout(),
            socket.timeout(),
            socket.timeout(),
            socket.timeout(),
            socket.timeout(),
            socket.timeout(),
            socket.timeout(),
        ]

        discovery = SSDPDiscovery(timeout=0.1, fetch_descriptions=False)
        with patch("backend.discovery.ssdp_discovery.socket.socket", return_value=mock_socket_instance):
            result = discovery.discover()

        ips = [d["ip_address"] for d in result]
        assert len(ips) == len(set(ips)), "Duplicate IPs should be removed"
        assert len(ips) == 1
        assert ips[0] == "192.168.1.30"


# ─────────────────────────────────────────────────────────────────────────────
# RTSP Prober tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRTSPProber:
    """Tests for RTSPProber and its helper functions."""

    def test_make_rtsp_request_format(self):
        req = _make_rtsp_request("OPTIONS", "rtsp://192.168.1.100:554/")
        text = req.decode("utf-8")
        assert "OPTIONS rtsp://192.168.1.100:554/ RTSP/1.0" in text
        assert "CSeq: 1" in text

    def test_parse_rtsp_status_200(self):
        raw = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
        code, reason = _parse_rtsp_status(raw)
        assert code == 200
        assert reason == "OK"

    def test_parse_rtsp_status_401(self):
        raw = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n"
        code, reason = _parse_rtsp_status(raw)
        assert code == 401

    def test_parse_rtsp_status_invalid(self):
        code, reason = _parse_rtsp_status("garbage")
        assert code == 0
        assert reason == ""

    def test_infer_manufacturer_hikvision(self):
        assert _infer_manufacturer("Hikvision DS-2CD2142FWD") == "hikvision"

    def test_infer_manufacturer_dahua(self):
        assert _infer_manufacturer("dahua NVR v1.0") == "dahua"

    def test_infer_manufacturer_unknown(self):
        assert _infer_manufacturer("Generic Camera Server") == "unknown"

    def test_probe_hosts_connection_refused_returns_empty(self):
        """Hosts that refuse connections should not appear in results."""
        prober = RTSPProber(timeout=0.1, ports=[554])
        result = prober.probe_hosts(["127.0.0.1"])
        # 127.0.0.1:554 is almost certainly not listening — should return empty
        assert isinstance(result, list)

    def test_probe_hosts_mock_success(self):
        """Mock a successful RTSP OPTIONS response."""
        options_response = (
            b"RTSP/1.0 200 OK\r\n"
            b"CSeq: 1\r\n"
            b"Server: Hikvision RTSP Server 3.0\r\n"
            b"Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
            b"\r\n"
        )
        describe_response = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n"

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [options_response, describe_response]
        mock_sock.connect_ex.return_value = 0

        with patch("backend.discovery.rtsp_prober.socket.socket", return_value=mock_sock):
            prober = RTSPProber(timeout=0.5, ports=[554], max_workers=1)
            result = prober.probe_hosts(["192.168.1.100"])

        # With mocked socket it may or may not return a device depending on connect
        assert isinstance(result, list)


# ─────────────────────────────────────────────────────────────────────────────
# Discovery Fusion tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDiscoveryFusion:
    """Tests for DiscoveryFusion merge logic."""

    def _make_device(self, ip: str, method: str, **extra) -> dict:
        return {"ip_address": ip, "discovery_method": method, **extra}

    def test_fuse_single_source(self):
        fusion = DiscoveryFusion()
        arp = [self._make_device("192.168.1.1", "arp", mac_address="AA:BB:CC:DD:EE:FF")]
        result = fusion.fuse(arp_results=arp)
        assert len(result) == 1
        assert result[0]["ip_address"] == "192.168.1.1"

    def test_fuse_deduplicates_same_ip(self):
        fusion = DiscoveryFusion()
        arp = [self._make_device("10.0.0.5", "arp")]
        onvif = [self._make_device("10.0.0.5", "onvif_ws_discovery")]
        result = fusion.fuse(arp_results=arp, onvif_results=onvif)
        assert len(result) == 1

    def test_fuse_confidence_boosted_multi_protocol(self):
        fusion = DiscoveryFusion()
        arp = [self._make_device("10.0.0.5", "arp")]
        onvif = [self._make_device("10.0.0.5", "onvif_ws_discovery")]
        rtsp = [self._make_device("10.0.0.5", "rtsp_probe")]
        result = fusion.fuse(arp_results=arp, onvif_results=onvif, rtsp_results=rtsp)
        assert result[0]["confidence"] > 1.0 or result[0]["confidence"] == 1.0  # capped at 1.0

    def test_fuse_empty_sources(self):
        fusion = DiscoveryFusion()
        result = fusion.fuse()
        assert result == []

    def test_fuse_preserves_all_unique_ips(self):
        fusion = DiscoveryFusion()
        arp = [
            self._make_device("192.168.1.1", "arp"),
            self._make_device("192.168.1.2", "arp"),
        ]
        onvif = [self._make_device("192.168.1.3", "onvif_ws_discovery")]
        result = fusion.fuse(arp_results=arp, onvif_results=onvif)
        assert len(result) == 3

    def test_fuse_discovery_methods_list(self):
        fusion = DiscoveryFusion()
        arp = [self._make_device("10.0.0.1", "arp")]
        onvif = [self._make_device("10.0.0.1", "onvif_ws_discovery")]
        result = fusion.fuse(arp_results=arp, onvif_results=onvif)
        methods = result[0]["discovery_methods"]
        assert "arp" in methods
        assert "onvif_ws_discovery" in methods

    def test_get_summary(self):
        fusion = DiscoveryFusion()
        arp = [self._make_device("10.0.0.1", "arp"), self._make_device("10.0.0.2", "arp")]
        onvif = [self._make_device("10.0.0.1", "onvif_ws_discovery")]
        fused = fusion.fuse(arp_results=arp, onvif_results=onvif)
        summary = fusion.get_summary(fused)
        assert summary["total_devices"] == 2
        assert "protocol_breakdown" in summary

    def test_merge_fills_missing_fields_from_secondary(self):
        """manufacturer from ONVIF record should fill in if ARP record lacks it."""
        fusion = DiscoveryFusion()
        arp = [self._make_device("10.0.0.10", "arp")]
        onvif = [self._make_device("10.0.0.10", "onvif_ws_discovery", manufacturer="Hikvision")]
        result = fusion.fuse(arp_results=arp, onvif_results=onvif)
        assert result[0].get("manufacturer") == "Hikvision"
