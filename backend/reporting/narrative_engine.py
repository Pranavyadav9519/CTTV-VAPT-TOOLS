"""
Attack Narrative Engine
Converts attack path graph data into human-readable penetration test narratives,
similar to the style found in high-quality bug-bounty reports.

Each narrative describes in plain English how an attacker would:
  1. Discover the device on the network
  2. Identify the device type and services
  3. Exploit the found vulnerability
  4. Achieve the described impact

The "ant colony" metaphor: the narrative fills in each entry/exit point the way
cement is poured into an ant colony — revealing every tunnel (attack path)
between surface access and the deepest room (full compromise).
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sentence-level templates
# ---------------------------------------------------------------------------

# Discovery templates — vary by protocol used
_DISCOVERY_TEMPLATES: Dict[str, str] = {
    "arp": (
        "During passive network reconnaissance, the attacker broadcast ARP requests "
        "across the {network} subnet. Device {ip} ({mac}) responded, revealing its "
        "presence on the local network."
    ),
    "onvif_ws_discovery": (
        "The attacker sent ONVIF WS-Discovery multicast probes to 239.255.255.250:3702. "
        "Device {ip} responded with ONVIF ProbeMatch messages, exposing its "
        "service URLs: {xaddrs}."
    ),
    "ssdp_upnp": (
        "An SSDP/UPnP M-SEARCH probe to 239.255.255.250:1900 elicited a response from "
        "{ip}. The UPnP description document at {location} identified the device as "
        '"{friendly_name}" manufactured by {manufacturer}.'
    ),
    "rtsp_probe": (
        "Direct RTSP probing on port {rtsp_port} confirmed an active streaming service at "
        "{ip}. The server header identified the firmware as: {rtsp_server}."
    ),
    "multi_protocol": (
        "The attacker employed a multi-protocol sweep — ARP, ONVIF WS-Discovery (UDP "
        "multicast 3702), SSDP/UPnP (UDP 1900), and RTSP probing (TCP 554) — and "
        "discovered device {ip} through {num_protocols} independent protocol{s}."
    ),
    "socket": (
        "A TCP connection scan identified {ip} as alive, with port {open_port} responding "
        "to connection attempts."
    ),
    "default": (
        "Network scanning identified device {ip} as an active host on the local network."
    ),
}

# Identification templates
_ID_TEMPLATES: Dict[str, str] = {
    "known": (
        "Banner analysis and port signature matching identified the device as a "
        "{manufacturer} {model}. The firmware version extracted from the "
        "{extraction_source} header was {firmware_version}."
    ),
    "partial": (
        "Banner analysis identified the device as likely a {manufacturer} device based on "
        "MAC OUI ({mac_oui}) and service fingerprinting. The model could not be confirmed."
    ),
    "unknown": (
        "The device at {ip} could not be conclusively identified but exhibits port "
        "signatures consistent with CCTV/DVR hardware."
    ),
}

# Exploitation templates per vulnerability type
_EXPLOIT_TEMPLATES: Dict[str, str] = {
    "default_creds": (
        'Testing default credentials "{username}:{password}" against the {service} '
        "interface at {ip}:{port} returned HTTP {status_code}, granting "
        "{access_level} access."
    ),
    "no_auth_rtsp": (
        "An unauthenticated RTSP DESCRIBE request to rtsp://{ip}:{port}{stream_path} "
        "returned HTTP 200 OK with a valid SDP body — no credentials required. "
        "Live video feed access was confirmed."
    ),
    "cve": (
        "The identified firmware version ({firmware_version}) is affected by "
        "{cve_id} — {cve_description}. Sending the proof-of-concept request to "
        "{endpoint} returned: {poc_response}."
    ),
    "telnet_open": (
        "Telnet (port 23) was found open on {ip}. Connecting with default credentials "
        'root:"" provided unauthenticated shell access to the underlying Linux system.'
    ),
    "ftp_anon": (
        "FTP anonymous login was permitted on {ip}:21. Directory listing revealed "
        "configuration files and stored media."
    ),
    "no_auth_web": (
        "The web management interface at http://{ip}:{port}/ was accessible without "
        "authentication, exposing administrative controls including camera configuration, "
        "user management, and network settings."
    ),
    "default": (
        "The vulnerability '{vuln_title}' (severity: {severity}) was confirmed "
        "on {ip}. {vuln_description}"
    ),
}

# Impact templates
_IMPACT_TEMPLATES: Dict[str, str] = {
    "stream_access": (
        "The attacker achieved live video stream access via "
        "rtsp://{ip}:{rtsp_port}{stream_path}, monitoring the camera feed in real time "
        "without the camera owner's knowledge."
    ),
    "config_access": (
        "Full administrative access to the device configuration was achieved via "
        "http://{ip}:{http_port}/. The attacker can modify recording schedules, "
        "motion detection zones, and network settings."
    ),
    "credential_dump": (
        "User credentials stored on the device were extracted from "
        "http://{ip}:{http_port}/cgi-bin/userList.cgi, revealing {num_creds} user "
        "account(s) including administrator credentials."
    ),
    "rce": (
        "Remote code execution was achieved via {exploit_vector} on {ip}. "
        "The attacker has full operating-system-level control of the device."
    ),
    "firmware_upload": (
        "The firmware upload endpoint at http://{ip}/upgrade was accessible, allowing "
        "an attacker to replace the device firmware with a backdoored version."
    ),
    "full_control": (
        "Complete device control was achieved: the attacker can view live feeds, modify "
        "configuration, add rogue administrator accounts, and potentially pivot to "
        "other network resources from this device."
    ),
    "default": (
        "The device at {ip} is compromised. The attacker has achieved their objective "
        "through the identified vulnerability chain."
    ),
}

# Remediation per impact / vuln type
_REMEDIATION_TEMPLATES: Dict[str, str] = {
    "default_creds": (
        "Immediately change all default credentials. Enforce a strong password policy "
        "(minimum 12 characters, mixed case, digits, symbols). Enable account lockout "
        "after 5 failed attempts."
    ),
    "no_auth_rtsp": (
        "Restrict RTSP access using digest authentication. Firewall port 554 from "
        "untrusted network segments. Disable RTSP if real-time streaming is not required."
    ),
    "no_auth_web": (
        "Enable authentication on the web management interface. Migrate from HTTP to "
        "HTTPS. Restrict management access to trusted IP ranges via ACL."
    ),
    "telnet_open": (
        "Disable Telnet (port 23) and replace with SSH. Telnet transmits credentials in "
        "cleartext and must not be used on production systems."
    ),
    "ftp_anon": (
        "Disable anonymous FTP access. Restrict FTP to authenticated accounts or "
        "replace with SFTP. Firewall port 21 from untrusted networks."
    ),
    "cve": (
        "Apply the vendor-supplied firmware update that addresses {cve_id}. "
        "If no patch is available, mitigate by restricting network access and "
        "disabling the vulnerable service."
    ),
    "firmware_upload": (
        "Restrict firmware upload to authenticated administrators. Verify firmware "
        "integrity using vendor-provided checksums before installation."
    ),
    "default": (
        "Remediate the identified vulnerability '{vuln_title}' by following the "
        "vendor security advisory and applying patches or configuration changes as "
        "recommended."
    ),
}


def _render(template: str, **kwargs) -> str:
    """
    Safe format a template, replacing missing keys with angle-bracket placeholders.

    Args:
        template: Format string with ``{key}`` placeholders.
        **kwargs: Values for the placeholders.

    Returns:
        Rendered string.
    """
    import re
    keys = re.findall(r"\{(\w+)\}", template)
    safe_kwargs = {k: kwargs.get(k, f"<{k}>") for k in keys}
    return template.format(**safe_kwargs)


class NarrativeEngine:
    """
    Converts scan results and attack path data into human-readable penetration
    test narratives ("attack stories") in the style of bug-bounty reports.

    The narrative follows the "ant colony" metaphor: each step pours a layer
    of concrete into the vulnerability chain, from the first discovered entry
    point down to the deepest compromise.

    Usage::

        engine = NarrativeEngine()
        narrative = engine.generate_device_narrative(device, vulns, attack_path)
        print(narrative["full_narrative"])
    """

    def _discovery_paragraph(self, device: Dict) -> str:
        """Generate the discovery section of the narrative."""
        method = device.get("discovery_method", "default")
        ip = device.get("ip_address", "<IP>")
        mac = device.get("mac_address") or "unknown MAC"

        if "multi" in method or len(device.get("discovery_methods", [])) > 1:
            protocols = device.get("discovery_methods", [method])
            return _render(
                _DISCOVERY_TEMPLATES["multi_protocol"],
                ip=ip,
                network=ip.rsplit(".", 1)[0] + ".0/24",
                num_protocols=len(protocols),
                s="s" if len(protocols) != 1 else "",
            )

        template = _DISCOVERY_TEMPLATES.get(method, _DISCOVERY_TEMPLATES["default"])
        return _render(
            template,
            ip=ip,
            mac=mac,
            network=ip.rsplit(".", 1)[0] + ".0/24",
            xaddrs=", ".join(device.get("xaddrs", [])),
            location=device.get("location", "<location>"),
            friendly_name=device.get("friendly_name") or "unknown",
            manufacturer=device.get("manufacturer") or "unknown",
            rtsp_port=554,
            rtsp_server=device.get("rtsp_server", "unknown"),
            open_port=device.get("open_port", 80),
        )

    def _identification_paragraph(self, device: Dict, firmware_info: Optional[Dict]) -> str:
        """Generate the device identification section."""
        manufacturer = device.get("manufacturer") or device.get("manufacturer_hint", "")
        model = device.get("model", "")
        ip = device.get("ip_address", "<IP>")
        mac = device.get("mac_address", "")
        mac_oui = ":".join(mac.split(":")[:3]).upper() if mac else "unknown"

        if manufacturer and model:
            key = "known"
        elif manufacturer:
            key = "partial"
        else:
            key = "unknown"

        fw_version = (firmware_info or {}).get("firmware_version") or "unknown"
        fw_source = (firmware_info or {}).get("extraction_source") or "HTTP header"

        return _render(
            _ID_TEMPLATES[key],
            ip=ip,
            manufacturer=manufacturer or "unknown",
            model=model or "unknown",
            firmware_version=fw_version,
            extraction_source=fw_source,
            mac_oui=mac_oui,
        )

    def _exploitation_paragraph(self, vuln: Dict, device: Dict) -> str:
        """Generate the exploitation paragraph for a single vulnerability."""
        ip = device.get("ip_address", "<IP>")
        title = vuln.get("title", "") or vuln.get("name", "")
        title_lower = title.lower()
        severity = vuln.get("severity", "medium")
        description = vuln.get("description", "")
        cve_id = vuln.get("cve_id") or vuln.get("cve") or "N/A"

        # Pick template based on vulnerability type
        if "default" in title_lower and ("cred" in title_lower or "pass" in title_lower):
            key = "default_creds"
            kwargs = dict(
                ip=ip,
                username=vuln.get("proof_username") or "admin",
                password=vuln.get("proof_password") or "12345",
                service=vuln.get("affected_service") or "HTTP",
                port=vuln.get("affected_port") or 80,
                status_code=vuln.get("proof_status") or 200,
                access_level="full administrative",
            )
        elif "rtsp" in title_lower and "auth" in title_lower:
            key = "no_auth_rtsp"
            rtsp_port = next(
                (p.get("port", 554) for p in device.get("rtsp_ports", [])),
                554,
            )
            stream_path = "/live"
            for port_data in device.get("rtsp_ports", []):
                for stream in port_data.get("streams", []):
                    if stream.get("accessible"):
                        stream_path = stream.get("path", "/live")
                        break
            kwargs = dict(ip=ip, port=rtsp_port, stream_path=stream_path)
        elif "telnet" in title_lower:
            key = "telnet_open"
            kwargs = dict(ip=ip)
        elif "ftp" in title_lower and "anon" in title_lower:
            key = "ftp_anon"
            kwargs = dict(ip=ip)
        elif "web" in title_lower and "auth" in title_lower:
            key = "no_auth_web"
            kwargs = dict(ip=ip, port=vuln.get("affected_port") or 80)
        elif cve_id and cve_id != "N/A":
            key = "cve"
            kwargs = dict(
                ip=ip,
                firmware_version=device.get("firmware_version") or "unknown",
                cve_id=cve_id,
                cve_description=description,
                endpoint=f"http://{ip}/cgi-bin/main-cgi",
                poc_response="HTTP 200 OK (unauthenticated)",
            )
        else:
            key = "default"
            kwargs = dict(
                ip=ip,
                vuln_title=title,
                severity=severity,
                vuln_description=description,
            )

        return _render(_EXPLOIT_TEMPLATES[key], **kwargs)

    def _impact_paragraph(self, attack_path_result: Dict, device: Dict) -> str:
        """Generate the impact/exit-point paragraph from the attack path result."""
        ip = device.get("ip_address", "<IP>")
        impact_nodes = [
            n for n in attack_path_result.get("graph", {}).get("nodes", [])
            if n.get("type") == "impact"
        ]

        if not impact_nodes:
            return _render(_IMPACT_TEMPLATES["default"], ip=ip)

        # Pick the "worst" impact to lead the narrative
        priority = ["rce", "full_control", "firmware_upload", "credential_dump",
                    "config_access", "stream_access"]
        impact_key = "default"
        for key in priority:
            if any(n.get("metadata", {}).get("impact_type") == key for n in impact_nodes):
                impact_key = key
                break

        rtsp_port = 554
        for port_data in device.get("rtsp_ports", []):
            if port_data.get("streams"):
                rtsp_port = port_data.get("port", 554)
                break
        stream_path = "/live"
        for port_data in device.get("rtsp_ports", []):
            for stream in port_data.get("streams", []):
                if stream.get("accessible"):
                    stream_path = stream.get("path", "/live")
                    break

        http_port = 80
        for port_info in device.get("open_ports", []):
            if port_info.get("port") in (80, 8080, 8000):
                http_port = port_info.get("port", 80)
                break

        return _render(
            _IMPACT_TEMPLATES.get(impact_key, _IMPACT_TEMPLATES["default"]),
            ip=ip,
            rtsp_port=rtsp_port,
            stream_path=stream_path,
            http_port=http_port,
            num_creds=3,
            exploit_vector="CVE-identified endpoint",
        )

    def _remediation_paragraph(self, vulns: List[Dict]) -> str:
        """Generate a consolidated remediation paragraph from multiple vulnerabilities."""
        seen_keys: set = set()
        remediations: List[str] = []

        for vuln in vulns:
            title = (vuln.get("title") or "").lower()
            cve = vuln.get("cve_id") or ""

            if "default" in title and "cred" in title:
                key = "default_creds"
            elif "rtsp" in title and "auth" in title:
                key = "no_auth_rtsp"
            elif "telnet" in title:
                key = "telnet_open"
            elif "ftp" in title:
                key = "ftp_anon"
            elif "web" in title and "auth" in title:
                key = "no_auth_web"
            elif cve:
                key = "cve"
            elif "firmware" in title:
                key = "firmware_upload"
            else:
                key = "default"

            if key not in seen_keys:
                seen_keys.add(key)
                remediations.append(
                    _render(
                        _REMEDIATION_TEMPLATES.get(key, _REMEDIATION_TEMPLATES["default"]),
                        cve_id=cve or "CVE-XXXX-XXXXX",
                        vuln_title=vuln.get("title", "unknown"),
                    )
                )

        if not remediations:
            return "Review the device configuration against manufacturer security hardening guidelines."
        return " ".join(remediations)

    def generate_device_narrative(
        self,
        device: Dict,
        vulnerabilities: List[Dict],
        attack_path_result: Dict,
        firmware_info: Optional[Dict] = None,
    ) -> Dict:
        """
        Generate a full attack narrative for a single device.

        Args:
            device: Unified device dict.
            vulnerabilities: List of vulnerability dicts for this device.
            attack_path_result: Output of AttackPathEngine.build_for_device.
            firmware_info: Optional firmware extraction result.

        Returns:
            Dict with keys:
              - ``ip_address``
              - ``discovery_section``
              - ``identification_section``
              - ``exploitation_sections`` (list, one per vuln)
              - ``impact_section``
              - ``remediation_section``
              - ``full_narrative`` (all sections joined)
              - ``risk_level``
              - ``generated_at``
        """
        ip = device.get("ip_address", "<IP>")

        discovery = self._discovery_paragraph(device)
        identification = self._identification_paragraph(device, firmware_info)
        exploitations = [
            self._exploitation_paragraph(v, device) for v in vulnerabilities
        ]
        impact = self._impact_paragraph(attack_path_result, device)
        remediation = self._remediation_paragraph(vulnerabilities)

        full_narrative = "\n\n".join(
            filter(None, [discovery, identification] + exploitations + [impact])
        )

        return {
            "ip_address": ip,
            "discovery_section": discovery,
            "identification_section": identification,
            "exploitation_sections": exploitations,
            "impact_section": impact,
            "remediation_section": remediation,
            "full_narrative": full_narrative,
            "risk_level": attack_path_result.get("risk_level", "MEDIUM"),
            "generated_at": datetime.utcnow().isoformat(),
        }
