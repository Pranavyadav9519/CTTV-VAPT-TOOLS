"""
CRR Report Builder
Generates bug-bounty-style penetration reports in HTML, JSON, and Markdown
formats from CRR Pipeline scan results.

Report Structure:
  1. Executive Summary — overall risk, device count, critical findings
  2. Scope & Methodology — network range, protocols, timeline
  3. Attack Narrative — auto-generated step-by-step story per device
  4. Entry/Exit Point Diagram — Mermaid diagram (attack path graph)
  5. Per-Device Vulnerability Cards — severity, CVSS, description, PoC, fix
  6. Evidence Section — banners, HTTP responses, RTSP headers
  7. Remediation Roadmap — prioritised list with effort estimates
  8. Appendices — raw scan data, CVE refs, methodology
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Severity ordering for sorting
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEVERITY_COLOURS = {
    "critical": "#d63031",
    "high": "#e17055",
    "medium": "#fdcb6e",
    "low": "#00b894",
    "info": "#74b9ff",
}


def _count_by_severity(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """Count vulnerabilities grouped by severity."""
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulnerabilities:
        sev = (v.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _overall_risk(devices: List[Dict], attack_paths: List[Dict]) -> str:
    """Determine overall scan risk level from device risk levels."""
    levels = [ap.get("risk_level", "INFO") for ap in attack_paths]
    for target in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if target in levels:
            return target
    return "INFO"


def _effort_estimate(severity: str) -> str:
    """Return a rough effort estimate for remediation."""
    return {
        "critical": "< 1 business day — immediate action required",
        "high": "1–3 business days",
        "medium": "1–2 weeks",
        "low": "Next maintenance window",
        "info": "Best-effort / backlog",
    }.get(severity.lower(), "TBD")


class ReportBuilder:
    """
    Builds comprehensive bug-bounty-style VAPT reports from CRR pipeline output.

    Supports output formats: HTML (styled), JSON (machine-readable), Markdown.

    Usage::

        builder = ReportBuilder(output_dir="reports/crr")
        paths = builder.build(
            scan_metadata=meta,
            devices=devices,
            vulnerabilities_map=vuln_map,
            attack_paths=attack_paths,
            narratives=narratives,
            firmware_map=firmware_map,
            discovery_summary=summary,
        )
        print(paths["html"])
    """

    def __init__(self, output_dir: str = "reports/crr") -> None:
        """
        Initialise the report builder.

        Args:
            output_dir: Directory where report files will be saved.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Jinja2 environment for HTML templates
        templates_dir = Path(__file__).parent / "templates"
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self._jinja_env.globals["severity_colour"] = lambda s: _SEVERITY_COLOURS.get(
            s.lower(), "#999"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_context(
        self,
        scan_metadata: Dict,
        devices: List[Dict],
        vulnerabilities_map: Dict[str, List[Dict]],
        attack_paths: List[Dict],
        narratives: List[Dict],
        firmware_map: Optional[Dict[str, Dict]],
        discovery_summary: Optional[Dict],
    ) -> Dict:
        """
        Build the Jinja2 / JSON context dict from all pipeline inputs.

        Returns a single rich context dict used by all output format renderers.
        """
        all_vulns: List[Dict] = [
            v for vlist in vulnerabilities_map.values() for v in vlist
        ]
        severity_counts = _count_by_severity(all_vulns)
        overall_risk = _overall_risk(devices, attack_paths)

        # Index attack paths and narratives by IP for easy lookup
        ap_by_ip = {ap["ip_address"]: ap for ap in attack_paths}
        narrative_by_ip = {n["ip_address"]: n for n in narratives}
        firmware_by_ip = firmware_map or {}

        # Build per-device cards
        device_cards: List[Dict] = []
        for device in devices:
            ip = device.get("ip_address", "")
            vulns = sorted(
                vulnerabilities_map.get(ip, []),
                key=lambda v: _SEVERITY_ORDER.get((v.get("severity") or "info").lower(), 99),
            )
            ap = ap_by_ip.get(ip, {})
            narrative = narrative_by_ip.get(ip, {})
            fw = firmware_by_ip.get(ip, {})

            device_cards.append({
                "device": device,
                "vulnerabilities": vulns,
                "severity_counts": _count_by_severity(vulns),
                "attack_path": ap,
                "narrative": narrative,
                "firmware": fw,
                "risk_level": ap.get("risk_level", "INFO"),
                "risk_score": ap.get("risk_score", 0.0),
                "mermaid_diagram": ap.get("mermaid_diagram", ""),
            })

        # Sort device cards: highest risk first
        device_cards.sort(
            key=lambda c: (
                _SEVERITY_ORDER.get(c["risk_level"].lower(), 99),
                -c.get("risk_score", 0),
            )
        )

        # Remediation roadmap (deduplicated, severity-ordered)
        roadmap: List[Dict] = []
        seen_remeds: set = set()
        for v in sorted(
            all_vulns,
            key=lambda x: _SEVERITY_ORDER.get((x.get("severity") or "info").lower(), 99),
        ):
            sev = (v.get("severity") or "info").lower()
            title = v.get("title") or v.get("name") or "Unknown"
            key = title.lower()
            if key not in seen_remeds:
                seen_remeds.add(key)
                roadmap.append({
                    "title": title,
                    "severity": sev,
                    "description": v.get("description") or "",
                    "remediation": v.get("remediation") or "Consult vendor advisory.",
                    "effort": _effort_estimate(sev),
                    "cve_id": v.get("cve_id") or "",
                    "cvss_score": v.get("cvss_score") or 0.0,
                    "colour": _SEVERITY_COLOURS.get(sev, "#999"),
                })

        return {
            "report_id": scan_metadata.get("scan_id", "CRR-" + datetime.utcnow().strftime("%Y%m%d%H%M")),
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "scan_metadata": scan_metadata,
            "total_devices": len(devices),
            "total_vulnerabilities": len(all_vulns),
            "severity_counts": severity_counts,
            "overall_risk": overall_risk,
            "overall_risk_colour": _SEVERITY_COLOURS.get(overall_risk.lower(), "#999"),
            "discovery_summary": discovery_summary or {},
            "device_cards": device_cards,
            "remediation_roadmap": roadmap,
            "all_vulnerabilities": sorted(
                all_vulns,
                key=lambda v: _SEVERITY_ORDER.get((v.get("severity") or "info").lower(), 99),
            ),
        }

    # ------------------------------------------------------------------
    # Format renderers
    # ------------------------------------------------------------------

    def _render_html(self, context: Dict) -> str:
        """Render the HTML report from the Jinja2 template."""
        try:
            template = self._jinja_env.get_template("crr_report.html")
            return template.render(**context)
        except Exception as exc:
            logger.warning("Jinja2 HTML template render failed (%s), using built-in template", exc)
            return self._builtin_html(context)

    def _builtin_html(self, ctx: Dict) -> str:
        """
        Minimal built-in HTML report (no external template required).
        Used as fallback when the Jinja2 template is missing.
        """
        sev_counts = ctx.get("severity_counts", {})
        device_rows = ""
        for card in ctx.get("device_cards", []):
            dev = card["device"]
            device_rows += (
                f"<tr>"
                f"<td>{dev.get('ip_address','')}</td>"
                f"<td>{dev.get('manufacturer','') or dev.get('manufacturer_hint','')}</td>"
                f"<td>{dev.get('model','')}</td>"
                f"<td style='color:{card.get('risk_level','INFO')}'>{card.get('risk_level','INFO')}</td>"
                f"<td>{card.get('risk_score',0):.1f}/10</td>"
                f"<td>{len(card.get('vulnerabilities',[]))}</td>"
                f"</tr>"
            )

        vuln_rows = ""
        for v in ctx.get("all_vulnerabilities", []):
            colour = _SEVERITY_COLOURS.get((v.get("severity") or "info").lower(), "#999")
            vuln_rows += (
                f"<tr>"
                f"<td style='border-left: 4px solid {colour};padding-left:8px'>"
                f"{v.get('title','')}</td>"
                f"<td style='color:{colour};font-weight:bold'>{v.get('severity','').upper()}</td>"
                f"<td>{v.get('cve_id','')}</td>"
                f"<td>{v.get('cvss_score','')}</td>"
                f"</tr>"
            )

        narratives_html = ""
        for card in ctx.get("device_cards", []):
            narrative_text = card.get("narrative", {}).get("full_narrative", "")
            ip = card["device"].get("ip_address", "")
            if narrative_text:
                paragraphs = "".join(f"<p>{p}</p>" for p in narrative_text.split("\n\n") if p.strip())
                narratives_html += f"<h3>Device: {ip}</h3>{paragraphs}<hr/>"

        roadmap_rows = ""
        for item in ctx.get("remediation_roadmap", []):
            colour = item.get("colour", "#999")
            roadmap_rows += (
                f"<tr>"
                f"<td style='color:{colour};font-weight:bold'>{item['severity'].upper()}</td>"
                f"<td>{item['title']}</td>"
                f"<td>{item['effort']}</td>"
                f"<td>{item.get('cve_id','')}</td>"
                f"</tr>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CCTV VAPT Report — {ctx.get('report_id','')}</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px;}}
  h1{{color:#58a6ff;}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:8px;}}
  h3{{color:#ffa657;}} table{{width:100%;border-collapse:collapse;margin-bottom:20px;}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:10px 12px;font-size:0.85em;}}
  td{{padding:8px 12px;border-bottom:1px solid #21262d;}} tr:hover{{background:#161b22;}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0;}}
  .risk-critical{{color:#d63031;}} .risk-high{{color:#e17055;}}
  .risk-medium{{color:#fdcb6e;}} .risk-low{{color:#00b894;}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:bold;}}
  .mermaid{{background:#0d1117;border:1px dashed #30363d;padding:12px;font-family:monospace;white-space:pre;font-size:0.8em;overflow-x:auto;}}
  p{{line-height:1.6;}}
  @media print{{body{{background:#fff;color:#000;}}}}
</style>
</head>
<body>
<h1>&#x1F6E1; CCTV VAPT Penetration Report</h1>
<div class="card">
  <h2>Executive Summary</h2>
  <p><strong>Report ID:</strong> {ctx.get('report_id','')}</p>
  <p><strong>Generated:</strong> {ctx.get('generated_at','')}</p>
  <p><strong>Network Range:</strong> {ctx.get('scan_metadata',{{}}).get('network_range','N/A')}</p>
  <p><strong>Total Devices Discovered:</strong> {ctx.get('total_devices',0)}</p>
  <p><strong>Total Vulnerabilities:</strong> {ctx.get('total_vulnerabilities',0)} &nbsp;
     (<span style="color:#d63031">Critical: {sev_counts.get('critical',0)}</span> |
      <span style="color:#e17055">High: {sev_counts.get('high',0)}</span> |
      <span style="color:#fdcb6e">Medium: {sev_counts.get('medium',0)}</span> |
      <span style="color:#00b894">Low: {sev_counts.get('low',0)}</span>)
  </p>
  <p><strong>Overall Risk Level:</strong>
     <span style="font-weight:bold;color:{ctx.get('overall_risk_colour','#999')}">{ctx.get('overall_risk','N/A')}</span>
  </p>
</div>

<h2>Devices Discovered</h2>
<table><thead><tr><th>IP Address</th><th>Manufacturer</th><th>Model</th><th>Risk Level</th><th>Risk Score</th><th>Vulnerabilities</th></tr></thead>
<tbody>{device_rows}</tbody></table>

<h2>Attack Narratives</h2>
{narratives_html if narratives_html else '<p>No attack narratives generated.</p>'}

<h2>Vulnerability Findings</h2>
<table><thead><tr><th>Vulnerability</th><th>Severity</th><th>CVE</th><th>CVSS</th></tr></thead>
<tbody>{vuln_rows}</tbody></table>

<h2>Remediation Roadmap</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Effort Estimate</th><th>CVE</th></tr></thead>
<tbody>{roadmap_rows}</tbody></table>

<div class="card">
  <h2>Attack Path Diagrams (Mermaid)</h2>
  {"".join(f'<h3>{c["device"].get("ip_address","")}</h3><div class="mermaid">{c.get("mermaid_diagram","")}</div>' for c in ctx.get("device_cards",[]) if c.get("mermaid_diagram"))}
</div>

<div class="card" style="font-size:0.8em;color:#8b949e;">
  <p>This report was generated automatically by CTTV-VAPT-TOOLS CRR Pipeline.
     All assessments are non-destructive. CVE data is from public NVD database.
     This document is confidential — handle in accordance with your organisation's data classification policy.</p>
</div>
</body></html>"""

    def _render_json(self, context: Dict) -> str:
        """Render machine-readable JSON report."""
        def _safe(obj):
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            if isinstance(obj, dict):
                return {k: _safe(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_safe(i) for i in obj]
            return str(obj)

        return json.dumps(_safe(context), indent=2, ensure_ascii=False)

    def _render_markdown(self, context: Dict) -> str:
        """Render Markdown report."""
        lines = [
            f"# CCTV VAPT Penetration Report",
            f"",
            f"**Report ID:** {context.get('report_id','')}  ",
            f"**Generated:** {context.get('generated_at','')}  ",
            f"**Network Range:** {context.get('scan_metadata',{}).get('network_range','N/A')}  ",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Devices | {context.get('total_devices',0)} |",
            f"| Total Vulnerabilities | {context.get('total_vulnerabilities',0)} |",
            f"| Overall Risk Level | **{context.get('overall_risk','N/A')}** |",
        ]
        sc = context.get("severity_counts", {})
        lines += [
            f"| Critical | {sc.get('critical',0)} |",
            f"| High | {sc.get('high',0)} |",
            f"| Medium | {sc.get('medium',0)} |",
            f"| Low | {sc.get('low',0)} |",
            f"",
            f"## Devices Discovered",
            f"",
            f"| IP Address | Manufacturer | Model | Risk Level | Risk Score |",
            f"|------------|--------------|-------|------------|------------|",
        ]
        for card in context.get("device_cards", []):
            dev = card["device"]
            lines.append(
                f"| {dev.get('ip_address','')} "
                f"| {dev.get('manufacturer','') or dev.get('manufacturer_hint','')} "
                f"| {dev.get('model','')} "
                f"| {card.get('risk_level','INFO')} "
                f"| {card.get('risk_score',0):.1f}/10 |"
            )

        lines += ["", "## Attack Narratives", ""]
        for card in context.get("device_cards", []):
            narrative = card.get("narrative", {}).get("full_narrative", "")
            if narrative:
                ip = card["device"].get("ip_address", "")
                lines.append(f"### Device: {ip}")
                lines.append("")
                lines.append(narrative)
                lines.append("")

        lines += ["", "## Vulnerability Findings", ""]
        lines += [
            "| Vulnerability | Severity | CVE | CVSS |",
            "|---------------|----------|-----|------|",
        ]
        for v in context.get("all_vulnerabilities", []):
            lines.append(
                f"| {v.get('title','')} "
                f"| {(v.get('severity') or '').upper()} "
                f"| {v.get('cve_id','')} "
                f"| {v.get('cvss_score','')} |"
            )

        lines += ["", "## Remediation Roadmap", ""]
        lines += [
            "| Severity | Finding | Effort |",
            "|----------|---------|--------|",
        ]
        for item in context.get("remediation_roadmap", []):
            lines.append(
                f"| {item['severity'].upper()} | {item['title']} | {item['effort']} |"
            )

        lines += [
            "",
            "---",
            "*Generated by CTTV-VAPT-TOOLS CRR Pipeline — Confidential*",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        scan_metadata: Dict,
        devices: List[Dict],
        vulnerabilities_map: Dict[str, List[Dict]],
        attack_paths: List[Dict],
        narratives: List[Dict],
        firmware_map: Optional[Dict[str, Dict]] = None,
        discovery_summary: Optional[Dict] = None,
        formats: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """
        Build and save reports in all requested formats.

        Args:
            scan_metadata: Scan session metadata (scan_id, operator, network_range, …).
            devices: Unified device list from DiscoveryFusion.
            vulnerabilities_map: Dict mapping IP → list of vulnerability dicts.
            attack_paths: List of attack path result dicts from AttackPathEngine.
            narratives: List of narrative dicts from NarrativeEngine.
            firmware_map: Optional dict mapping IP → firmware extraction result.
            discovery_summary: Optional dict from DiscoveryFusion.get_summary().
            formats: List of output formats to generate.  Defaults to
                ``["html", "json", "markdown"]``.

        Returns:
            Dict mapping format name → absolute path of saved report file.
        """
        if formats is None:
            formats = ["html", "json", "markdown"]

        context = self._build_context(
            scan_metadata=scan_metadata,
            devices=devices,
            vulnerabilities_map=vulnerabilities_map,
            attack_paths=attack_paths,
            narratives=narratives,
            firmware_map=firmware_map,
            discovery_summary=discovery_summary,
        )

        report_id = context["report_id"]
        saved: Dict[str, str] = {}

        renderers = {
            "html": (self._render_html, ".html"),
            "json": (self._render_json, ".json"),
            "markdown": (self._render_markdown, ".md"),
        }

        for fmt in formats:
            if fmt not in renderers:
                logger.warning("Unknown report format '%s', skipping.", fmt)
                continue
            renderer, ext = renderers[fmt]
            try:
                content = renderer(context)
                filename = f"crr_report_{report_id}{ext}"
                filepath = self.output_dir / filename
                filepath.write_text(content, encoding="utf-8")
                saved[fmt] = str(filepath.resolve())
                logger.info("CRR report saved: %s", saved[fmt])
            except Exception as exc:
                logger.error("Failed to generate %s report: %s", fmt, exc)

        return saved
