"""
LAYER 3: RISK INTELLIGENCE & CONTEXT ENGINE
Calculates contextual risk using multiple factors beyond CVSS score.

This layer provides:
- Asset criticality assessment
- Network exposure analysis
- Authentication state evaluation
- Exploit availability checking
- Contextual risk rating (Critical/High/Medium/Low)
- Risk scoring (0-100 scale)

The risk calculation is based on:
1. CVSS Score (technical severity)
2. Asset Criticality (business importance)
3. Network Exposure (internal vs external)
4. Authentication State (unauthenticated access is higher risk)
5. Exploit Availability (exploitability)
6. Asset Type Context (CCTV devices have unique risk profile)
"""

from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


class RiskIntelligenceEngine:
    """
    Calculates contextual risk ratings and scores for vulnerabilities and assets.
    Ensures risk assessment reflects real-world business impact, not just technical metrics.
    """

    def __init__(self):
        """Initialize risk intelligence engine"""
        self.enriched_assets = {}
        self.enriched_vulnerabilities = []
        self.risk_metadata = {}

        # Risk scoring weights (configurable for different organizations)
        self.weights = {
            "cvss_score": 0.25,  # Technical severity
            "asset_criticality": 0.25,  # Business importance
            "network_exposure": 0.20,  # Internal vs external
            "auth_state": 0.15,  # Unauthenticated access risk
            "exploit_availability": 0.15,  # Exploitability
        }

    def calculate_contextual_risk(
        self, normalized_assets: List[Dict], normalized_vulns: List[Dict]
    ) -> Tuple[Dict, bool]:
        """
        Calculate contextual risk for all assets and vulnerabilities.

        Args:
            normalized_assets: List of normalized assets from Layer 2
            normalized_vulns: List of normalized vulnerabilities from Layer 2

        Returns:
            Tuple of (enriched_data_dict, success_bool)
        """
        try:
            # Step 1: Assess asset criticality
            self._assess_asset_criticality(normalized_assets)

            # Step 2: Enrich each asset with risk context
            self._enrich_assets_with_context(normalized_assets)

            # Step 3: Calculate risk for each vulnerability
            self._calculate_vulnerability_risk(normalized_vulns)

            # Step 4: Aggregate risk at asset level
            self._aggregate_asset_risk()

            # Step 5: Validate risk calculations
            self._validate_risk_calculations()

            enriched_output = {
                "risk_enriched_assets": list(self.enriched_assets.values()),
                "risk_enriched_vulnerabilities": self.enriched_vulnerabilities,
                "risk_summary": self._get_risk_summary(),
                "risk_recommendations": self._generate_risk_recommendations(),
            }

            logger.info(
                f"Risk calculation completed for {len(self.enriched_assets)} assets"
            )
            return enriched_output, True

        except Exception as e:
            logger.error(f"Error during risk calculation: {str(e)}")
            return {}, False

    # =========================================================================
    # ASSET CRITICALITY ASSESSMENT
    # =========================================================================

    def _assess_asset_criticality(self, assets: List[Dict]):
        """
        Assess and assign criticality level to each asset.
        CCTV/DVR systems may have high business criticality for security operations.
        """
        for asset in assets:
            criticality = self._determine_asset_criticality(asset)
            asset["criticality"] = criticality

    def _determine_asset_criticality(self, asset: Dict) -> str:
        """
        Determine asset criticality based on:
        - Device type (CCTV/DVR = potentially critical)
        - Service roles (NVR = more critical than single camera)
        - Network position
        """
        device_type = asset.get("asset_type", "unknown").lower()
        is_cctv = asset.get("is_cctv", False)

        # CCTV/DVR devices are typically critical for security operations
        if is_cctv:
            # NVR (Network Video Recorder) is typically more critical than individual cameras
            if "nvr" in device_type or "ndr" in device_type:
                return "critical"
            # DVR is also important
            elif "dvr" in device_type:
                return "high"
            # Individual cameras
            else:
                return "medium"

        # Non-CCTV devices
        if (
            "network_device" in device_type
            or "switch" in device_type
            or "router" in device_type
        ):
            return "critical"  # Network infrastructure is critical
        elif "server" in device_type or "storage" in device_type:
            return "high"

        return "low"

    # =========================================================================
    # ASSET CONTEXT ENRICHMENT
    # =========================================================================

    def _enrich_assets_with_context(self, assets: List[Dict]):
        """Enrich each asset with risk context factors"""
        for asset in assets:
            enriched_asset = asset.copy()

            # Add risk context factors
            enriched_asset["risk_context"] = {
                "criticality_factor": self._score_criticality(asset["criticality"]),
                "network_exposure_factor": self._score_network_exposure(
                    asset["network_segment"]
                ),
                "auth_state_factor": self._score_auth_state(
                    asset["authentication_state"]
                ),
                "open_ports_count": len(asset.get("ports", [])),
                "vulnerability_count": len(asset.get("vulnerabilities", [])),
                "is_cctv": asset.get("is_cctv", False),
                "has_default_creds": asset.get("has_default_credentials", False),
            }

            # Store enriched asset
            self.enriched_assets[asset["asset_id"]] = enriched_asset

    def _score_criticality(self, criticality_level: str) -> float:
        """Convert criticality level to risk score factor (0-1)"""
        scores = {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
            "unknown": 0.3,
        }
        return scores.get(criticality_level.lower(), 0.3)

    def _score_network_exposure(self, network_segment: str) -> float:
        """Score network exposure risk (0-1)"""
        scores = {
            "external": 1.0,  # Internet-facing = high risk
            "dmz": 0.75,  # DMZ = moderate risk
            "internal": 0.3,  # Internal network = lower risk
            "unknown": 0.5,
        }
        return scores.get(network_segment.lower(), 0.5)

    def _score_auth_state(self, auth_state: str) -> float:
        """Score authentication state risk (0-1)"""
        # Unauthenticated = highest risk
        scores = {
            "unauthenticated": 1.0,
            "mixed": 0.75,
            "authenticated": 0.25,
            "unknown": 0.5,
        }
        return scores.get(auth_state.lower(), 0.5)

    # =========================================================================
    # VULNERABILITY RISK CALCULATION
    # =========================================================================

    def _calculate_vulnerability_risk(self, vulns: List[Dict]):
        """Calculate contextual risk rating and score for each vulnerability"""
        for vuln in vulns:
            enriched_vuln = vuln.copy()

            # Get asset context
            asset = self.enriched_assets.get(vuln["asset_id"])
            if not asset:
                logger.warning(
                    f"Asset {vuln['asset_id']} not found for vulnerability {vuln['vulnerability_id']}"
                )
                asset = {"risk_context": {}}

            # Calculate composite risk score
            risk_data = self._compute_risk_score(vuln, asset)

            enriched_vuln["risk_rating"] = risk_data["risk_rating"]
            enriched_vuln["risk_score"] = risk_data["risk_score"]
            enriched_vuln["risk_factors"] = risk_data["risk_factors"]
            enriched_vuln["remediation_priority"] = risk_data["remediation_priority"]
            enriched_vuln["risk_justification"] = risk_data["justification"]

            self.enriched_vulnerabilities.append(enriched_vuln)

    def _compute_risk_score(self, vuln: Dict, asset: Dict) -> Dict:
        """
        Compute composite risk score using weighted factors.
        Score = (CVSS * weight) + (Criticality * weight) + (Exposure * weight) + ...
        """
        # Get individual risk factors
        cvss_score = vuln.get("cvss_score", 0.0) or 0.0
        cvss_factor = min(cvss_score / 10.0, 1.0)  # Normalize to 0-1

        risk_context = asset.get("risk_context", {})
        criticality_factor = risk_context.get("criticality_factor", 0.3)
        network_exposure_factor = risk_context.get("network_exposure_factor", 0.5)
        auth_state_factor = risk_context.get("auth_state_factor", 0.5)

        # Check exploit availability
        exploit_factor = 1.0 if vuln.get("exploit_available", False) else 0.5

        # Calculate weighted composite score
        composite_score = (
            cvss_factor * self.weights["cvss_score"]
            + criticality_factor * self.weights["asset_criticality"]
            + network_exposure_factor * self.weights["network_exposure"]
            + auth_state_factor * self.weights["auth_state"]
            + exploit_factor * self.weights["exploit_availability"]
        ) * 100  # Scale to 0-100

        # Determine risk rating based on composite score
        risk_rating = self._score_to_rating(composite_score)

        # Calculate remediation priority based on risk rating
        priority_map = {
            "critical": "Immediate (0-4 hours)",
            "high": "24 hours",
            "medium": "7 days",
            "low": "30 days",
            "info": "Best practice review",
        }

        # Generate justification
        justification = self._generate_risk_justification(vuln, asset, risk_context)

        return {
            "risk_score": round(composite_score, 1),
            "risk_rating": risk_rating,
            "remediation_priority": priority_map.get(risk_rating, "Unknown"),
            "risk_factors": {
                "cvss_score": cvss_score,
                "cvss_factor": round(cvss_factor, 2),
                "asset_criticality": risk_context.get("criticality_factor", 0.3),
                "network_exposure": network_exposure_factor,
                "auth_state": auth_state_factor,
                "exploit_available": vuln.get("exploit_available", False),
                "exploit_factor": exploit_factor,
            },
            "justification": justification,
        }

    def _score_to_rating(self, score: float) -> str:
        """Convert numeric risk score to risk rating"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "info"

    def _generate_risk_justification(
        self, vuln: Dict, asset: Dict, risk_context: Dict
    ) -> str:
        """Generate human-readable risk justification"""
        factors = []

        # CVSS factor
        cvss = vuln.get("cvss_score", 0.0) or 0.0
        if cvss >= 7.0:
            factors.append(f"High technical severity (CVSS {cvss:.1f})")

        # Asset criticality
        criticality = asset.get("criticality", "unknown")
        if criticality in ["critical", "high"]:
            factors.append(f"{criticality.title()} business asset")

        # CCTV-specific risk
        if asset.get("is_cctv"):
            factors.append(
                "CCTV/Security camera system (critical for facility security)"
            )

        # Network exposure
        if asset.get("network_segment") == "external":
            factors.append("Externally accessible (internet-facing)")

        # Authentication risk
        if asset.get("risk_context", {}).get("has_default_creds"):
            factors.append("Default credentials detected (unauthenticated access)")

        # Exploit availability
        if vuln.get("exploit_available"):
            factors.append("Exploit publicly available")

        if factors:
            return f"Risk elevated due to: {'; '.join(factors)}"
        else:
            return "Standard technical vulnerability in isolated asset"

    # =========================================================================
    # ASSET-LEVEL RISK AGGREGATION
    # =========================================================================

    def _aggregate_asset_risk(self):
        """
        Aggregate vulnerability risk to asset level.
        Determine overall asset risk based on most severe vulnerability.
        """
        for asset_id, asset in self.enriched_assets.items():
            # Find all vulnerabilities for this asset
            asset_vulns = [
                v for v in self.enriched_vulnerabilities if v["asset_id"] == asset_id
            ]

            if not asset_vulns:
                asset["overall_risk_rating"] = "low"
                asset["overall_risk_score"] = 0.0
                asset["most_severe_vuln"] = None
            else:
                # Most severe vulnerability determines overall asset risk
                most_severe = max(asset_vulns, key=lambda v: v["risk_score"])

                asset["overall_risk_rating"] = most_severe["risk_rating"]
                asset["overall_risk_score"] = most_severe["risk_score"]
                asset["most_severe_vuln"] = {
                    "title": most_severe["title"],
                    "risk_rating": most_severe["risk_rating"],
                    "risk_score": most_severe["risk_score"],
                }

                # Summary stats
                asset["critical_vuln_count"] = len(
                    [v for v in asset_vulns if v["risk_rating"] == "critical"]
                )
                asset["high_vuln_count"] = len(
                    [v for v in asset_vulns if v["risk_rating"] == "high"]
                )
                asset["medium_vuln_count"] = len(
                    [v for v in asset_vulns if v["risk_rating"] == "medium"]
                )

    # =========================================================================
    # VALIDATION & SUMMARY
    # =========================================================================

    def _validate_risk_calculations(self):
        """Validate risk calculation consistency"""
        for vuln in self.enriched_vulnerabilities:
            risk_score = vuln.get("risk_score", 0)
            risk_rating = vuln.get("risk_rating", "unknown")

            # Validate score matches rating
            expected_rating = self._score_to_rating(risk_score)
            if expected_rating != risk_rating:
                logger.warning(
                    f"Risk rating mismatch for {vuln['vulnerability_id']}: "
                    f"score {risk_score} suggests {expected_rating} but got {risk_rating}"
                )

    def _get_risk_summary(self) -> Dict:
        """Get summary statistics of risk assessment"""
        critical_count = sum(
            1 for v in self.enriched_vulnerabilities if v["risk_rating"] == "critical"
        )
        high_count = sum(
            1 for v in self.enriched_vulnerabilities if v["risk_rating"] == "high"
        )
        medium_count = sum(
            1 for v in self.enriched_vulnerabilities if v["risk_rating"] == "medium"
        )
        low_count = sum(
            1 for v in self.enriched_vulnerabilities if v["risk_rating"] == "low"
        )

        return {
            "total_assets": len(self.enriched_assets),
            "total_vulnerabilities": len(self.enriched_vulnerabilities),
            "risk_distribution": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
            "cctv_devices_at_risk": sum(
                1
                for a in self.enriched_assets.values()
                if a.get("is_cctv") and a["overall_risk_rating"] in ["critical", "high"]
            ),
            "externally_exposed": sum(
                1
                for a in self.enriched_assets.values()
                if a["network_segment"] == "external"
            ),
            "with_default_credentials": sum(
                1
                for a in self.enriched_assets.values()
                if a.get("risk_context", {}).get("has_default_creds")
            ),
        }

    def _generate_risk_recommendations(self) -> List[str]:
        """Generate strategic recommendations based on risk analysis"""
        recommendations = []

        summary = self._get_risk_summary()

        # Critical items
        if summary["risk_distribution"]["critical"] > 0:
            recommendations.append(
                f"URGENT: {summary['risk_distribution']['critical']} critical vulnerabilities detected. "
                "Immediate remediation required within 4 hours."
            )

        # CCTV-specific recommendations
        if summary["cctv_devices_at_risk"] > 0:
            recommendations.append(
                f"{summary['cctv_devices_at_risk']} CCTV/DVR systems have high-risk vulnerabilities. "
                "Prioritize updates and network isolation."
            )

        # External exposure
        if summary["externally_exposed"] > 0:
            recommendations.append(
                f"{summary['externally_exposed']} assets are externally accessible. "
                "Implement firewall rules and reduce attack surface."
            )

        # Default credentials
        if summary["with_default_credentials"] > 0:
            recommendations.append(
                f"{summary['with_default_credentials']} systems with default credentials detected. "
                "Change all default passwords immediately."
            )

        if not recommendations:
            recommendations.append(
                "Risk profile is acceptable. Continue regular monitoring and patching."
            )

        return recommendations

    # =========================================================================
    # DATA RETRIEVAL FOR DOWNSTREAM LAYERS
    # =========================================================================

    def get_enriched_assets(self) -> List[Dict]:
        """Get risk-enriched assets for report generation"""
        return list(self.enriched_assets.values())

    def get_enriched_vulnerabilities(self) -> List[Dict]:
        """Get risk-enriched vulnerabilities for report generation"""
        return self.enriched_vulnerabilities.copy()

    def get_risk_summary(self) -> Dict:
        """Get risk summary for executive reports"""
        return self._get_risk_summary()
