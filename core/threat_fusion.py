"""
core/threat_fusion.py - Threat Fusion Engine

Merges multi-source intelligence into single unified threat intelligence object.

Current flow (WRONG):
tool result → summarize → output

New flow (RIGHT):
normalize → correlate → fuse → contextualize → score → persist

Fusion sources:
- NVD (CVSS, CWE, CPE, description)
- EPSS (exploitation probability)
- KEV (exploited in wild)
- Vulners (exploit intelligence, fallback enrichment)
- OpenCTI (IOC, malware, campaigns)
- Internal telemetry (asset, exposure, criticality)
"""

from typing import Optional, Dict, Any, List
from datetime import datetime

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    RiskContext,
    ThreatIntelligenceObject,
    SeverityLevel,
    EntityType,
    Relationship,
    RelationshipType,
)
from core.threat_adapters import (
    NVDAdapter,
    EPSSAdapter,
    KEVAdapter,
    VulnersAdapter,
    OpenCTIAdapter,
)


class ThreatFusionEngine:
    """
    Multi-source threat intelligence fusion.

    Transforms:
    - Separate tool outputs
    Into:
    - Single unified threat intelligence object
    - Ready for contextual scoring and graph reasoning
    """

    def __init__(self):
        """Initialize adapters."""
        self.nvd_adapter = NVDAdapter()
        self.epss_adapter = EPSSAdapter()
        self.kev_adapter = KEVAdapter()
        self.vulners_adapter = VulnersAdapter()
        self.opencti_adapter = OpenCTIAdapter()

    # ============================================================
    # CVE FUSION (Primary use case)
    # ============================================================

    async def fuse_cve(
        self,
        nvd_data: Dict[str, Any],
        epss_data: Optional[Dict[str, Any]] = None,
        kev_data: Optional[Dict[str, Any]] = None,
        vulners_data: Optional[Dict[str, Any]] = None,
        internal_context: Optional[Dict[str, Any]] = None,
    ) -> ThreatIntelligenceObject:
        """
        Fuse CVE data from multiple sources into single intelligence object.

        Args:
            nvd_data: NVD API response (base source)
            epss_data: EPSS API response
            kev_data: CISA KEV response
            vulners_data: Vulners API response
            internal_context: Internal asset/exposure data

        Returns:
            ThreatIntelligenceObject with fused risk context
        """
        # Step 1: Normalize NVD (base source)
        vulnerability = self.nvd_adapter.normalize_vulnerability(nvd_data)
        if not vulnerability:
            raise ValueError(f"Cannot normalize NVD data: {nvd_data}")

        # Step 2: Merge EPSS enrichment
        if epss_data:
            vulnerability = self.epss_adapter.merge_epss_enrichment(
                vulnerability, epss_data
            )

        # Step 3: Merge KEV enrichment
        if kev_data:
            vulnerability = self.kev_adapter.merge_kev_enrichment(
                vulnerability, kev_data
            )

        # Step 4: Merge Vulners enrichment (exploit intelligence + fallback)
        if vulners_data:
            vulnerability = self.vulners_adapter.merge_vulners_enrichment(
                vulnerability, vulners_data
            )

        # Step 5: Add internal context (asset exposure, criticality)
        if internal_context:
            vulnerability = self._merge_internal_context(
                vulnerability, internal_context
            )

        # Step 6: Create relationships from fusion data
        relationships = self._build_cve_relationships(
            vulnerability, epss_data, kev_data, vulners_data, internal_context
        )

        # Step 7: Calculate contextual threat score
        threat_score = self._calculate_threat_score(vulnerability)

        # Step 8: Determine persistence decision
        should_persist, persistence_reason = self._evaluate_persistence(
            vulnerability, threat_score
        )

        # Step 9: Build fused intelligence object
        fused_object = ThreatIntelligenceObject(
            entity_id=vulnerability.id,
            entity_type=EntityType.VULNERABILITY,
            entity=vulnerability,
            fused_risk=vulnerability.risk_context,
            relationships=relationships,
            threat_score=threat_score,
            threat_level=self._score_to_severity(threat_score),
            threat_reasoning=self._build_threat_reasoning(
                vulnerability, threat_score, internal_context
            ),
            fusion_sources=vulnerability.risk_context.data_sources,
            should_persist=should_persist,
            persistence_reason=persistence_reason,
        )

        return fused_object

    # ============================================================
    # IOC FUSION
    # ============================================================

    async def fuse_ioc(
        self,
        ioc_data: Dict[str, Any],
        opencti_data: Optional[Dict[str, Any]] = None,
        internal_context: Optional[Dict[str, Any]] = None,
    ) -> ThreatIntelligenceObject:
        """
        Fuse IOC from multiple sources.

        Args:
            ioc_data: OpenCTI indicator/observable
            opencti_data: Additional OpenCTI enrichment (malware, campaign)
            internal_context: Internal detection/exposure data

        Returns:
            ThreatIntelligenceObject with IOC
        """
        # Normalize IOC
        ioc = self.opencti_adapter.normalize_ioc(ioc_data)
        if not ioc:
            raise ValueError(f"Cannot normalize IOC data: {ioc_data}")

        # Build relationships
        relationships = []
        if opencti_data:
            relationships = self._build_ioc_relationships(ioc, opencti_data)

        # Score IOC
        threat_score = self._calculate_ioc_threat_score(ioc, opencti_data)

        # Persistence decision
        should_persist, persistence_reason = self._evaluate_ioc_persistence(ioc)

        fused_object = ThreatIntelligenceObject(
            entity_id=ioc.id,
            entity_type=EntityType.IOC,
            entity=ioc,
            fused_risk=ioc.risk_context,
            relationships=relationships,
            threat_score=threat_score,
            threat_level=self._score_to_severity(threat_score),
            threat_reasoning=self._build_ioc_reasoning(ioc, opencti_data),
            fusion_sources=["opencti"],
            should_persist=should_persist,
            persistence_reason=persistence_reason,
        )

        return fused_object

    # ============================================================
    # ASSET FUSION
    # ============================================================

    async def fuse_asset(
        self,
        asset_data: Dict[str, Any],
        vulnerable_cves: Optional[List[Vulnerability]] = None,
        detected_iocs: Optional[List[IOC]] = None,
    ) -> ThreatIntelligenceObject:
        """
        Fuse asset with vulnerability and IOC context.

        Args:
            asset_data: Internal asset/CMDB data
            vulnerable_cves: List of CVEs affecting asset
            detected_iocs: List of IOCs detected on asset

        Returns:
            ThreatIntelligenceObject with Asset
        """
        from core.threat_adapters import InternalTelemetryAdapter

        adapter = InternalTelemetryAdapter()
        asset = adapter.normalize_asset(asset_data)
        if not asset:
            raise ValueError(f"Cannot normalize asset data: {asset_data}")

        # Build relationships
        relationships = []

        if vulnerable_cves:
            for cve in vulnerable_cves:
                rel = Relationship(
                    source_id=asset.id,
                    source_type=EntityType.ASSET,
                    target_id=cve.id,
                    target_type=EntityType.VULNERABILITY,
                    relationship_type=RelationshipType.VULNERABLE_TO,
                    confidence=0.95,  # High confidence from CPE/scanner match
                    evidence_sources=["cpematch", "vulnerability_scan"],
                )
                relationships.append(rel)

        if detected_iocs:
            for ioc in detected_iocs:
                rel = Relationship(
                    source_id=asset.id,
                    source_type=EntityType.ASSET,
                    target_id=ioc.id,
                    target_type=EntityType.IOC,
                    relationship_type=RelationshipType.DETECTED_ON,
                    confidence=0.99,  # High confidence from detection
                    evidence_sources=["internal_detection"],
                )
                relationships.append(rel)

        # Score asset
        threat_score = self._calculate_asset_threat_score(
            asset, vulnerable_cves, detected_iocs
        )

        should_persist, persistence_reason = self._evaluate_asset_persistence(
            asset, threat_score
        )

        fused_object = ThreatIntelligenceObject(
            entity_id=asset.id,
            entity_type=EntityType.ASSET,
            entity=asset,
            fused_risk=asset.risk_context,
            relationships=relationships,
            threat_score=threat_score,
            threat_level=self._score_to_severity(threat_score),
            threat_reasoning=self._build_asset_reasoning(
                asset, vulnerable_cves, detected_iocs
            ),
            fusion_sources=["internal"],
            should_persist=should_persist,
            persistence_reason=persistence_reason,
        )

        return fused_object

    # ============================================================
    # PRIVATE HELPER METHODS
    # ============================================================

    def _merge_internal_context(
        self,
        vulnerability: Vulnerability,
        internal_context: Dict[str, Any]
    ) -> Vulnerability:
        """Add internal asset exposure context to CVE."""
        if vulnerability.risk_context is None:
            vulnerability.risk_context = RiskContext()

        vulnerability.risk_context.internet_exposed = internal_context.get(
            "internet_exposed", False
        )
        vulnerability.risk_context.asset_criticality = internal_context.get(
            "asset_criticality"
        )
        vulnerability.risk_context.attack_path_exists = internal_context.get(
            "attack_path_exists", False
        )
        vulnerability.risk_context.lateral_movement_potential = (
            internal_context.get("lateral_movement_potential", False)
        )

        # Mark as having internal context
        if "internal" not in vulnerability.risk_context.data_sources:
            vulnerability.risk_context.data_sources.append("internal")

        return vulnerability

    def _build_cve_relationships(
        self,
        vulnerability: Vulnerability,
        epss_data: Optional[Dict[str, Any]],
        kev_data: Optional[Dict[str, Any]],
        vulners_data: Optional[Dict[str, Any]],
        internal_context: Optional[Dict[str, Any]],
    ) -> List[Relationship]:
        """Build relationships from fusion sources."""
        relationships = []

        # If internal context provided, create asset→vulnerable_to→CVE relationships
        if internal_context:
            affected_assets = internal_context.get("affected_assets", [])
            for asset_id in affected_assets:
                rel = Relationship(
                    source_id=asset_id,
                    source_type=EntityType.ASSET,
                    target_id=vulnerability.id,
                    target_type=EntityType.VULNERABILITY,
                    relationship_type=RelationshipType.VULNERABLE_TO,
                    confidence=internal_context.get("match_confidence", 0.85),
                    evidence_sources=internal_context.get(
                        "evidence_sources", ["cpematch"]
                    ),
                )
                relationships.append(rel)

        return relationships

    def _build_ioc_relationships(
        self,
        ioc: IOC,
        opencti_data: Dict[str, Any]
    ) -> List[Relationship]:
        """Build relationships for IOC (linked to malware, campaigns)."""
        relationships = []

        # IOC → Malware
        linked_malware = opencti_data.get("linked_malware", [])
        for malware_id in linked_malware:
            rel = Relationship(
                source_id=ioc.id,
                source_type=EntityType.IOC,
                target_id=malware_id,
                target_type=EntityType.MALWARE,
                relationship_type=RelationshipType.LINKED_TO,
                confidence=0.85,
                evidence_sources=["opencti"],
            )
            relationships.append(rel)

        # IOC → Campaign
        linked_campaigns = opencti_data.get("linked_campaigns", [])
        for campaign_id in linked_campaigns:
            rel = Relationship(
                source_id=ioc.id,
                source_type=EntityType.IOC,
                target_id=campaign_id,
                target_type=EntityType.CAMPAIGN,
                relationship_type=RelationshipType.OBSERVED_IN,
                confidence=0.90,
                evidence_sources=["opencti"],
            )
            relationships.append(rel)

        return relationships

    def _calculate_threat_score(self, vulnerability: Vulnerability) -> float:
        """
        Calculate contextual threat score (0-100) for CVE.

        Factors (with weights):
        - CVSS: 20% (base severity)
        - EPSS: 25% (exploitation probability)
        - KEV: 20% (actively exploited)
        - Public Exploit: 15% (ease of exploitation)
        - Internet Exposed: 10% (accessibility)
        - Attack Path Exists: 10% (reachability)
        """
        risk = vulnerability.risk_context
        if not risk:
            return 50.0  # Default if no risk context

        score = 0.0

        # CVSS (0-10 → 0-20 points)
        if risk.cvss_score:
            score += (risk.cvss_score / 10.0) * 20

        # EPSS (0-1 → 0-25 points)
        if risk.epss_score is not None:
            score += risk.epss_score * 25

        # KEV (boolean → 0 or 20 points)
        if risk.kev_listed:
            score += 20

        # Public Exploit (boolean → 0 or 15 points)
        if risk.public_exploit_available or risk.exploit_count > 0:
            score += 15

        # Internet Exposed (boolean → 0 or 10 points)
        if risk.internet_exposed:
            score += 10

        # Attack Path Exists (boolean → 0 or 10 points)
        if risk.attack_path_exists:
            score += 10

        return min(100.0, score)

    def _calculate_ioc_threat_score(
        self,
        ioc: IOC,
        opencti_data: Optional[Dict[str, Any]] = None
    ) -> float:
        """Calculate threat score for IOC."""
        score = 0.0

        # Observation count (repeated observations = higher score)
        observation_count = ioc.observation_count
        if observation_count > 5:
            score += 30
        elif observation_count > 2:
            score += 20
        else:
            score += 10

        # Linked to ransomware campaign
        if opencti_data:
            if opencti_data.get("ransomware_campaign"):
                score += 40

            # Linked to active campaign
            if opencti_data.get("active_campaign"):
                score += 30

        return min(100.0, score)

    def _calculate_asset_threat_score(
        self,
        asset: Asset,
        vulnerable_cves: Optional[List[Vulnerability]] = None,
        detected_iocs: Optional[List[IOC]] = None,
    ) -> float:
        """Calculate threat score for asset."""
        score = 0.0

        # Internet facing (high risk)
        if asset.internet_facing:
            score += 30

        # Criticality
        criticality = (asset.criticality or "low").lower()
        if criticality == "critical":
            score += 30
        elif criticality == "high":
            score += 20
        elif criticality == "medium":
            score += 10

        # Vulnerable CVEs
        if vulnerable_cves:
            high_risk_cves = sum(1 for cve in vulnerable_cves if cve.severity in
                               [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
            score += min(30, high_risk_cves * 5)

        # Detected IOCs
        if detected_iocs:
            score += min(20, len(detected_iocs) * 5)

        return min(100.0, score)

    def _evaluate_persistence(
        self,
        vulnerability: Vulnerability,
        threat_score: float
    ) -> tuple[bool, str]:
        """
        Decide if CVE should be persisted (selective persistence).

        Persist if:
        - KEV listed
        - High EPSS (>= 0.8)
        - Threat score >= 75
        - Known exploit available
        """
        risk = vulnerability.risk_context
        if not risk:
            return False, "No risk context"

        # KEV is always persisted
        if risk.kev_listed:
            return True, "KEV listed"

        # High EPSS
        if risk.epss_score and risk.epss_score >= 0.8:
            return True, "High EPSS (>= 0.8)"

        # High threat score
        if threat_score >= 75:
            return True, f"High threat score ({threat_score:.1f})"

        # Public exploit available
        if risk.public_exploit_available or risk.exploit_count > 0:
            return True, "Public exploit available"

        return False, f"Low priority (score: {threat_score:.1f})"

    def _evaluate_ioc_persistence(self, ioc: IOC) -> tuple[bool, str]:
        """Decide if IOC should be persisted."""
        # Persist if:
        # - Recurring (observation_count > 2)
        # - High severity
        # - Part of campaign

        if ioc.observation_count > 2:
            return True, f"Recurring IOC ({ioc.observation_count} observations)"

        if ioc.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            return True, f"High severity ({ioc.severity})"

        return False, "Low priority IOC"

    def _evaluate_asset_persistence(
        self,
        asset: Asset,
        threat_score: float
    ) -> tuple[bool, str]:
        """Decide if asset should be persisted."""
        # Always persist critical assets or those with high exposure
        if asset.internet_facing or asset.criticality == "critical":
            return True, f"Internet-facing or critical (score: {threat_score:.1f})"

        if threat_score >= 70:
            return True, f"High threat score ({threat_score:.1f})"

        return False, f"Low priority (score: {threat_score:.1f})"

    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convert threat score to severity level."""
        if score >= 80:
            return SeverityLevel.CRITICAL
        elif score >= 60:
            return SeverityLevel.HIGH
        elif score >= 40:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _build_threat_reasoning(
        self,
        vulnerability: Vulnerability,
        threat_score: float,
        internal_context: Optional[Dict[str, Any]],
    ) -> str:
        """Build human-readable threat reasoning."""
        risk = vulnerability.risk_context
        if not risk:
            return "Unknown threat"

        factors = []

        if risk.kev_listed:
            factors.append("[KEV] Exploited in wild")

        if risk.public_exploit_available:
            factors.append("[EXPLOIT] Public exploit available")

        if risk.epss_score and risk.epss_score >= 0.8:
            factors.append(f"[EPSS] High exploitation probability ({risk.epss_score:.2f})")

        if risk.internet_exposed:
            factors.append("[EXPOSURE] Internet-facing asset vulnerable")

        if risk.attack_path_exists:
            factors.append("[PATH] Attack path exists")

        if risk.linked_campaigns:
            factors.append(f"[CAMPAIGN] Linked to: {', '.join(risk.linked_campaigns)}")

        if risk.ransomware_linked:
            factors.append("[ALERT] Ransomware-linked")

        reasoning = f"CVE {vulnerability.id} - Score: {threat_score:.0f}/100\n"
        reasoning += "\n".join(factors)

        return reasoning

    def _build_ioc_reasoning(
        self,
        ioc: IOC,
        opencti_data: Optional[Dict[str, Any]]
    ) -> str:
        """Build human-readable IOC threat reasoning."""
        factors = []

        if ioc.observation_count > 2:
            factors.append(f"[RECURRING] IOC ({ioc.observation_count} observations)")

        if opencti_data:
            if opencti_data.get("linked_malware"):
                factors.append(
                    f"[MALWARE] Linked to: {', '.join(opencti_data['linked_malware'])}"
                )

            if opencti_data.get("linked_campaigns"):
                factors.append(
                    f"[CAMPAIGN] Observed in: {', '.join(opencti_data['linked_campaigns'])}"
                )

            if opencti_data.get("ransomware_campaign"):
                factors.append("[ALERT] Part of ransomware campaign")

        reasoning = f"IOC: {ioc.value}\n"
        reasoning += "\n".join(factors)

        return reasoning

    def _build_asset_reasoning(
        self,
        asset: Asset,
        vulnerable_cves: Optional[List[Vulnerability]] = None,
        detected_iocs: Optional[List[IOC]] = None,
    ) -> str:
        """Build human-readable asset threat reasoning."""
        factors = []

        if asset.internet_facing:
            factors.append("[EXPOSURE] Internet-facing")

        if asset.criticality:
            factors.append(f"[CRITICALITY] {asset.criticality.upper()}")

        if vulnerable_cves:
            critical_count = sum(1 for cve in vulnerable_cves if cve.severity == SeverityLevel.CRITICAL)
            high_count = sum(1 for cve in vulnerable_cves if cve.severity == SeverityLevel.HIGH)

            if critical_count > 0:
                factors.append(f"[ALERT] {critical_count} CRITICAL CVE(s)")
            if high_count > 0:
                factors.append(f"[ALERT] {high_count} HIGH CVE(s)")

        if detected_iocs:
            factors.append(f"[DETECTION] {len(detected_iocs)} IOC(s) detected")

        reasoning = f"Asset: {asset.hostname} ({asset.ip_address or 'N/A'})\n"
        reasoning += "\n".join(factors)

        return reasoning
