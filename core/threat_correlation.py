"""
core/threat_correlation.py - Relationship Correlation Engine

Correlates entities to find:
- CVE ↔ Asset relationships
- CVE ↔ Campaign relationships
- CVE ↔ Malware relationships
- IOC ↔ Malware relationships
- Asset ↔ Asset reachability

This is the foundation for:
- Attack path analysis
- Campaign correlation
- Infrastructure mapping
- Transitive threat relationships
"""

from typing import Optional, List, Dict, Set, Tuple, Any
from datetime import datetime

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    Relationship,
    RelationshipType,
    EntityType,
    RiskContext,
)


class RelationshipCorrelationEngine:
    """
    Correlates threat intelligence entities to build relationship graphs.

    Key operations:
    - CVE-to-Asset correlation (via CPE matching)
    - IOC-to-Malware correlation (via OpenCTI)
    - Campaign-to-CVE correlation (via threat intel feeds)
    - Asset-to-Asset reachability (network topology)
    - Transitive relationship traversal
    """

    # ============================================================
    # CVE ↔ ASSET CORRELATION
    # ============================================================

    async def correlate_cve_to_assets(
        self,
        vulnerability: Vulnerability,
        assets: List[Asset],
        min_confidence: float = 0.7,
    ) -> List[Relationship]:
        """
        Correlate CVE to assets via CPE matching.

        Args:
            vulnerability: CVE to match
            assets: List of assets to match against
            min_confidence: Minimum confidence threshold (0-1)

        Returns:
            List of asset→vulnerable_to→CVE relationships
        """
        relationships = []

        # Extract CPEs from CVE
        cve_cpes = set(vulnerability.cpe_uris)
        if not cve_cpes:
            return relationships

        # Try to match with asset CPEs
        for asset in assets:
            asset_cpes = set(asset.cpe_mappings)
            if not asset_cpes:
                continue

            # Check for CPE overlap
            match_type, confidence = self._evaluate_cpe_match(
                cve_cpes, asset_cpes
            )

            if confidence >= min_confidence:
                rel = Relationship(
                    source_id=asset.id,
                    source_type=EntityType.ASSET,
                    target_id=vulnerability.id,
                    target_type=EntityType.VULNERABILITY,
                    relationship_type=RelationshipType.VULNERABLE_TO,
                    confidence=confidence,
                    evidence_sources=["cpematch"],
                    strength=self._confidence_to_strength(confidence),
                    context={
                        "match_type": match_type,
                        "cve_cpes": list(cve_cpes),
                        "asset_cpes": list(asset_cpes),
                    }
                )
                relationships.append(rel)

        return relationships

    def _evaluate_cpe_match(
        self,
        cve_cpes: Set[str],
        asset_cpes: Set[str]
    ) -> Tuple[str, float]:
        """
        Evaluate CPE match between CVE and asset.

        Returns:
            (match_type, confidence) where:
            - match_type: "exact", "vendor_match", "no_match"
            - confidence: 0.0-1.0
        """
        if not cve_cpes or not asset_cpes:
            return ("no_match", 0.0)

        # Extract vendor:product from CPE URIs
        cve_vendors = self._extract_cpe_vendors(cve_cpes)
        asset_vendors = self._extract_cpe_vendors(asset_cpes)

        # Exact match (same vendor:product)
        if cve_vendors & asset_vendors:
            return ("vendor_match", 0.95)

        # Vendor-only match (less confident)
        cve_vendor_names = {v.split(":")[0] for v in cve_vendors if ":" in v}
        asset_vendor_names = {v.split(":")[0] for v in asset_vendors if ":" in v}

        if cve_vendor_names & asset_vendor_names:
            return ("vendor_match", 0.70)

        return ("no_match", 0.0)

    @staticmethod
    def _extract_cpe_vendors(cpes: Set[str]) -> Set[str]:
        """Extract vendor:product from CPE URIs."""
        vendors = set()
        for cpe in cpes:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            parts = cpe.split(":")
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                vendors.add(f"{vendor}:{product}")
        return vendors

    # ============================================================
    # IOC ↔ MALWARE CORRELATION
    # ============================================================

    async def correlate_ioc_to_malware(
        self,
        ioc: IOC,
        malware_data: List[Dict[str, Any]],
        min_confidence: float = 0.7,
    ) -> List[Relationship]:
        """
        Correlate IOC to malware families.

        Args:
            ioc: IOC to correlate
            malware_data: List of malware with IOC indicators
            min_confidence: Minimum confidence threshold

        Returns:
            List of IOC→linked_to→Malware relationships
        """
        relationships = []

        for malware in malware_data:
            malware_id = malware.get("id")
            iocs = malware.get("iocs", [])
            confidence = malware.get("confidence", 0.8)

            # Check if IOC is in malware's IOC list
            if self._ioc_in_list(ioc.value, iocs):
                if confidence >= min_confidence:
                    rel = Relationship(
                        source_id=ioc.id,
                        source_type=EntityType.IOC,
                        target_id=malware_id,
                        target_type=EntityType.MALWARE,
                        relationship_type=RelationshipType.LINKED_TO,
                        confidence=confidence,
                        evidence_sources=["malware_intelligence"],
                        strength=self._confidence_to_strength(confidence),
                        context={"ioc_type": ioc.ioc_type.value}
                    )
                    relationships.append(rel)

        return relationships

    @staticmethod
    def _ioc_in_list(ioc_value: str, ioc_list: List[str]) -> bool:
        """Check if IOC value matches any IOC in list (case-insensitive)."""
        ioc_lower = ioc_value.lower()
        return any(i.lower() == ioc_lower for i in ioc_list)

    # ============================================================
    # CAMPAIGN ↔ CVE CORRELATION
    # ============================================================

    async def correlate_campaign_to_cves(
        self,
        campaign_id: str,
        campaign_data: Dict[str, Any],
        cves: List[Vulnerability],
    ) -> List[Relationship]:
        """
        Correlate campaign to CVEs it exploits.

        Args:
            campaign_id: Campaign identifier
            campaign_data: Campaign details (targeted_cves, etc)
            cves: List of CVEs to check

        Returns:
            List of Campaign→exploits→CVE relationships
        """
        relationships = []

        targeted_cves = campaign_data.get("targeted_cves", [])
        confidence = campaign_data.get("confidence", 0.8)

        for cve in cves:
            if cve.id in targeted_cves:
                rel = Relationship(
                    source_id=campaign_id,
                    source_type=EntityType.CAMPAIGN,
                    target_id=cve.id,
                    target_type=EntityType.VULNERABILITY,
                    relationship_type=RelationshipType.EXPLOITS,
                    confidence=confidence,
                    evidence_sources=["threat_intel"],
                    strength=self._confidence_to_strength(confidence),
                    context={"campaign_name": campaign_data.get("name")}
                )
                relationships.append(rel)

        return relationships

    # ============================================================
    # ASSET ↔ ASSET REACHABILITY
    # ============================================================

    async def correlate_asset_reachability(
        self,
        source_asset: Asset,
        target_asset: Asset,
        network_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Relationship]:
        """
        Correlate asset-to-asset reachability (network path exists).

        Args:
            source_asset: Source asset
            target_asset: Target asset
            network_data: Network topology data

        Returns:
            Relationship if reachable, None otherwise
        """
        if not network_data:
            return None

        reachability = network_data.get("reachable_assets", {})
        if target_asset.id in reachability:
            confidence = reachability[target_asset.id].get("confidence", 0.85)

            rel = Relationship(
                source_id=source_asset.id,
                source_type=EntityType.ASSET,
                target_id=target_asset.id,
                target_type=EntityType.ASSET,
                relationship_type=RelationshipType.REACHABLE_TO,
                confidence=confidence,
                evidence_sources=["network_topology"],
                strength=self._confidence_to_strength(confidence),
                context={
                    "path_type": reachability[target_asset.id].get("type"),
                    "hops": reachability[target_asset.id].get("hops", 0),
                }
            )
            return rel

        return None

    # ============================================================
    # TRANSITIVE RELATIONSHIP QUERIES
    # ============================================================

    async def find_attack_paths(
        self,
        target_cve: Vulnerability,
        relationships: List[Relationship],
        assets: List[Asset],
        max_depth: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Find attack paths from internet-exposed assets to CVE.

        Example path:
        Internet → dmz-web-01 (exposed) → internal-db (reachable) → vulnerable_to → CVE

        Args:
            target_cve: Target vulnerability
            relationships: All relationships
            assets: All assets
            max_depth: Maximum path depth

        Returns:
            List of attack paths with details
        """
        paths = []

        # Find assets vulnerable to CVE
        vulnerable_assets = self._find_entities_by_relationship(
            target_id=target_cve.id,
            relationship_type=RelationshipType.VULNERABLE_TO,
            relationships=relationships,
        )

        # For each vulnerable asset, find path from internet
        for vuln_asset_id in vulnerable_assets:
            # Is it internet-exposed?
            vuln_asset = next(
                (a for a in assets if a.id == vuln_asset_id), None
            )
            if vuln_asset and vuln_asset.internet_facing:
                # Direct path
                paths.append({
                    "type": "direct",
                    "steps": [
                        "Internet",
                        vuln_asset_id,
                        target_cve.id,
                    ],
                    "risk": "CRITICAL"
                })
            else:
                # Indirect path (reachable from exposed asset)
                exposed_assets = [a for a in assets if a.internet_facing]

                for exposed_asset in exposed_assets:
                    reachable = self._find_reachable_path(
                        source_id=exposed_asset.id,
                        target_id=vuln_asset_id,
                        relationships=relationships,
                        max_depth=max_depth,
                    )

                    if reachable:
                        full_path = ["Internet", exposed_asset.id] + reachable + [
                            target_cve.id
                        ]
                        paths.append({
                            "type": "lateral_movement",
                            "steps": full_path,
                            "risk": "HIGH"
                        })

        return paths

    async def find_campaign_affected_assets(
        self,
        campaign_id: str,
        relationships: List[Relationship],
        assets: List[Asset],
    ) -> List[Dict[str, Any]]:
        """
        Find all assets affected by campaign (via campaign→exploits→CVE→vulnerable_to→Asset).

        Args:
            campaign_id: Campaign ID
            relationships: All relationships
            assets: All assets

        Returns:
            List of affected assets with risk context
        """
        affected = []

        # Find CVEs exploited by campaign
        exploited_cves = self._find_entities_by_relationship(
            source_id=campaign_id,
            relationship_type=RelationshipType.EXPLOITS,
            relationships=relationships,
        )

        # For each CVE, find vulnerable assets
        for cve_id in exploited_cves:
            vulnerable_asset_ids = self._find_entities_by_relationship(
                target_id=cve_id,
                relationship_type=RelationshipType.VULNERABLE_TO,
                relationships=relationships,
            )

            for asset_id in vulnerable_asset_ids:
                asset = next(
                    (a for a in assets if a.id == asset_id), None
                )
                if asset:
                    affected.append({
                        "asset_id": asset_id,
                        "hostname": asset.hostname,
                        "cve_id": cve_id,
                        "internet_facing": asset.internet_facing,
                        "criticality": asset.criticality,
                        "risk_level": "CRITICAL" if asset.internet_facing else "HIGH"
                    })

        return affected

    # ============================================================
    # GRAPH TRAVERSAL HELPERS
    # ============================================================

    def _find_entities_by_relationship(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        relationship_type: Optional[RelationshipType] = None,
        relationships: Optional[List[Relationship]] = None,
    ) -> List[str]:
        """Find entities connected by specific relationship."""
        if not relationships:
            return []

        results = []
        for rel in relationships:
            match = True

            if source_id and rel.source_id != source_id:
                match = False
            if target_id and rel.target_id != target_id:
                match = False
            if relationship_type and rel.relationship_type != relationship_type:
                match = False

            if match:
                # Return the other endpoint
                if source_id:
                    results.append(rel.target_id)
                elif target_id:
                    results.append(rel.source_id)

        return list(set(results))  # Deduplicate

    def _find_reachable_path(
        self,
        source_id: str,
        target_id: str,
        relationships: List[Relationship],
        max_depth: int = 3,
        visited: Optional[Set[str]] = None,
    ) -> Optional[List[str]]:
        """
        BFS to find path from source to target via REACHABLE_TO relationships.

        Returns:
            List of intermediate asset IDs, or None if not reachable
        """
        if visited is None:
            visited = set()

        if source_id == target_id:
            return []

        if source_id in visited or max_depth <= 0:
            return None

        visited.add(source_id)

        # Find assets reachable from source
        reachable = self._find_entities_by_relationship(
            source_id=source_id,
            relationship_type=RelationshipType.REACHABLE_TO,
            relationships=relationships,
        )

        for asset_id in reachable:
            if asset_id == target_id:
                return [asset_id]

            path = self._find_reachable_path(
                source_id=asset_id,
                target_id=target_id,
                relationships=relationships,
                max_depth=max_depth - 1,
                visited=visited.copy(),
            )

            if path:
                return [asset_id] + path

        return None

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    @staticmethod
    def _confidence_to_strength(confidence: float) -> str:
        """Convert confidence score to strength level."""
        if confidence >= 0.9:
            return "strong"
        elif confidence >= 0.7:
            return "medium"
        else:
            return "weak"

    # ============================================================
    # BULK CORRELATION
    # ============================================================

    async def correlate_all(
        self,
        vulnerabilities: List[Vulnerability],
        iocs: List[IOC],
        assets: List[Asset],
        malware_data: Optional[List[Dict[str, Any]]] = None,
        campaign_data: Optional[List[Dict[str, Any]]] = None,
        network_data: Optional[Dict[str, Any]] = None,
    ) -> List[Relationship]:
        """
        Perform all correlations in one pass.

        Args:
            vulnerabilities: List of CVEs
            iocs: List of IOCs
            assets: List of assets
            malware_data: List of malware intelligence
            campaign_data: List of campaigns
            network_data: Network topology

        Returns:
            List of all discovered relationships
        """
        all_relationships = []

        # CVE <-> Asset correlation
        print("  [CORRELATION] CVE <-> Asset...")
        for vuln in vulnerabilities:
            rels = await self.correlate_cve_to_assets(vuln, assets)
            all_relationships.extend(rels)
            if rels:
                print(f"    Found {len(rels)} asset vulnerabilities for {vuln.id}")

        # IOC <-> Malware correlation
        if malware_data:
            print("  [CORRELATION] IOC <-> Malware...")
            for ioc in iocs:
                rels = await self.correlate_ioc_to_malware(
                    ioc, malware_data
                )
                all_relationships.extend(rels)
                if rels:
                    print(f"    Linked {ioc.id} to {len(rels)} malware families")

        # Campaign <-> CVE correlation
        if campaign_data:
            print("  [CORRELATION] Campaign <-> CVE...")
            for campaign in campaign_data:
                campaign_id = campaign.get("id")
                rels = await self.correlate_campaign_to_cves(
                    campaign_id, campaign, vulnerabilities
                )
                all_relationships.extend(rels)
                if rels:
                    print(f"    Campaign {campaign_id} exploits {len(rels)} CVEs")

        # Asset <-> Asset reachability
        if network_data:
            print("  [CORRELATION] Asset <-> Asset...")
            for source_asset in assets:
                for target_asset in assets:
                    if source_asset.id != target_asset.id:
                        rel = await self.correlate_asset_reachability(
                            source_asset, target_asset, network_data
                        )
                        if rel:
                            all_relationships.append(rel)

        print(f"\n  [CORRELATION] Total relationships discovered: {len(all_relationships)}")
        return all_relationships
