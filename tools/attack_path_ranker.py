"""
tools/attack_path_ranker.py - Rank attack paths (CWE→CAPEC→ATT&CK) by relevance

Implements G8 + G10:
  G10: CVE priority score (Layer 1) - decide if enrichment worthwhile
  G8: Attack path relevance score (Layer 2) - rank individual paths

Formula (BƯỚC 4):
  Layer 1: cve_priority_score = 0.35×CVSS + 0.30×KEV + 0.25×EPSS + 0.10×relevance
  Layer 2: path_relevance_score = 0.40×capec_strength + 0.30×directness + 0.20×tactic + 0.10×abstraction

Thresholds:
  Tier >= 0.7: CRITICAL → full enrichment
  Tier 0.4-0.69: STANDARD → standard enrichment
  Tier < 0.4: LOW → skip (save cost)

Hard Filters (before scoring):
  1. Remove deprecated CAPEC patterns
  2. Remove Meta-only patterns (if alternatives exist)
  3. Remove domain mismatches (Mobile/ICS on Enterprise system, etc)
"""

import logging
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class AttackPathRanker:
    """
    Rank attack paths and filter noise.
    Implements 2-layer scoring system from BƯỚC 4.
    """

    # ── LAYER 1: CVE PRIORITY SCORE ──

    @staticmethod
    def calculate_cve_priority_score(
        cvss_score: Optional[float] = None,
        kev_listed: bool = False,
        epss_score: Optional[float] = None,
        asset_relevance: float = 0.8
    ) -> Tuple[float, str]:
        """
        Layer 1: CVE priority score (0-1)

        Formula:
          score = 0.35×norm_cvss + 0.30×kev_flag + 0.25×epss + 0.10×relevance

        Args:
            cvss_score: 0-10 (None → 0)
            kev_listed: CISA KEV catalog listed
            epss_score: 0-1 (None → 0)
            asset_relevance: 0-1, CPE match percentage (default 0.8 if unknown)

        Returns:
            (score: 0-1, tier: "CRITICAL" | "STANDARD" | "LOW")

        Tier mapping:
          >= 0.7: CRITICAL (full enrichment)
          0.4-0.69: STANDARD (standard enrichment)
          < 0.4: LOW (skip - save cost)
        """
        # Extract signals
        cvss = cvss_score if cvss_score else 0.0
        norm_cvss = min(cvss / 10.0, 1.0)  # Normalize to 0-1

        kev_flag = 1.0 if kev_listed else 0.0

        epss = epss_score if epss_score else 0.0  # Already 0-1

        # Asset relevance: default 0.8 (assume somewhat relevant)
        relevance = asset_relevance

        # Calculate score
        score = (
            0.35 * norm_cvss +
            0.30 * kev_flag +
            0.25 * epss +
            0.10 * relevance
        )

        # Map to tier
        if score >= 0.70:
            tier = "CRITICAL"
        elif score >= 0.40:
            tier = "STANDARD"
        else:
            tier = "LOW"

        return (round(score, 3), tier)

    # ── LAYER 2: ATTACK PATH RELEVANCE SCORE ──

    @staticmethod
    def calculate_path_relevance_score(
        capec_likelihood: str = "Unknown",  # "High" | "Medium" | "Low" | "Unknown"
        is_direct_mapping: bool = True,  # Direct CAPEC→T or via sub-technique
        tactic: str = "Unknown",
        cvss_vector: Optional[str] = None,  # For tactic relevance heuristic
        capec_abstraction: str = "Standard"  # "Meta" | "Category" | "Standard" | "Detailed"
    ) -> float:
        """
        Layer 2: Attack path relevance score (0-1)

        Formula:
          score = 0.40×capec_strength + 0.30×directness + 0.20×tactic_relevance + 0.10×abstraction_penalty

        Args:
            capec_likelihood: CAPEC Likelihood_Of_Attack
            is_direct_mapping: Direct CAPEC→technique (True) or via subtechnique (False)
            tactic: ATT&CK tactic (e.g., "Initial Access", "Execution")
            cvss_vector: CVSS vector for tactic relevance heuristic
            capec_abstraction: CAPEC abstraction level

        Returns:
            score: 0-1
        """

        # CAPEC strength: High=1.0, Medium=0.6, Low=0.3, Unknown=0.5
        capec_strength_map = {
            "High": 1.0,
            "Medium": 0.6,
            "Low": 0.3,
            "Unknown": 0.5
        }
        capec_strength = capec_strength_map.get(capec_likelihood, 0.5)

        # Directness: Direct=1.0, Sub-technique=0.6
        directness = 1.0 if is_direct_mapping else 0.6

        # Tactic relevance: Heuristic based on CVE vector
        tactic_relevance = AttackPathRanker._compute_tactic_relevance(tactic, cvss_vector)

        # Abstraction penalty: Meta=0.2, Category=0.4, Standard=0.8, Detailed=1.0
        abstraction_map = {
            "Meta": 0.2,
            "Category": 0.4,
            "Standard": 0.8,
            "Detailed": 1.0
        }
        abstraction_penalty = abstraction_map.get(capec_abstraction, 0.5)

        # Calculate score
        score = (
            0.40 * capec_strength +
            0.30 * directness +
            0.20 * tactic_relevance +
            0.10 * abstraction_penalty
        )

        return round(score, 3)

    @staticmethod
    def _compute_tactic_relevance(tactic: str, cvss_vector: Optional[str] = None) -> float:
        """
        Compute tactic relevance based on CVE characteristics.

        Heuristic:
          RCE (AV:N) → prefer Initial Access, Execution: 1.0
          Privilege Escalation vector → prefer Privilege Escalation: 1.0
          Information Disclosure → prefer Reconnaissance: 0.7
          Others → 0.5

        Args:
            tactic: ATT&CK tactic name
            cvss_vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

        Returns:
            relevance: 0-1
        """
        if not cvss_vector:
            # Default: assume moderate relevance
            if tactic in ["Initial Access", "Execution", "Lateral Movement"]:
                return 1.0
            elif tactic in ["Persistence", "Privilege Escalation"]:
                return 0.7
            elif tactic in ["Defense Evasion"]:
                return 0.4
            else:
                return 0.5

        # Parse CVSS vector for hints
        is_network_accessible = "AV:N" in cvss_vector
        is_local_only = "AV:L" in cvss_vector

        # RCE / Network-accessible
        if is_network_accessible:
            if tactic in ["Initial Access", "Execution", "Lateral Movement"]:
                return 1.0
            elif tactic in ["Persistence", "Privilege Escalation"]:
                return 0.7
            elif tactic in ["Defense Evasion"]:
                return 0.4
            else:
                return 0.5

        # Local-only
        if is_local_only:
            if tactic in ["Privilege Escalation", "Execution"]:
                return 1.0
            elif tactic in ["Persistence", "Defense Evasion"]:
                return 0.7
            else:
                return 0.5

        return 0.5

    # ── HARD FILTERING ──

    @staticmethod
    def should_filter_path(
        capec_id: str,
        capec_status: Optional[str] = None,  # "Deprecated", "Obsolete", "Draft", "Stable"
        capec_abstraction: str = "Standard",
        has_non_meta_alternative: bool = False,
        system_domain: str = "Enterprise"  # "Enterprise", "Mobile", "ICS"
    ) -> Tuple[bool, Optional[str]]:
        """
        Hard filtering rules (before scoring).
        Applied to REMOVE low-quality paths.

        Rules:
        1. Deprecated/Obsolete CAPEC → FILTER
        2. Meta pattern (if alternatives exist) → FILTER
        3. Domain mismatch (Mobile on Enterprise, ICS on Web) → FILTER

        Args:
            capec_id: CAPEC pattern ID
            capec_status: Status from CAPEC XML
            capec_abstraction: Abstraction level
            has_non_meta_alternative: Are there non-Meta alternatives?
            system_domain: Target system domain

        Returns:
            (should_filter: bool, reason: str | None)
        """

        # Rule 1: Deprecation check
        if capec_status and capec_status.lower() in ["deprecated", "obsolete"]:
            return (True, f"deprecated_capec: CAPEC-{capec_id} status={capec_status}")

        # Rule 2: Meta pattern exclusion
        if capec_abstraction == "Meta" and has_non_meta_alternative:
            return (True, f"meta_pattern: CAPEC-{capec_id} (alternatives available)")

        # Rule 3: Domain mismatch (simplified - can be enhanced)
        # NOTE: Domain info would come from technique data, not CAPEC
        # This is placeholder for infrastructure to pass domain hints
        # if system_domain == "Enterprise" and technique_domain == "Mobile":
        #     return (True, f"domain_mismatch: Mobile technique on Enterprise system")

        return (False, None)

    # ── RANKING ──

    @staticmethod
    def rank_attack_paths(
        attack_techniques: List[Dict],
        capec_data: Dict[str, Dict],  # {capec_id: {name, likelihood, abstraction, status}}
        max_paths: int = 5,
        cvss_vector: Optional[str] = None
    ) -> Tuple[List[Dict], int]:
        """
        Rank attack paths by relevance.

        Steps:
        1. Hard filter: Remove deprecated, meta, domain mismatches
        2. Score each path: Layer 2 formula
        3. Sort by score descending
        4. Return top-K paths

        Args:
            attack_techniques: [
                {
                    "t_number": "T1083",
                    "name": "File and Directory Discovery",
                    "tactics": ["Reconnaissance"],
                    "capec_id": "3",
                    "capec_name": "Footprinting"
                }
            ]
            capec_data: {
                "3": {
                    "name": "Footprinting",
                    "likelihood": "High",
                    "abstraction": "Standard",
                    "status": "Stable"
                }
            }
            max_paths: Keep top-K paths
            cvss_vector: For tactic relevance heuristic

        Returns:
            (ranked_paths: List[Dict], filtered_count: int)
        """

        if not attack_techniques:
            return ([], 0)

        # Step 1: Hard filtering
        filtered_paths = []
        filtered_count = 0

        for tech in attack_techniques:
            capec_id = tech.get("capec_id", "Unknown")
            capec_info = capec_data.get(capec_id, {})

            should_filter, reason = AttackPathRanker.should_filter_path(
                capec_id,
                capec_status=capec_info.get("status"),
                capec_abstraction=capec_info.get("abstraction", "Standard"),
                has_non_meta_alternative=len([t for t in attack_techniques if t.get("capec_id") != capec_id]) > 0
            )

            if should_filter:
                filtered_count += 1
                logger.debug(f"Filtered: {reason}")
                continue

            filtered_paths.append(tech)

        # Step 2: Score each path
        scored = []
        for tech in filtered_paths:
            capec_id = tech.get("capec_id", "Unknown")
            capec_info = capec_data.get(capec_id, {})

            score = AttackPathRanker.calculate_path_relevance_score(
                capec_likelihood=capec_info.get("likelihood", "Unknown"),
                is_direct_mapping=True,  # Assume direct (can be enhanced)
                tactic=tech.get("tactics", ["Unknown"])[0] if tech.get("tactics") else "Unknown",
                cvss_vector=cvss_vector,
                capec_abstraction=capec_info.get("abstraction", "Standard")
            )

            scored.append({
                "technique": tech,
                "score": score
            })

        # Step 3: Sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)

        # Step 4: Top-K with metadata
        results = []
        for rank, item in enumerate(scored[:max_paths], 1):
            tech = item["technique"]
            capec_id = tech.get("capec_id", "Unknown")
            capec_info = capec_data.get(capec_id, {})

            results.append({
                "rank": rank,
                "relevance_score": item["score"],
                "cwe": tech.get("cwe", "Unknown"),
                "capec": {
                    "id": capec_id,
                    "name": capec_info.get("name", f"CAPEC-{capec_id}"),
                    "likelihood": capec_info.get("likelihood", "Unknown"),
                    "abstraction": capec_info.get("abstraction", "Unknown")
                },
                "attack_technique": {
                    "t_number": tech.get("t_number"),
                    "name": tech.get("name"),
                    "tactics": tech.get("tactics", []),
                    "description": tech.get("description", "")
                },
                "reasoning": f"{tech.get('tactics', ['Unknown'])[0]} technique via {capec_info.get('abstraction', 'Unknown')} CAPEC-{capec_id}"
            })

        return (results, filtered_count)
