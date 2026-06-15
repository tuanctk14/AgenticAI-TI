"""
tools/control_aggregator.py - Deduplicate + weight NIST controls

Implements G9: Control deduplication & aggregation

Problem: Multiple attack paths map to same controls (SI-10, SC-7, AC-3 appear often)
Solution: Weight controls by coverage + dedup

Formula:
  control_weight = count(techniques mapping to control) × avg(relevance_score of those techniques)

Example:
  - SI-10: covered by T1190 (score 0.88) + T1203 (score 0.81)
    → count=2, avg_relevance=0.845, weight=1.69

Process:
  1. Collect controls from all attack paths
  2. For each control: count techniques + avg their relevance scores
  3. Weight = count × avg_relevance
  4. Sort by weight descending
  5. Return top-K controls (default K=12)
"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class ControlAggregator:
    """
    Aggregate + deduplicate NIST controls from attack paths.
    """

    @staticmethod
    def aggregate_controls(
        ranked_paths: List[Dict],
        nist_controls_per_technique: Dict[str, List[Dict]] = None,
        top_k: int = 12
    ) -> List[Dict]:
        """
        Deduplicate + weight NIST controls across attack paths.

        Args:
            ranked_paths: Output from AttackPathRanker.rank_attack_paths()
                [
                    {
                        "rank": 1,
                        "relevance_score": 0.88,
                        "attack_technique": {
                            "t_number": "T1190",
                            "name": "Exploit Public-Facing Application",
                            "tactics": ["Initial Access"]
                        }
                    }
                ]
            nist_controls_per_technique: {
                "T1190": [
                    {"control": "SI-10", "name": "Information Input Validation"},
                    {"control": "SC-7", "name": "Boundary Protection"}
                ],
                "T1083": [...]
            }
            top_k: Keep top-K controls (default 12)

        Returns: [
            {
                "rank": 1,
                "control": "SI-10",
                "name": "Information Input Validation",
                "weight": 1.69,
                "technique_count": 2,
                "techniques": ["T1190", "T1203"],
                "reason": "covers 2 attack technique(s): T1190, T1203"
            }
        ]
        """

        if not ranked_paths or not nist_controls_per_technique:
            return []

        # Collect controls from all paths
        control_stats = {}  # control_id → {weights: [], names: set, techniques: set}

        for path in ranked_paths:
            relevance = path.get("relevance_score", 0.5)
            technique = path.get("attack_technique", {})
            t_number = technique.get("t_number", "")

            if not t_number:
                continue

            # Get controls for this technique
            controls = nist_controls_per_technique.get(t_number, [])

            for ctrl in controls:
                ctrl_id = ctrl.get("control", "")

                if not ctrl_id:
                    continue

                if ctrl_id not in control_stats:
                    control_stats[ctrl_id] = {
                        "weights": [],
                        "name": ctrl.get("name", ctrl_id),
                        "techniques": set()
                    }

                control_stats[ctrl_id]["weights"].append(relevance)
                control_stats[ctrl_id]["techniques"].add(t_number)

        # Calculate aggregated weights
        results = []
        for ctrl_id, stats in control_stats.items():
            count = len(stats["weights"])
            avg_relevance = sum(stats["weights"]) / count if stats["weights"] else 0.0
            weight = count * avg_relevance

            results.append({
                "control": ctrl_id,
                "name": stats["name"],
                "weight": round(weight, 2),
                "technique_count": count,
                "techniques": sorted(list(stats["techniques"])),
                "reason": f"covers {count} attack technique(s): {', '.join(sorted(list(stats['techniques'])))}"
            })

        # Sort by weight descending
        results.sort(key=lambda x: x["weight"], reverse=True)

        # Add rank and return top-K
        for rank, item in enumerate(results[:top_k], 1):
            item["rank"] = rank

        return results[:top_k]

    @staticmethod
    def aggregate_controls_from_mapper(
        ranked_paths: List[Dict],
        cwe_mapper,  # CWEMapper instance with cwe_to_nist_with_fallback()
        attack_nist_mapper,  # AttackNISTMapper instance
        top_k: int = 12
    ) -> List[Dict]:
        """
        Convenience: Aggregate controls by calling mappers dynamically.

        Args:
            ranked_paths: From AttackPathRanker
            cwe_mapper: CWEMapper instance
            attack_nist_mapper: AttackNISTMapper instance
            top_k: Top-K controls to return

        Returns: [control dicts with weights]
        """

        if not ranked_paths:
            return []

        # Build nist_controls_per_technique dynamically
        nist_controls_per_technique = {}

        for path in ranked_paths:
            t_number = path.get("attack_technique", {}).get("t_number", "")

            if t_number and t_number not in nist_controls_per_technique:
                # Query attack_nist_mapper
                controls = attack_nist_mapper.technique_to_nist_controls(t_number)
                nist_controls_per_technique[t_number] = controls

        # Aggregate
        return ControlAggregator.aggregate_controls(
            ranked_paths,
            nist_controls_per_technique,
            top_k
        )
