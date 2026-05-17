# -*- coding: utf-8 -*-
"""
tools/relationship_formatter.py - Output Formatting for Validated Relationships

Formats validated relationships for display, clearly separating:
1. VERIFIED RELATIONSHIPS - high confidence, direct evidence
2. POTENTIAL CONTEXTUAL ENTITIES - weak signals, NLP inference
"""

from typing import Dict, List


def _get_entity_type(rel) -> str:
    """Get entity type from dict or object"""
    if isinstance(rel, dict):
        return rel.get("entity_type", "")
    return getattr(rel, "entity_type", "")


def format_relationship_section(
    cve_id: str,
    validated_data: Dict,
) -> str:
    """
    Format validated relationship data for display in reports.

    Input structure:
    {
        "verified_relationships": [ValidatedRelationship],
        "potential_entities": [Dict],
        "validation_summary": {...}
    }

    Returns: Formatted string for Menu 1 output
    """

    lines = []

    # Get summary stats
    summary = validated_data.get("validation_summary", {})
    total_entities = summary.get("total_entities", 0)
    verified_count = summary.get("verified_count", 0)
    potential_count = summary.get("potential_count", 0)
    avg_confidence = summary.get("avg_confidence", 0.0)

    lines.append("═" * 70)
    lines.append(" THREAT RELATIONSHIP INTELLIGENCE (Validated)")
    lines.append("═" * 70)
    lines.append("")

    lines.append(f"  CVE: {cve_id}")
    lines.append(f"  Entities analyzed: {total_entities}")
    lines.append(f"  Verified relationships: {verified_count}")
    lines.append(f"  Potential correlations: {potential_count}")
    lines.append(f"  Average confidence: {avg_confidence:.1%}")
    lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # SECTION 1: VERIFIED RELATIONSHIPS (HIGH CONFIDENCE)
    # ══════════════════════════════════════════════════════════════════

    verified_rels = validated_data.get("verified_relationships", [])

    if verified_rels:
        lines.append("─" * 70)
        lines.append(" ✓ VERIFIED RELATIONSHIPS (High Confidence)")
        lines.append("─" * 70)
        lines.append("")

        # Group by entity type
        malware_rels = [r for r in verified_rels if _get_entity_type(r) == "malware"]
        campaign_rels = [r for r in verified_rels if _get_entity_type(r) == "campaign"]
        actor_rels = [r for r in verified_rels if _get_entity_type(r) == "threat_actor"]

        # Malware relationships
        if malware_rels:
            lines.append(f"  MALWARE FAMILIES ({len(malware_rels)}):")
            lines.append("")
            for rel in malware_rels[:10]:
                lines.extend(_format_verified_relationship(rel))
            if len(malware_rels) > 10:
                lines.append(f"    ... and {len(malware_rels) - 10} more")
            lines.append("")

        # Campaign relationships
        if campaign_rels:
            lines.append(f"  ACTIVE CAMPAIGNS ({len(campaign_rels)}):")
            lines.append("")
            for rel in campaign_rels[:10]:
                lines.extend(_format_verified_relationship(rel))
            if len(campaign_rels) > 10:
                lines.append(f"    ... and {len(campaign_rels) - 10} more")
            lines.append("")

        # Threat actor relationships
        if actor_rels:
            lines.append(f"  THREAT ACTORS ({len(actor_rels)}):")
            lines.append("")
            for rel in actor_rels[:10]:
                lines.extend(_format_verified_relationship(rel))
            if len(actor_rels) > 10:
                lines.append(f"    ... and {len(actor_rels) - 10} more")
            lines.append("")
    else:
        lines.append("─" * 70)
        lines.append(" ✓ VERIFIED RELATIONSHIPS")
        lines.append("─" * 70)
        lines.append("")
        lines.append("  No verified relationships found.")
        lines.append("  (Requires direct evidence or multi-source confirmation)")
        lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # SECTION 2: POTENTIAL CONTEXTUAL ENTITIES (WEAK SIGNALS)
    # ══════════════════════════════════════════════════════════════════

    potential_entities = validated_data.get("potential_entities", [])

    if potential_entities:
        lines.append("─" * 70)
        lines.append(" ⚠ POTENTIAL CONTEXTUAL ENTITIES (Weak Signals)")
        lines.append("─" * 70)
        lines.append("")
        lines.append("  These entities show contextual correlation but lack direct evidence.")
        lines.append("  Suitable for investigative leads, not operational intelligence.")
        lines.append("")

        # Group by type
        malware_potential = [e for e in potential_entities if e.get("type") == "malware"]
        campaign_potential = [e for e in potential_entities if e.get("type") == "campaign"]
        actor_potential = [e for e in potential_entities if e.get("type") == "threat_actor"]

        # Malware potential
        if malware_potential:
            lines.append(f"  POTENTIALLY RELATED MALWARE ({len(malware_potential)}):")
            lines.append("")
            for entity in malware_potential[:10]:
                lines.extend(_format_potential_entity(entity))
            if len(malware_potential) > 10:
                lines.append(f"    ... and {len(malware_potential) - 10} more")
            lines.append("")

        # Campaign potential
        if campaign_potential:
            lines.append(f"  POTENTIALLY RELATED CAMPAIGNS ({len(campaign_potential)}):")
            lines.append("")
            for entity in campaign_potential[:10]:
                lines.extend(_format_potential_entity(entity))
            if len(campaign_potential) > 10:
                lines.append(f"    ... and {len(campaign_potential) - 10} more")
            lines.append("")

        # Actor potential
        if actor_potential:
            lines.append(f"  POTENTIALLY RELATED THREAT ACTORS ({len(actor_potential)}):")
            lines.append("")
            for entity in actor_potential[:10]:
                lines.extend(_format_potential_entity(entity))
            if len(actor_potential) > 10:
                lines.append(f"    ... and {len(actor_potential) - 10} more")
            lines.append("")

    lines.append("═" * 70)
    lines.append("")

    return "\n".join(lines)


def _format_verified_relationship(rel) -> List[str]:
    """Format a single verified relationship for display"""
    lines = []

    # Convert to dict if needed
    if hasattr(rel, 'to_dict'):
        rel_data = rel.to_dict()
    else:
        rel_data = rel

    entity = rel_data.get("target_entity", "Unknown")
    rel_type = rel_data.get("relationship_type", "associated_with")
    confidence = rel_data.get("confidence", 0.0)
    confidence_level = rel_data.get("confidence_level", "LOW")
    provenance = rel_data.get("provenance", [])
    evidence_list = rel_data.get("evidence", [])

    lines.append(f"    • {entity}")
    lines.append(f"      Relationship: {rel_type}")
    lines.append(f"      Confidence: {confidence:.1%} ({confidence_level})")

    if provenance:
        prov_str = ", ".join(provenance[:3])
        if len(provenance) > 3:
            prov_str += f", ... (+{len(provenance) - 3})"
        lines.append(f"      Sources: {prov_str}")

    if evidence_list:
        lines.append(f"      Evidence ({len(evidence_list)}):")
        for ev in evidence_list[:2]:
            desc = ev.get("description", "")
            lines.append(f"        - {desc}")
        if len(evidence_list) > 2:
            lines.append(f"        ... and {len(evidence_list) - 2} more evidence items")

    lines.append("")
    return lines


def _format_potential_entity(entity: Dict) -> List[str]:
    """Format a potential entity for display"""
    lines = []

    name = entity.get("name", "Unknown")
    confidence = entity.get("confidence", 0.0)
    confidence_level = entity.get("confidence_level", "LOW")
    correlation_type = entity.get("correlation_type", "contextual_overlap")
    evidence_count = entity.get("evidence_count", 0)

    lines.append(f"    • {name}")
    lines.append(f"      Correlation: {correlation_type}")
    lines.append(f"      Confidence: {confidence:.1%} ({confidence_level})")
    lines.append(f"      Evidence sources: {evidence_count}")
    lines.append("")

    return lines


def format_relationship_summary(validated_data: Dict) -> str:
    """
    Format a brief summary of validation results.
    Useful for agent responses.
    """
    summary = validated_data.get("validation_summary", {})

    verified_count = summary.get("verified_count", 0)
    potential_count = summary.get("potential_count", 0)
    total_entities = summary.get("total_entities", 0)
    avg_confidence = summary.get("avg_confidence", 0.0)

    if verified_count == 0:
        return (
            f"No verified relationships found. "
            f"{potential_count} potential entities found with weak signals. "
            f"Average confidence: {avg_confidence:.1%}."
        )

    summary_text = (
        f"Found {verified_count} verified relationships "
        f"({verified_count}/{total_entities} entities, {avg_confidence:.1%} avg confidence). "
    )

    if potential_count > 0:
        summary_text += (
            f"{potential_count} additional entities show contextual correlation "
            f"but lack direct evidence."
        )

    return summary_text


def create_validation_report(cve_id: str, validated_data: Dict) -> str:
    """
    Create a detailed validation report showing methodology.
    """
    lines = []

    lines.append("\n" + "=" * 70)
    lines.append(" RELATIONSHIP VALIDATION REPORT")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"CVE: {cve_id}")
    lines.append("")

    summary = validated_data.get("validation_summary", {})
    lines.append("VALIDATION SUMMARY:")
    lines.append(f"  Total entities analyzed: {summary.get('total_entities', 0)}")
    lines.append(f"  Verified relationships: {summary.get('verified_count', 0)}")
    lines.append(f"  Potential entities: {summary.get('potential_count', 0)}")
    lines.append(f"  Average confidence: {summary.get('avg_confidence', 0.0):.1%}")
    lines.append("")

    lines.append("METHODOLOGY:")
    lines.append("  - Direct OpenCTI graph edges")
    lines.append("  - Campaign membership confirmation")
    lines.append("  - Malware analysis linkage")
    lines.append("  - ATT&CK-confirmed techniques")
    lines.append("  - IOC correlation")
    lines.append("")

    lines.append("CONFIDENCE THRESHOLDS:")
    lines.append("  HIGH (≥80%): Direct evidence, multi-source")
    lines.append("  MEDIUM (50-79%): Single source, indirect linkage")
    lines.append("  LOW (20-49%): Contextual overlap only")
    lines.append("  VERY_LOW (<20%): Semantic similarity only")
    lines.append("")

    return "\n".join(lines)
