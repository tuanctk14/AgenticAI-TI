#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test OpenCTI data to check if it has date fields"""
import sys
import json
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

from tools.opencti_client import fetch_opencti_indicators

print("=" * 80)
print("TEST: OpenCTI Data Fields and Dates")
print("=" * 80)

result = fetch_opencti_indicators(search_term="")
indicators = result.get("context", [])

print(f"\nTotal indicators fetched: {len(indicators)}")
print("\nSample indicators structure:")

# Show first indicator of each type
by_type = {}
for ind in indicators:
    entity_type = ind.get("entity_type", "Unknown")
    if entity_type not in by_type:
        by_type[entity_type] = ind

for entity_type, sample in by_type.items():
    print(f"\n{entity_type}:")
    print(f"  Full object: {json.dumps(sample, indent=2, default=str)[:500]}")
    print(f"  Keys available: {list(sample.keys())}")

print("\n" + "=" * 80)
print("Question: Do any have date fields like 'created_at', 'published', 'date'?")
print("=" * 80)
