#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test if created_at is being saved"""
import sys
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

from tools.opencti_client import fetch_opencti_indicators

result = fetch_opencti_indicators(search_term="", max_results=10)
indicators = result.get("context", [])

print(f"Total indicators (no date filter): {len(indicators)}")
if indicators:
    first = indicators[0]
    print(f"\nFirst indicator:")
    print(f"  Name: {first.get('name')}")
    print(f"  Entity type: {first.get('entity_type')}")
    print(f"  created_at: {first.get('created_at')}")
    print(f"  All keys: {list(first.keys())}")
