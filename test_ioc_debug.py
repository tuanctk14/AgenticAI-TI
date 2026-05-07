#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Debug IOC fetching"""
import sys
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

from tools.opencti_client import fetch_opencti_indicators
from datetime import datetime, timedelta, timezone

print("=" * 80)
print("DEBUG: IOC Fetching with Date Range")
print("=" * 80)

# 7 day range
end_dt = datetime.now(timezone.utc)
start_dt = end_dt - timedelta(days=7)
start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
end_date = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

print(f"\nDate range: {start_date} to {end_date}")
print(f"  (Start: {start_dt.date()}, End: {end_dt.date()})")

# Test with different max_results
for max_res in [50, 100, 200]:
    print(f"\n--- Test with max_results={max_res} ---")
    result = fetch_opencti_indicators(
        search_term="",
        start_date=start_date,
        end_date=end_date,
        max_results=max_res
    )

    indicators = result.get("context", [])
    print(f"Total results: {len(indicators)}")

    # Count by type
    by_type = {}
    for ind in indicators:
        et = ind.get("entity_type", "Unknown")
        by_type[et] = by_type.get(et, 0) + 1

    print(f"Breakdown:")
    for et, count in sorted(by_type.items()):
        print(f"  - {et}: {count}")

    # Show sample created_at
    print(f"Sample created_at dates:")
    for ind in indicators[:3]:
        print(f"  - {ind.get('name', 'N/A')}: {ind.get('created_at', 'N/A')}")

print("\n" + "=" * 80)
