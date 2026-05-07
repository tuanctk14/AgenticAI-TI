#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Debug date filtering logic"""
import sys
from datetime import datetime, timedelta, timezone

sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

# Sample created_at from OpenCTI
created_at_str = "2026-05-05T06:05:18.797Z"

# 7 day range (now)
end_dt = datetime.now(timezone.utc)
start_dt = end_dt - timedelta(days=7)
start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
end_date = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

print("=" * 80)
print("Debug Date Filtering")
print("=" * 80)

print(f"\nDate strings from code:")
print(f"  start_date: {start_date}")
print(f"  end_date: {end_date}")

print(f"\nParsed:")
start_dt_parsed = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
end_dt_parsed = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
print(f"  start_dt: {start_dt_parsed}")
print(f"  end_dt: {end_dt_parsed}")

print(f"\nSample created_at: {created_at_str}")
created_at_parsed = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
print(f"  Parsed: {created_at_parsed}")

print(f"\nComparison:")
print(f"  created_at >= start_dt: {created_at_parsed >= start_dt_parsed}")
print(f"  created_at <= end_dt: {created_at_parsed <= end_dt_parsed}")
print(f"  Both: {(created_at_parsed >= start_dt_parsed) and (created_at_parsed <= end_dt_parsed)}")

# Now test with actual function
print("\n" + "=" * 80)
print("Test with OpenCTI function:")
print("=" * 80)

from tools.opencti_client import fetch_opencti_indicators

result = fetch_opencti_indicators(
    search_term="",
    start_date=start_date,
    end_date=end_date,
    max_results=10
)
indicators = result.get("context", [])
print(f"\nResults with date filter: {len(indicators)}")
if indicators:
    for ind in indicators[:3]:
        print(f"  - {ind.get('name')}: {ind.get('created_at')}")
