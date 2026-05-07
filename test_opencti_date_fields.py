#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test OpenCTI date fields"""
import sys
import json
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN
from datetime import datetime, timedelta, timezone

sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

if not OPENCTI_TOKEN or not OPENCTI_URL:
    print("Missing OPENCTI_TOKEN or OPENCTI_URL")
    sys.exit(1)

# Test với fields có sẵn
gql = """
query {
  indicators(first: 3, orderBy: created_at, orderMode: desc) {
    edges { node {
      id
      name
      created_at
      updated_at
      valid_from
      valid_until
    }}
  }
}
"""

try:
    resp = requests.post(
        f"{OPENCTI_URL}/graphql",
        json={"query": gql},
        headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    if "errors" in data:
        print(f"GraphQL error:")
        for err in data['errors']:
            print(f"  - {err['message']}")
        sys.exit(1)

    print("=" * 80)
    print("Indicators with date fields:")
    print("=" * 80)

    indicators = data.get("data", {}).get("indicators", {}).get("edges", [])
    for i, edge in enumerate(indicators, 1):
        node = edge.get("node", {})
        print(f"\n{i}. {node.get('name')}")
        print(f"   ID: {node.get('id')}")
        print(f"   created_at: {node.get('created_at')}")
        print(f"   updated_at: {node.get('updated_at')}")
        print(f"   valid_from: {node.get('valid_from')}")
        print(f"   valid_until: {node.get('valid_until')}")

    print("\n" + "=" * 80)
    print("So sánh với date range (7 days)")
    print("=" * 80)

    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=7)
    print(f"Start: {start_dt.isoformat()}")
    print(f"End: {end_dt.isoformat()}")

    for edge in indicators:
        node = edge.get("node", {})
        created_str = node.get("created_at")
        if created_str:
            print(f"\n{node.get('name')}: {created_str}")
            try:
                created = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                in_range = start_dt <= created <= end_dt
                print(f"  In range: {in_range}")
            except:
                print("  Cannot parse date")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
