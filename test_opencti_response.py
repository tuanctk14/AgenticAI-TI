#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Check actual OpenCTI GraphQL response"""
import sys
import json
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN

sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

gql = """
query GetThreatIntel($search: String, $first: Int) {
  indicators(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
    edges { node {
      id name pattern confidence description created_at
    }}
  }
}
"""

try:
    resp = requests.post(
        f"{OPENCTI_URL}/graphql",
        json={"query": gql, "variables": {"search": "", "first": 3}},
        headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    if "errors" in data:
        print("GraphQL Errors:")
        for err in data['errors']:
            print(f"  - {err['message']}")
        sys.exit(1)

    print("=" * 80)
    print("Raw GraphQL Response (first 3 indicators):")
    print("=" * 80)

    indicators = data.get("data", {}).get("indicators", {}).get("edges", [])
    for i, edge in enumerate(indicators, 1):
        node = edge.get("node", {})
        print(f"\n{i}. {node.get('name')}")
        print(json.dumps(node, indent=2, default=str))

    print("\n" + "=" * 80)
    print("Check if 'created_at' is in response:")
    if indicators:
        first_node = indicators[0].get("node", {})
        if "created_at" in first_node:
            print(f"  YES - created_at: {first_node.get('created_at')}")
        else:
            print(f"  NO - Fields available: {list(first_node.keys())}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
