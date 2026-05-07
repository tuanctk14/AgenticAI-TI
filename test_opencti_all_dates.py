#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Check all available date fields in OpenCTI"""
import sys
import json
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN

sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

# Try to fetch with all possible date fields
gql = """
query {
  indicators(first: 1) {
    edges { node {
      id
      name
      created_at
      updated_at
      x_opencti_modified_at
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
        print("GraphQL Errors:")
        for err in data['errors']:
            print(f"  - {err['message']}")
        sys.exit(1)

    print("=" * 80)
    print("Available date fields in Indicator:")
    print("=" * 80)

    indicators = data.get("data", {}).get("indicators", {}).get("edges", [])
    if indicators:
        node = indicators[0].get("node", {})
        print(json.dumps(node, indent=2, default=str)[:1000])

        print("\n\nDate fields found:")
        for key in ['created_at', 'updated_at', 'x_opencti_modified_at']:
            if key in node:
                print(f"  ✓ {key}: {node[key]}")
            else:
                print(f"  ✗ {key}: NOT AVAILABLE")

except Exception as e:
    print(f"Error: {e}")
