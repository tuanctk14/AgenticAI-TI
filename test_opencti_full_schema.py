#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test OpenCTI full schema to find date fields"""
import sys
import json
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN

sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

if not OPENCTI_TOKEN or not OPENCTI_URL:
    print("Missing OPENCTI_TOKEN or OPENCTI_URL")
    sys.exit(1)

# Thử query với tất cả available fields
gql = """
query {
  indicators(first: 1, orderBy: created_at, orderMode: desc) {
    edges { node {
      id
      name
      description
      pattern
      confidence
      indicator_types
      created_at
      updated_at
      valid_from
      valid_until
      x_opencti_created_at_full
      x_opencti_updated_at_full
    }}
  }
  malwares(first: 1, orderBy: created_at, orderMode: desc) {
    edges { node {
      id
      name
      description
      malware_types
      created_at
      updated_at
      valid_from
      valid_until
      x_opencti_created_at_full
      x_opencti_updated_at_full
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
        print(f"GraphQL error: {data['errors']}")
        print("\nTrying to see what fields are available...")
        # Thử query đơn giản hơn
        gql2 = """
        query {
          indicators(first: 1) {
            edges { node {
              __typename
            }}
          }
        }
        """
        sys.exit(1)

    print("=" * 80)
    print("Indicator sample:")
    print("=" * 80)
    indicator = data.get("data", {}).get("indicators", {}).get("edges", [{}])[0].get("node", {})
    if indicator:
        print(json.dumps(indicator, indent=2, default=str)[:1500])
        print("\nFields available:")
        print(list(indicator.keys()))
    else:
        print("No indicator data")

    print("\n" + "=" * 80)
    print("Malware sample:")
    print("=" * 80)
    malware = data.get("data", {}).get("malwares", {}).get("edges", [{}])[0].get("node", {})
    if malware:
        print(json.dumps(malware, indent=2, default=str)[:1500])
        print("\nFields available:")
        print(list(malware.keys()))
    else:
        print("No malware data")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
