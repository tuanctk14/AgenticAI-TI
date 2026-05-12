#!/usr/bin/env python3
"""Debug CPE extraction"""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id

print("=" * 80)
print("CVE-2026-8259 Configurations Structure Debug")
print("=" * 80)

result = fetch_cve_by_id('CVE-2026-8259')
cves = result.get('context', [])

if cves:
    cve = cves[0]
    configs = cve.get('configurations', [])

    print(f"\nConfigurations count: {len(configs)}")

    if configs:
        for i, config in enumerate(configs):
            print(f"\nConfig {i}:")
            print(f"  Keys: {list(config.keys())}")

            nodes = config.get('nodes', [])
            print(f"  Nodes: {len(nodes)} items")

            if nodes:
                for j, node in enumerate(nodes):
                    print(f"\n  Node {j}:")
                    print(f"    Keys: {list(node.keys())}")

                    cpe_matches = node.get('cpeMatch', [])
                    print(f"    CPE Matches: {len(cpe_matches)} items")

                    if cpe_matches:
                        for k, match in enumerate(cpe_matches[:2]):
                            print(f"\n    Match {k}:")
                            print(f"      {json.dumps(match, indent=6)}")
else:
    print("CVE not found")
