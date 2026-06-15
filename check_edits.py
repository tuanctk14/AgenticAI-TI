import json

with open("data/knowledge_base/cves/2026/CVE-2026-54420.json") as f:
    cve = json.load(f)

print("Current _metadata:")
print(f"  date: {cve['_metadata']['last_updated']}")
print(f"  user: {cve['_metadata']['user']}")
print(f"  source: {cve['_metadata']['source']}")
print(f"  changes: {cve['_metadata']['changes']}")

print("\nMetadata history (_edits):")
for i, edit in enumerate(cve["_edits"]):
    print(f"  [{i}] {edit['date'][:19]} - {edit['user']} ({edit['source']}) - {edit['changes']}")

print(f"\nTotal edits: {len(cve['_edits'])}")
