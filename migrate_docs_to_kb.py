#!/usr/bin/env python3
"""
Migrate data/docs (old KB) to data/knowledge_base (unified KB).

Reads cves.json, iocs.json, malwares.json from data/docs
and saves to data/knowledge_base/cves/YYYY, iocs/YYYY, malwares/YYYY
with full metadata tracking.
"""

import json
from pathlib import Path
from datetime import datetime
from tools.knowledge_base_manager import get_kb_manager

DOCS_DIR = Path("data/docs")
OLD_KB_FILES = {
    "cves": DOCS_DIR / "cves.json",
    "iocs": DOCS_DIR / "iocs.json",
    "malwares": DOCS_DIR / "malwares.json"
}


def migrate_cves():
    """Migrate CVEs from data/docs/cves.json to KB."""
    cves_file = OLD_KB_FILES["cves"]
    if not cves_file.exists():
        print(f"[INFO] {cves_file} not found, skipping")
        return 0

    try:
        with open(cves_file, 'r', encoding='utf-8') as f:
            cves = json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not load {cves_file}: {e}")
        return 0

    kb = get_kb_manager()
    migrated = 0

    for cve in cves:
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # Save to KB with metadata
        success = kb.save_cve(
            cve_id,
            cve,
            user="migration",
            source="user_upload",
            changes=f"Migrated from data/docs/cves.json on {datetime.now().isoformat()}"
        )

        if success:
            migrated += 1
        else:
            print(f"[WARN] Failed to migrate {cve_id}")

    print(f"[OK] Migrated {migrated} CVEs from data/docs")
    return migrated


def migrate_iocs():
    """Migrate IOCs from data/docs/iocs.json to KB."""
    iocs_file = OLD_KB_FILES["iocs"]
    if not iocs_file.exists():
        print(f"[INFO] {iocs_file} not found, skipping")
        return 0

    try:
        with open(iocs_file, 'r', encoding='utf-8') as f:
            iocs = json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not load {iocs_file}: {e}")
        return 0

    kb = get_kb_manager()
    migrated = 0

    for ioc in iocs:
        ioc_id = ioc.get("id", "")
        if not ioc_id:
            continue

        success = kb.save_ioc(ioc_id, ioc, user="migration")
        if success:
            migrated += 1

    print(f"[OK] Migrated {migrated} IOCs from data/docs")
    return migrated


def migrate_malwares():
    """Migrate Malwares from data/docs/malwares.json to KB."""
    mal_file = OLD_KB_FILES["malwares"]
    if not mal_file.exists():
        print(f"[INFO] {mal_file} not found, skipping")
        return 0

    try:
        with open(mal_file, 'r', encoding='utf-8') as f:
            malwares = json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not load {mal_file}: {e}")
        return 0

    kb = get_kb_manager()
    migrated = 0

    for mal in malwares:
        mal_id = mal.get("id", "")
        if not mal_id:
            continue

        success = kb.save_malware(mal_id, mal, user="migration")
        if success:
            migrated += 1

    print(f"[OK] Migrated {migrated} Malwares from data/docs")
    return migrated


def main():
    """Run migration."""
    print("=" * 70)
    print("MIGRATING data/docs -> data/knowledge_base")
    print("=" * 70)

    total = 0
    total += migrate_cves()
    total += migrate_iocs()
    total += migrate_malwares()

    print(f"\n[DONE] Total migrated: {total} entries")
    print("=" * 70)

    # Show KB status
    kb = get_kb_manager()
    stats = kb.get_kb_stats()
    print("\nNew KB Status:")
    print(f"  Total CVEs: {stats['total_cves']}")
    print(f"  Total IOCs: {stats['total_iocs']}")
    print(f"  Total Malwares: {stats['total_malwares']}")
    print(f"  Last updated: {stats['last_updated']}")


if __name__ == "__main__":
    main()
