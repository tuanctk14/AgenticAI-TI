#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick test of live Menu 1 with enrichment display"""

import sys
from main import chat_with_supervisor

# Test Menu 1
print("=" * 60)
print("TESTING LIVE MENU 1 WITH ENRICHMENT")
print("=" * 60)

state = {
    "query": "CVE-2021-44228",
    "conversation_history": [],
}

# Run the workflow (mimics Menu 1)
final_response = chat_with_supervisor(state["query"], state.get("conversation_history", []))
print("\n" + final_response)

# Check for enrichment
if "THREAT RELATIONSHIPS" in final_response:
    print("\n✅ SUCCESS: Enrichment section found!")
    if "MALWARE FAMILIES" in final_response:
        print("✅ Malware families displayed!")
    if "ACTIVE CAMPAIGNS" in final_response:
        print("✅ Active campaigns displayed!")
else:
    print("\n❌ FAIL: Enrichment section NOT found")

print("\n" + "=" * 60)
