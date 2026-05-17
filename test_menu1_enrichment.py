#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify Menu 1 enrichment display works
"""

import sys
from agents.base import call_agent, call_tool

def test_menu1_enrichment():
    """Test that Menu 1 displays enrichment data from Priority #1"""

    # Initialize state for Menu 1 query
    state = {
        "query": "CVE-2021-44228",
        "conversation_history": [],
        "num_steps": 0,
        "agent_history": [],
    }

    print("="*60)
    print("TESTING MENU 1 ENRICHMENT DISPLAY")
    print("="*60)
    print(f"\nQuery: {state['query']}")
    print()

    max_iterations = 8
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        print(f"\n{'─'*60}")
        print(f"ITERATION {iteration}")
        print(f"{'─'*60}")

        last_agent = state.get("last_agent")
        agent_history = state.get("agent_history", [])

        # Determine next agent
        if not agent_history:
            next_agent = "agent_supervisor"
        else:
            last_response = state.get("last_agent_response", "")
            if "HANDOFF:" in last_response:
                next_agent = last_response.split("HANDOFF:")[-1].strip()
            elif "ANSWER:" in last_response:
                print("\nFinal answer received. Workflow complete.")
                break
            else:
                next_agent = last_agent

        print(f"Agent: {next_agent}")
        print(f"Last response: {state.get('last_agent_response', 'None')[:80]}...")

        # Call agent
        state = call_agent(state, next_agent)

        # Execute any tools
        if "ACTION:" in state.get("last_agent_response", ""):
            print(f"Executing tools...")
            state = call_tool(state)

    # Check results
    print("\n" + "="*60)
    print("VERIFICATION")
    print("="*60)

    cves = state.get("collected_cves", [])
    print(f"\nCVEs collected: {len(cves)}")

    if cves:
        for cve in cves:
            cve_id = cve.get("id")
            relationships = cve.get("relationships", {})
            print(f"\nCVE: {cve_id}")
            print(f"  Has relationships: {bool(relationships)}")
            if relationships:
                malwares = relationships.get("malwares", [])
                campaigns = relationships.get("campaigns", [])
                actors = relationships.get("threat_actors", [])
                print(f"    Malware families: {len(malwares)}")
                print(f"    Campaigns: {len(campaigns)}")
                print(f"    Threat actors: {len(actors)}")
                if malwares:
                    print(f"      Example: {malwares[0].get('name')}")
                if campaigns:
                    print(f"      Example campaign: {campaigns[0].get('name')}")

    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

if __name__ == "__main__":
    test_menu1_enrichment()
