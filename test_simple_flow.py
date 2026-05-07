#!/usr/bin/env python
"""Test simple query through system."""
import sys, os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from config import MAX_STEPS
from core.state import init_state
from core.graph import get_graph

print("=" * 70)
print("SIMPLE FLOW TEST")
print("=" * 70)

query = "Liet ke cac thiet bi trong CMDB"
print(f"\nQuery: {query}")
print(f"Max steps: {MAX_STEPS}")

state = init_state(query)
graph = get_graph()

print("\n[Starting graph invoke...]")
try:
    result = graph.invoke(state, config={"recursion_limit": 15})

    print(f"\n✓ COMPLETED")
    print(f"  Total steps: {result.get('num_steps')}")
    print(f"  Agents: {' -> '.join(result.get('agent_history', []))}")

    devices = result.get('matched_devices') or []
    if devices:
        print(f"  Matched devices: {len(devices)}")

    response = result.get('last_agent_response', '')[:200]
    if response:
        print(f"\n[Response preview:]")
        print(f"  {response}...")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
