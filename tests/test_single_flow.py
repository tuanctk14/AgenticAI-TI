"""Quick test of single analyst-first flow"""
import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.graph import get_graph
from core.state import init_state

print("\n" + "=" * 80)
print(" ANALYST-FIRST PIPELINE - SINGLE TEST")
print("=" * 80)

query = "Quét CVE log4j"
print(f"\nQuery: {query}\n")

graph = get_graph()
state = init_state(query)

# Run with limited iterations
result = graph.invoke(state, config={"recursion_limit": 10})

# Extract final answer
final_response = result.get("last_agent_response", "")
agent_flow = result.get("agent_history", [])

print(f"\nAgent flow: {' > '.join(agent_flow)}")
print(f"\nAnalyst iterations: {result.get('analyst_iterations', 0)}")
print(f"Attack info populated: {bool(result.get('attack_info', {}))}")
print(f"NIST info populated: {bool(result.get('nist_info', {}))}")

# Show first 500 chars of response
if final_response.startswith("ANSWER:"):
    final_response = final_response[8:].strip()

print(f"\nFinal response (first 500 chars):")
print(final_response[:500] + ("..." if len(final_response) > 500 else ""))

# Validate key requirements
has_mitre = "MITRE" in final_response
has_nist = "NIST" in final_response or "NIST SP" in final_response

print(f"\n✓ Has MITRE section: {has_mitre}")
print(f"✓ Has NIST section: {has_nist}")

if has_mitre and has_nist:
    print("\n✅ ANALYST-FIRST PIPELINE WORKING!")
else:
    print("\n❌ PIPELINE INCOMPLETE - Missing sections")
