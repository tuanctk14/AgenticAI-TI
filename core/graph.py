"""
core/graph.py - Xây dựng LangGraph workflow cho ATI-AgenticThreatIntelligence
"""
from langgraph.graph import StateGraph, END
from core.state      import CyberSecState
from agents.base     import call_agent, call_tool
from config          import MAX_STEPS


# ── Node functions ─────────────────────────────────────────────────────────
def node_supervisor(state): return call_agent(state, "agent_supervisor")
def node_ti(state):         return call_agent(state, "agent_ti")
def node_ti_extended(state):return call_agent(state, "agent_ti_extended")
def node_device(state):     return call_agent(state, "agent_device")
def node_matcher(state):    return call_agent(state, "agent_matcher")
# REMOVED: agent_analyst (CVE-only, no MITRE/NIST)
def node_doc(state):        return call_agent(state, "agent_doc")
def node_reporter(state):   return call_agent(state, "agent_reporter")
def node_tools(state):      return call_tool(state)


# ── Routing logic ──────────────────────────────────────────────────────────
def route_after_agent(state: dict) -> str:
    """Quyết định bước tiếp theo sau khi agent phản hồi."""
    response = state.get("last_agent_response", "").strip()

    if state.get("num_steps", 0) >= MAX_STEPS:
        print(f"    Đạt {MAX_STEPS} bước → end")
        return "end"

    # Check TASK_COMPLETE signal (iteration limit reached)
    if "TASK_COMPLETE" in response:
        print("    TASK_COMPLETE → end")
        return "end"

    # Check ANSWER FIRST (before ACTION) - agent may write both
    if "ANSWER:" in response and "ACTION:" not in response:
        print("   ANSWER → end")
        return "end"

    if "ACTION:" in response:
        print("    ACTION → tools")
        return "tools"

    if "HANDOFF:" in response:
        target = response.split("HANDOFF:")[1].strip().split()[0].strip()
        # Prevent self-handoff
        last_agent = state.get("last_agent", "")
        if target == last_agent:
            print(f"    HANDOFF: {target} (self) → BLOCKED")
            return "end"
        print(f"    HANDOFF → {target}")
        valid_targets = {
            "agent_ti", "agent_ti_extended", "agent_device", "agent_matcher",
            "agent_doc", "agent_reporter", "agent_supervisor",
        }  # Added agent_ti_extended for IOC/Malware, agent_device for device info
        if target in valid_targets:
            return f"handoff_{target}"

    return "end"


def which_agent_from_tools(state: dict) -> str:
    """Sau khi tool chạy xong, quay về agent nào đã gọi."""
    return state.get("last_agent", "agent_supervisor")


# ── Build graph ────────────────────────────────────────────────────────────
def build_graph() -> StateGraph:
    graph = StateGraph(state_schema=CyberSecState)  # type: ignore

    # Thêm nodes (CVE + IOC/Malware from OpenCTI + Device Info)
    graph.add_node("agent_supervisor",  node_supervisor)
    graph.add_node("agent_ti",          node_ti)
    graph.add_node("agent_ti_extended", node_ti_extended)
    graph.add_node("agent_device",      node_device)
    graph.add_node("agent_matcher",     node_matcher)
    # REMOVED: graph.add_node("agent_analyst", node_analyst)
    graph.add_node("agent_doc",         node_doc)
    graph.add_node("agent_reporter",    node_reporter)
    graph.add_node("tools",             node_tools)

    # Entry point
    graph.set_entry_point("agent_supervisor")

    # Supervisor routing (CVE + IOC/Malware + Device)
    graph.add_conditional_edges(
        "agent_supervisor",
        route_after_agent,
        {
            "handoff_agent_ti":            "agent_ti",
            "handoff_agent_ti_extended":   "agent_ti_extended",
            "handoff_agent_device":        "agent_device",
            "handoff_agent_matcher":       "agent_matcher",
            # "handoff_agent_analyst":      removed (CVE-only)
            "handoff_agent_doc":           "agent_doc",
            "handoff_agent_reporter":      "agent_reporter",
            "tools":                       "tools",
            "end":                         END,
        },
    )

    # Specialist agents routing (CVE + IOC/Malware + Device, no analyst)
    specialist_routing = {
        "tools":                       "tools",
        "handoff_agent_supervisor":    "agent_supervisor",
        "handoff_agent_ti":            "agent_ti",
        "handoff_agent_ti_extended":   "agent_ti_extended",
        "handoff_agent_device":        "agent_device",
        "handoff_agent_matcher":       "agent_matcher",
        # "handoff_agent_analyst":       removed
        "handoff_agent_doc":           "agent_doc",
        "handoff_agent_reporter":      "agent_reporter",
        "end":                         END,
    }
    for agent_node in ["agent_ti", "agent_ti_extended", "agent_device", "agent_matcher",
                       "agent_doc", "agent_reporter"]:
        graph.add_conditional_edges(agent_node, route_after_agent, specialist_routing)

    # Tools → về agent đã gọi (CVE + IOC/Malware + Device)
    graph.add_conditional_edges(
        "tools",
        which_agent_from_tools,
        {
            "agent_supervisor":   "agent_supervisor",
            "agent_ti":           "agent_ti",
            "agent_ti_extended":  "agent_ti_extended",
            "agent_device":       "agent_device",
            "agent_matcher":      "agent_matcher",
            # "agent_analyst":      removed
            "agent_doc":          "agent_doc",
            "agent_reporter":     "agent_reporter",
        },
    )

    return graph.compile()


# Singleton graph
_graph = None

def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
        print(" ATI-AgenticThreatIntelligence Graph đã biên dịch")
    return _graph
