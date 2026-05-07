"""
core/state.py - LangGraph State Schema cho ATI-AgenticThreatIntelligence
"""
from typing import TypedDict, List, Optional


class CyberSecState(TypedDict):
    # Input
    query:               str

    # Agent tracking
    last_agent_response: str
    last_agent:          str
    num_steps:           int
    agent_history:       List[str]

    # Iteration limits (prevent infinite loops)
    ti_iterations:       int
    matcher_iterations:  int
    analyst_iterations:  int

    # Completion flags
    ti_completed:        bool
    matcher_completed:   bool
    analyst_completed:   bool
    reporter_completed:  bool

    # Tool results (raw log)
    tool_observations:   List[str]

    # Structured data passed between agents
    collected_cves:       Optional[List[dict]]
    collected_indicators: Optional[List[dict]]  # IOC/Malware from OpenCTI
    matched_devices:      Optional[List[dict]]

    # Device-level aggregation (optimized for analysis)
    device_cve_map:       Optional[dict]  # {device_id: [cve_ids]}
    device_analysis:      Optional[dict]  # {device_id: {mitre: [...], nist: [...]}}

    attack_info:          Optional[dict]
    nist_info:            Optional[dict]
    final_report:         Optional[str]

    # Document upload / Knowledge base
    uploaded_docs:        Optional[List[dict]]


def init_state(query: str) -> CyberSecState:
    """Khởi tạo state mới cho một câu hỏi."""
    return CyberSecState(
        query=query,
        last_agent_response="",
        last_agent="",
        num_steps=0,
        agent_history=[],
        ti_iterations=0,
        matcher_iterations=0,
        analyst_iterations=0,
        ti_completed=False,
        matcher_completed=False,
        analyst_completed=False,
        reporter_completed=False,
        tool_observations=[],
        collected_cves=None,
        collected_indicators=None,
        matched_devices=None,
        device_cve_map=None,
        device_analysis=None,
        attack_info=None,
        nist_info=None,
        final_report=None,
        uploaded_docs=None,
    )
