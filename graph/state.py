from typing import TypedDict, List, Optional, Annotated
import operator

class SOCState(TypedDict):

    # Main input
    alert: dict
    # Raw Wazuh alert — injected by main.py

    # Agent 2 → Agent 3
    index_mapping: dict
    # OpenSearch field schema

    # Agent 1 → Agent 3 Round 1
    questions_round1: List[str]
    # Context gathering questions

    # Agent 3 → Agent 1
    context_round1: dict
    # Historical context found in wazuh-alerts-*

    # Agent 1 → Router
    round2_required: bool
    # True = launch Round 2

    # Agent 1 → Agent 3 Round 2
    questions_round2: Optional[List[str]]
    # Deep investigation questions

    # Agent 1 → Agent 4
    context_summary: str
    # Summary of the pattern detected by Agent 1

    # Agent 3 → Agent 4
    results_round2: Optional[dict]
    # Detailed activities from wazuh-archives-*

    # Agent 4 → SOC Analyst
    final_report: str
    # Final Markdown report

    risk_score: int
    # Risk score 0-10