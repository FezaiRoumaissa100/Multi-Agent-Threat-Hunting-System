import json
import os
import ollama
from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from graph.state import SOCState


load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# Load prompt template
_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "..", "prompts", "agent4_correlation.txt")
with open(_PROMPT_PATH, "r", encoding="utf-8") as _f:
    _PROMPT_TEMPLATE = _f.read()
def correlation_node(state: SOCState) -> dict:
    """
    Agent 4 reads all evidence from the State
    and generates the final report + risk score
    """
    print("[AGENT 4] Correlating evidence...")

    # Read from State
    alert           = state.get("alert", {})
    context_summary = state.get("context_summary", "No summary available")
    context_tour1   = state.get("context_tour1", {})
    results_tour2   = state.get("results_tour2", None)

    # Build prompt from external template
    prompt = _PROMPT_TEMPLATE.format(
        alert   = json.dumps(alert, indent=2),
        summary = context_summary,
        tour1   = json.dumps(context_tour1, indent=2),
        tour2   = json.dumps(results_tour2, indent=2) if results_tour2 else "Round 2 not launched"
    )

    # Call Ollama
    print(f"[AGENT 4] Calling Ollama ({OLLAMA_MODEL})...")
    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[{"role":"system","content": "You are an expert SOC analyst.Correlate all evidence and deliver a final verdict."},
        {"role": "user", "content": prompt}]
    )
    try:
        content = response["message"]["content"]
        content = content.replace("```json", "").replace("```", "").strip()
        result  = json.loads(content)

    except (json.JSONDecodeError, KeyError) as e:
        print(f"[AGENT 4] JSON parsing error: {e}")
        result = {
            "risk_score"          : 5,
            "verdict"             : "NEEDS_INVESTIGATION",
            "attack_type"         : "Unknown",
            "mitre_techniques"    : [],
            "timeline"            : [],
            "recommended_actions" : ["Manually review the alert"],
            "summary"             : "Parsing error — manual investigation required"
        }

    # Generate Markdown report 
    risk_score = result.get("risk_score", 5)
    verdict    = result.get("verdict", "UNKNOWN")
    # Build Markdown report
    markdown_report = f"""# SOC Investigation Report
**Date**      : {alert.get("@timestamp", "N/A")}
**Agent**     : {alert.get("agent", {}).get("name", "N/A")}
**Score**     : {risk_score}/10 
**Verdict**   : {verdict}

---

## Initial Alert
- **Description** : {alert.get("rule", {}).get("description", "N/A")}
- **Wazuh Level** : {alert.get("rule", {}).get("level", "N/A")}
- **Source IP**   : {alert.get("src_ip", "N/A")}
- **User**        : {alert.get("dst_user", "N/A")}

---

## Detected Pattern (Agent 1)
{context_summary}

---

## Attack Type
{result.get("attack_type", "N/A")}

---

## MITRE ATT&CK Techniques
{chr(10).join([f"- {t}" for t in result.get("mitre_techniques", [])])}

---

## Timeline
{chr(10).join([f"- {e.get('event', '')}" for e in result.get("timeline", [])])}

---

## Recommended Actions
{chr(10).join([f"{i+1}. {a}" for i, a in enumerate(result.get("recommended_actions", []))])}

---

## Summary
{result.get("summary", "")}

---
*Report automatically generated*
"""

    #Save the report 
    try:
        import os
        os.makedirs("reports", exist_ok=True)
        timestamp = alert.get("@timestamp", "latest").replace(":", "-")
        path = f"reports/report_{timestamp}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(markdown_report)
        print(f"[AGENT 4] Report saved: {path}")
    except Exception as e:
        print(f"[AGENT 4] Save error: {e}")

    print(f"[AGENT 4] Score: {risk_score}/10 — Verdict: {verdict}")

    #Write to State 
    return {
        "final_report" : markdown_report,
        "risk_score"   : risk_score
    }
# AGENT 4 SUBGRAPh
builder = StateGraph(SOCState)
builder.add_node("correlation", correlation_node)
builder.add_edge(START, "correlation")
builder.add_edge("correlation", END)
# Compile:imported in workflow.py
agent4 = builder.compile()