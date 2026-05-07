import os
import json
from pathlib import Path
from dotenv import load_dotenv
from langchain_ollama import ChatOllama

# -----------------------------
# LOAD ENV
# -----------------------------
load_dotenv()

OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL")
ALERTS_FILE     = os.getenv("ALERTS_FILE", "data/my_alerts.json")

PROMPT_PATH      = Path(__file__).resolve().parent.parent / "prompts" / "agent1_prompt.txt"

# Max context alerts sent to the LLM (keeps prompt small → faster response)
MAX_CONTEXT_FOR_LLM = 3

# -----------------------------
# INIT LLM
# -----------------------------
llm = ChatOllama(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_BASE_URL,
    timeout=120,          # seconds — raise if your machine is slow
    num_predict=1024,     # cap output tokens → prevents infinite generation
)


# -----------------------------
# LOAD PROMPT TEMPLATE
# -----------------------------
def load_prompt_template(path: Path = PROMPT_PATH) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"[ERROR] Prompt file not found: {path}")


# -----------------------------
# 1. LOAD ALERTS
# -----------------------------
def load_alerts(file_path: str = ALERTS_FILE) -> list:
    """
    Supports:
    - JSON array  -> [ {...}, {...} ]
    - NDJSON      -> one JSON object per line
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            print("[WARN] Empty alerts file")
            return []

        if content.startswith("["):
            return json.loads(content)

        alerts = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping invalid JSON line: {e}")
        return alerts

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return []
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON structure: {e}")
        return []


# -----------------------------
# 2. EXTRACT FIELDS FROM WAZUH ALERT
# -----------------------------
def extract_alert_fields(alert: dict) -> dict:
    """
    Normalise a raw Wazuh alert into a flat dict of fields
    used for context matching and scoring.

    Wazuh field locations:
      rule id        -> alert["rule"]["id"]
      rule level     -> alert["rule"]["level"]
      agent name     -> alert["agent"]["name"]
      agent ip       -> alert["agent"]["ip"]           (absent on manager agent)
      src user       -> alert["data"]["srcuser"]        (optional)
      dst user       -> alert["data"]["dstuser"]        (optional)
      src ip         -> alert["data"]["srcip"]          (optional)
      mitre tactics  -> alert["rule"]["mitre"]["tactic"] (optional)
    """
    rule  = alert.get("rule", {})
    agent = alert.get("agent", {})
    data  = alert.get("data", {})
    mitre = rule.get("mitre", {})

    return {
        "rule_id":       rule.get("id"),
        "rule_level":    rule.get("level", 0),
        "rule_desc":     rule.get("description", ""),
        "agent_name":    agent.get("name"),
        "agent_ip":      agent.get("ip"),
        "srcuser":       data.get("srcuser"),
        "dstuser":       data.get("dstuser"),
        # srcip can live at data.srcip or at root (legacy)
        "srcip":         data.get("srcip") or alert.get("srcip"),
        "mitre_tactics": mitre.get("tactic", []),
        "mitre_ids":     mitre.get("id", []),
        "groups":        rule.get("groups", []),
        "timestamp":     alert.get("timestamp"),
        "full_log":      alert.get("full_log", ""),
    }


# -----------------------------
# 3. FETCH CONTEXT
# -----------------------------
def fetch_alert_context(alert: dict, alerts: list, max_results: int = 10) -> list:
    """
    Return related alerts using multiple Wazuh-aware criteria:
      - same rule id
      - same agent name or agent ip
      - same srcuser or srcip
      - overlapping MITRE tactic
    """
    f = extract_alert_fields(alert)

    related = []
    for a in alerts:
        if a is alert:
            continue
        af = extract_alert_fields(a)

        match = (
            (f["rule_id"]    and af["rule_id"]    == f["rule_id"])
            or (f["agent_ip"]   and af["agent_ip"]   == f["agent_ip"])
            or (f["agent_name"] and af["agent_name"] == f["agent_name"])
            or (f["srcuser"]    and af["srcuser"]    == f["srcuser"])
            or (f["srcip"]      and af["srcip"]      == f["srcip"])
            or bool(set(f["mitre_tactics"]) & set(af["mitre_tactics"]))
        )

        if match:
            related.append(a)

    return related[:max_results]


# -----------------------------
# 4. HEURISTIC SCORING
# -----------------------------
def compute_threat_score(alert: dict, context: list) -> int:
    """
    Score 0-100 based on:
      - number of corroborating alerts  (up to 40 pts)
      - Wazuh rule level  0-15          (up to 30 pts)
      - presence of MITRE techniques    (15 pts)
      - internal vs external source IP  (5 or 15 pts)
    """
    f           = extract_alert_fields(alert)
    occurrences = len(context)

    if occurrences >= 10:
        freq_score = 40
    elif occurrences >= 5:
        freq_score = 30
    elif occurrences >= 3:
        freq_score = 20
    elif occurrences >= 1:
        freq_score = 10
    else:
        freq_score = 0

    level       = int(f["rule_level"])
    level_score = min(int(level / 15 * 30), 30)

    mitre_score = 15 if f["mitre_ids"] else 0

    src_ip   = f["srcip"] or ""
    ip_score = 5 if (src_ip.startswith("192.168") or src_ip.startswith("10.")) else 15

    return min(freq_score + level_score + mitre_score + ip_score, 100)


# -----------------------------
# 5. SLIM CONTEXT FOR LLM
# -----------------------------
def slim_context(context: list, max_alerts: int = MAX_CONTEXT_FOR_LLM) -> list:
    """
    Reduce each context alert to the fields that matter for analysis,
    and cap the number of alerts sent to the LLM.
    Sending 10 full raw Wazuh alerts easily exceeds 4 000 tokens — this
    keeps the prompt under ~1 500 tokens regardless of dataset size.
    """
    slimmed = []
    for a in context[:max_alerts]:
        rule  = a.get("rule", {})
        agent = a.get("agent", {})
        data  = a.get("data", {})
        slimmed.append({
            "timestamp":   a.get("timestamp"),
            "rule_id":     rule.get("id"),
            "rule_level":  rule.get("level"),
            "description": rule.get("description"),
            "mitre":       rule.get("mitre", {}).get("id", []),
            "agent":       agent.get("name"),
            "srcuser":     data.get("srcuser"),
            "dstuser":     data.get("dstuser"),
            "command":     data.get("command"),
            "full_log":    a.get("full_log", "")[:300],   # truncate long logs
        })
    return slimmed


# -----------------------------
# 6. LLM ANALYSIS
# -----------------------------
def analyze_alert(alert: dict, context: list, score: int) -> dict:
    template = load_prompt_template()
    prompt   = template.format(
        alert   = json.dumps(alert,              indent=2, ensure_ascii=False),
        context = json.dumps(slim_context(context), indent=2, ensure_ascii=False),
        score   = score,
    )

    estimated_tokens = len(prompt) // 4
    print(f"[+] Prompt size: ~{estimated_tokens} tokens — sending to LLM...")

    response = llm.invoke(prompt)
    raw      = response.content.strip()

    # Strip markdown fences some models accidentally add
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[WARN] LLM returned non-JSON output: {e}")
        return {
            "summary":             "LLM response could not be parsed",
            "severity":            "unknown",
            "attack_type":         "unknown",
            "justification":       raw,
            "recommended_actions": [],
        }


# -----------------------------
# 7. MAIN AGENT
# -----------------------------
def run_agent(alert: dict) -> dict:
    print("[+] Loading alerts dataset...")
    alerts = load_alerts()
    print(f"[+] Loaded {len(alerts)} alerts from dataset")

    print("[+] Fetching context...")
    context = fetch_alert_context(alert, alerts)
    print(f"[+] Found {len(context)} related alerts")

    score = compute_threat_score(alert, context)
    print(f"[+] Threat Score: {score}/100")

    # Skip LLM only when there is truly nothing to analyse
    f = extract_alert_fields(alert)
    if len(context) == 0 and f["rule_level"] < 5 and not f["mitre_ids"]:
        print("[!] Not enough evidence -> skipping LLM")
        return {
            "alert":        alert,
            "context":      context,
            "threat_score": score,
            "analysis": {
                "summary":             "Not enough evidence to draw a conclusion.",
                "severity":            "low",
                "attack_type":         "none",
                "justification":       "No corroborating alerts, low rule level, and no MITRE technique.",
                "recommended_actions": [],
            },
        }

    print("[+] Running LLM analysis...")
    analysis = analyze_alert(alert, context, score)

    return {
        "alert":        alert,
        "context":      context,
        "threat_score": score,
        "analysis":     analysis,
    }


# -----------------------------
# 8. TEST  -  real Wazuh alert format
# -----------------------------
if __name__ == "__main__":
    # Taken directly from my_alerts.json structure
    sample_alert = {
        "timestamp": "2026-04-20T00:14:58.933+0100",
        "rule": {
            "level": 3,
            "description": "Successful sudo to ROOT executed.",
            "id": "5402",
            "mitre": {
                "id": ["T1548.003"],
                "tactic": ["Privilege Escalation", "Defense Evasion"],
                "technique": ["Sudo and Sudo Caching"]
            },
            "groups": ["syslog", "sudo"]
        },
        "agent": {
            "id": "000",
            "name": "Ubuntu24"
        },
        "manager": {"name": "Ubuntu24"},
        "full_log": (
            "Apr 19 23:14:58 Ubuntu24 sudo[6322]: rna : TTY=pts/0 ; "
            "PWD=/home/rna ; USER=root ; COMMAND=/usr/bin/systemctl status wazuh-manager"
        ),
        "data": {
            "srcuser": "rna",
            "dstuser": "root",
            "tty": "pts/0",
            "pwd": "/home/rna",
            "command": "/usr/bin/systemctl status wazuh-manager"
        },
        "location": "journald"
    }

    result = run_agent(sample_alert)

    print("\n====== FINAL RESULT ======\n")
    print(f"Threat Score : {result['threat_score']}/100")
    print(f"Context size : {len(result['context'])} related alerts")
    print("\nLLM Analysis:")
    print(json.dumps(result["analysis"], indent=2, ensure_ascii=False))