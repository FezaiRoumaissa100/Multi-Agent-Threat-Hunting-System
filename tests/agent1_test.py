import sys
import os
import json
import logging

# Ajout du root au path pour importer les agents
sys.path.append(".")

from agents.agent1_investigation import run_round1, run_analyse_contexte

# Configuration du logging pour voir les étapes
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s — %(message)s')
logger = logging.getLogger("TestAgent1_FTP")

# 1. Alerte réelle : Session FTP ouverte
ftp_alert = {
    "@timestamp": "2026-04-21T00:29:23.842+0100",
    "rule": {
        "level": 3,
        "description": "vsftpd: FTP session opened.",
        "id": "11401",
        "groups": ["syslog", "vsftpd", "connection_attempt"]
    },
    "agent": {"id": "003", "name": "web-server-01", "ip": "192.168.100.50"},
    "full_log": "Tue Apr 21 00:29:23 2026 [pid 4192] CONNECT: Client \"::ffff:192.168.100.45\"",
    "data": {"action": "CONNECT", "srcip": "::ffff:192.168.100.45"},
    "src_ip": "192.168.100.45",
    "dst_user": "anonymous"
}

# 2. Contexte simulé (ce que l'Agent 3 trouverait après le Round 1)
# On simule ici la découverte des sudo escalations et de l'auth success
simulated_context_round1 = [
    {
        "timestamp": "2026-04-21T00:29:30.838+0100",
        "rule_id": "11402",
        "description": "vsftpd: FTP Authentication success (anonymous).",
        "src_ip": "192.168.100.45"
    },
    {
        "timestamp": "2026-04-21T00:30:46.545+0100",
        "rule_id": "5402",
        "description": "Successful sudo to ROOT executed.",
        "data": {"command": "/usr/bin/mkdir -p /var/ftp/pub"},
        "user": "rna"
    },
    {
        "timestamp": "2026-04-21T00:30:48.569+0100",
        "rule_id": "5402",
        "description": "Successful sudo to ROOT executed.",
        "data": {"command": "/usr/bin/tee /var/ftp/pub/employees.csv"},
        "user": "rna"
    }
]

def test_agent1_full_cycle():
    print("\n" + "="*60)
    print("  TEST AGENT 1 — Scenario: FTP Exfiltration")
    print("="*60)

    # --- ÉTAPE 1 : ROUND 1 ---
    print("\n[Étape 1] Génération des questions Round 1...")
    initial_state = {"alert": ftp_alert, "context_round1": None}
    
    # Appel de la fonction de l'agent 1
    state_after_r1 = run_round1(initial_state)
    
    print(f"✓ Entités : {state_after_r1.get('entites_extraites')}")
    print(f"✓ Questions : {json.dumps(state_after_r1.get('questions_round1'), indent=2, ensure_ascii=False)}")

    # --- ÉTAPE 2 : ANALYSE DU CONTEXTE ---
    print("\n[Étape 2] Analyse du contexte (Simulation détection Sudo + FTP)...")
    
    # On injecte le contexte simulé pour voir la décision de l'agent
    analysis_state = {
        "alert": ftp_alert,
        "context_round1": simulated_context_round1
    }
    
    state_final = run_analyse_contexte(analysis_state)
    
    print(f"✓ Justification : {state_final.get('justification')}")
    print(f"✓ Questions archives (Round 2) : {json.dumps(state_final.get('questions_round2'), indent=2, ensure_ascii=False)}")
    print(f"✓ Résumé contexte : {state_final.get('context_summary')}")

if __name__ == "__main__":
    test_agent1_full_cycle()