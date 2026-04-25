import sys
sys.path.append(".")

from agents.agent4_correlation import agent4

# ── Real alert from data/alerts_today21_04.json (line 27) ──────────────────
# Trigger alert : vsftpd FTP session opened from 192.168.100.45
# Context       : preceded by sudo escalations (T1548.003) and followed by
#                 FTP anonymous login success (T1078) on web-server-01
#just a local test before building the full system

test_state = {
    # Main alert sent by Agent 1 (the triggering event)
    "alert": {
        "@timestamp"  : "2026-04-21T00:29:23.842+0100",
        "rule": {
            "level"       : 3,
            "description" : "vsftpd: FTP session opened.",
            "id"          : "11401",
            "groups"      : ["syslog", "vsftpd", "connection_attempt"]
        },
        "agent"  : {"id": "003", "name": "web-server-01", "ip": "192.168.100.50"},
        "manager": {"name": "Ubuntu24"},
        "id"     : "1776727763.18130",
        "full_log": "Tue Apr 21 00:29:23 2026 [pid 4192] CONNECT: Client \"::ffff:192.168.100.45\"",
        "decoder": {"parent": "vsftpd", "name": "vsftpd"},
        "data"   : {"action": "CONNECT", "srcip": "::ffff:192.168.100.45"},
        "location": "/var/log/vsftpd.log",
        # Extra fields used by the Markdown report (src_ip / dst_user)
        "src_ip"  : "192.168.100.45",
        "dst_user": "anonymous"
    },

    # Agent 1 summary : pattern detected across correlated events
    "context_summary": (
        "FTP connection from 192.168.100.45 to web-server-01 (192.168.100.50). "
        "Shortly before, user 'rna' performed multiple sudo escalations to root "
        "(T1548.003) to create /var/ftp/pub and copy sensitive files "
        "(data.txt, employees.csv). "
        "FTP anonymous login succeeded 7 seconds after the session opened (rule 11402, T1078). "
        "Possible data staging and exfiltration via anonymous FTP."
    ),

    # Agent 2 (tour1) : historical context about these IPs / rules
    "context_tour1": {
        "total_alerts"   : 12,
        "agent_involved" : "web-server-01",
        "src_ip"         : "192.168.100.45",
        "rules_fired"    : ["11401", "11402", "5402", "5501", "5502"],
        "related_alerts" : [
            {
                "timestamp"  : "2026-04-21T00:29:30.838+0100",
                "rule_id"    : "11402",
                "description": "vsftpd: FTP Authentication success.",
                "mitre"      : {"id": ["T1078"], "technique": ["Valid Accounts"]}
            },
            {
                "timestamp"  : "2026-04-21T00:30:46.545+0100",
                "rule_id"    : "5402",
                "description": "Successful sudo to ROOT executed.",
                "data"       : {"command": "/usr/bin/mkdir -p /var/ftp/pub"},
                "mitre"      : {"id": ["T1548.003"], "technique": ["Sudo and Sudo Caching"]}
            },
            {
                "timestamp"  : "2026-04-21T00:30:48.569+0100",
                "rule_id"    : "5402",
                "description": "Successful sudo to ROOT executed.",
                "data"       : {"command": "/usr/bin/tee /var/ftp/pub/employees.csv"},
                "mitre"      : {"id": ["T1548.003"], "technique": ["Sudo and Sudo Caching"]}
            }
        ]
    },

    # Agent 3 (tour2) : deep investigation results
    "results_tour2": {
        "threat_intel"   : "IP 192.168.100.45 is an internal host — possible insider threat or compromised workstation.",
        "file_staging"   : "Files employees.csv and data.txt copied to /var/ftp/pub (world-readable FTP directory).",
        "exfil_vector"   : "Anonymous FTP login succeeded — no credentials required to download staged files.",
        "privilege_abuse": "User 'rna' (uid=1001) used sudo 8 times in under 90 seconds to prepare the FTP directory."
    },

    # Required State fields (used by other agents / graph routing)
    "index_mapping"   : {},
    "questions_tour1" : [],
    "questions_tour2" : [],
    "tour2_required"  : True,
    "final_report"    : "",
    "risk_score"      : 0
}
# Run Agent 4
result = agent4.invoke(test_state)
print(f"\nScore  : {result['risk_score']}/10")
print(f"Report :\n{result['final_report']}")