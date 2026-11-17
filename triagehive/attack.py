"""MITRE ATT&CK reference data used to explain and order findings.

Author: Chandu Komme

Only the techniques the detection rules can produce are listed. Tactics are
ordered along the kill chain, which lets the correlation agent tell a story
("initial access -> execution -> command and control -> credential access ->
lateral movement") and reward incidents that progress through several stages.
"""

from __future__ import annotations

__author__ = "Chandu Komme"

TACTIC_ORDER = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
                "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
                "exfiltration", "impact"]

TECHNIQUES = {
    "T1566.002": ("Phishing: Spearphishing Link", "initial-access"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
    "T1569.002": ("System Services: Service Execution", "execution"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "persistence"),
    "T1098.003": ("Account Manipulation: Additional Cloud Roles", "privilege-escalation"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "credential-access"),
    "T1621": ("Multi-Factor Authentication Request Generation", "credential-access"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
    "T1530": ("Data from Cloud Storage", "collection"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
}


def tactic(technique: str) -> str:
    return TECHNIQUES.get(technique, ("Unknown", "unknown"))[1]


def name(technique: str) -> str:
    return TECHNIQUES.get(technique, (technique, "unknown"))[0]


def kill_chain(techniques: list[str]) -> list[str]:
    """Distinct tactics in kill-chain order."""
    seen = {tactic(t) for t in techniques} - {"unknown"}
    return [t for t in TACTIC_ORDER if t in seen]
