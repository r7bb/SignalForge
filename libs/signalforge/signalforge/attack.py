"""MITRE ATT&CK reference data used for incident presentation.

Only the tactics and the techniques the bundled detections reference are
included - enough to render a kill-chain view and to order an incident's
tactics the way an analyst expects to read them.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

#: Tactic slug -> (ATT&CK id, display name).  Ordered by kill-chain position.
TACTICS: Dict[str, Dict[str, str]] = {
    "reconnaissance": {"id": "TA0043", "name": "Reconnaissance"},
    "resource_development": {"id": "TA0042", "name": "Resource Development"},
    "initial_access": {"id": "TA0001", "name": "Initial Access"},
    "execution": {"id": "TA0002", "name": "Execution"},
    "persistence": {"id": "TA0003", "name": "Persistence"},
    "privilege_escalation": {"id": "TA0004", "name": "Privilege Escalation"},
    "defense_evasion": {"id": "TA0005", "name": "Defense Evasion"},
    "credential_access": {"id": "TA0006", "name": "Credential Access"},
    "discovery": {"id": "TA0007", "name": "Discovery"},
    "lateral_movement": {"id": "TA0008", "name": "Lateral Movement"},
    "collection": {"id": "TA0009", "name": "Collection"},
    "command_and_control": {"id": "TA0011", "name": "Command and Control"},
    "exfiltration": {"id": "TA0010", "name": "Exfiltration"},
    "impact": {"id": "TA0040", "name": "Impact"},
}

TACTIC_ORDER: List[str] = list(TACTICS)

#: Technique id -> display name.
TECHNIQUES: Dict[str, str] = {
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1136": "Create Account",
    "T1136.003": "Create Account: Cloud Account",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1556": "Modify Authentication Process",
    "T1556.006": "Modify Authentication Process: Multi-Factor Authentication",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1530": "Data from Cloud Storage",
    "T1567": "Exfiltration Over Web Service",
    "T1562": "Impair Defenses",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1069": "Permission Groups Discovery",
    "T1087": "Account Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1003": "OS Credential Dumping",
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1195": "Supply Chain Compromise",
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies",
}


def tactic_name(slug: str) -> str:
    entry = TACTICS.get(slug.lower())
    return entry["name"] if entry else slug.replace("_", " ").title()


def tactic_id(slug: str) -> Optional[str]:
    entry = TACTICS.get(slug.lower())
    return entry["id"] if entry else None


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id.upper(), technique_id.upper())


def sort_tactics(tactics: Sequence[str]) -> List[str]:
    """Order tactics by kill-chain position, unknown ones last."""
    unique = {t.lower() for t in tactics}
    known = [t for t in TACTIC_ORDER if t in unique]
    unknown = sorted(unique - set(known))
    return known + unknown


def kill_chain(tactics: Sequence[str]) -> List[Dict[str, str]]:
    """Render the ATT&CK path shown on the incident screen."""
    return [
        {"slug": slug, "id": tactic_id(slug) or "", "name": tactic_name(slug)}
        for slug in sort_tactics(tactics)
    ]


def describe_techniques(techniques: Sequence[str]) -> List[Dict[str, str]]:
    return [
        {
            "id": technique.upper(),
            "name": technique_name(technique),
            "url": "https://attack.mitre.org/techniques/%s/" % technique.upper().replace(".", "/"),
        }
        for technique in dict.fromkeys(t.upper() for t in techniques)
    ]
