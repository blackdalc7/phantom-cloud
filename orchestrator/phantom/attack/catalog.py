"""The slice of MITRE ATT&CK (Enterprise) this grid can observe.

IDs and names follow attack.mitre.org. Techniques that belong to several
tactics are listed under the one that best fits how a decoy sees them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    severity: int  # 1 = noise, 2 = notable, 3 = critical


TACTICS: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

_T = Technique
TECHNIQUES: dict[str, Technique] = {t.id: t for t in (
    _T("T1595", "Active Scanning", "TA0043", 1),
    _T("T1078", "Valid Accounts", "TA0001", 3),
    _T("T1133", "External Remote Services", "TA0001", 2),
    _T("T1059.004", "Unix Shell", "TA0002", 2),
    _T("T1098.004", "SSH Authorized Keys", "TA0003", 3),
    _T("T1053.003", "Cron", "TA0003", 3),
    _T("T1136.001", "Create Local Account", "TA0003", 3),
    _T("T1548.003", "Sudo and Sudo Caching", "TA0004", 2),
    _T("T1070.003", "Clear Command History", "TA0005", 2),
    _T("T1070.004", "File Deletion", "TA0005", 2),
    _T("T1222.002", "Linux File Permissions Modification", "TA0005", 1),
    _T("T1110.001", "Password Guessing", "TA0006", 2),
    _T("T1110.003", "Password Spraying", "TA0006", 2),
    _T("T1552.001", "Credentials In Files", "TA0006", 3),
    _T("T1552.003", "Bash History", "TA0006", 2),
    _T("T1003.008", "/etc/passwd and /etc/shadow", "TA0006", 3),
    _T("T1046", "Network Service Discovery", "TA0007", 2),
    _T("T1018", "Remote System Discovery", "TA0007", 2),
    _T("T1082", "System Information Discovery", "TA0007", 1),
    _T("T1033", "System Owner/User Discovery", "TA0007", 1),
    _T("T1083", "File and Directory Discovery", "TA0007", 1),
    _T("T1057", "Process Discovery", "TA0007", 1),
    _T("T1016", "System Network Configuration Discovery", "TA0007", 1),
    _T("T1049", "System Network Connections Discovery", "TA0007", 1),
    _T("T1087.001", "Local Account Discovery", "TA0007", 1),
    _T("T1021", "Remote Services", "TA0008", 3),
    _T("T1021.004", "Remote Services: SSH", "TA0008", 3),
    _T("T1005", "Data from Local System", "TA0009", 2),
    _T("T1560.001", "Archive via Utility", "TA0009", 2),
    _T("T1105", "Ingress Tool Transfer", "TA0011", 3),
    _T("T1071.001", "Web Protocols", "TA0011", 2),
    _T("T1048.003", "Exfiltration Over Unencrypted Protocol", "TA0010", 3),
    _T("T1496", "Resource Hijacking", "TA0040", 3),
    _T("T1485", "Data Destruction", "TA0040", 3),
)}


def matrix() -> list[dict]:
    """Tactic columns with their techniques, in kill-chain order."""
    return [
        {"id": tid, "name": name,
         "techniques": [{"id": t.id, "name": t.name, "severity": t.severity}
                        for t in TECHNIQUES.values() if t.tactic == tid]}
        for tid, name in TACTICS
    ]
