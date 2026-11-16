"""Maps shell commands typed in a decoy to ATT&CK techniques.

Rule-based on purpose: a detection an analyst can read and argue with is worth
more here than a classifier nobody can explain.
"""

from __future__ import annotations

import re

from .catalog import TECHNIQUES

_RULES: list[tuple[str, str]] = [
    (r"\b(whoami|id|w|who|last)\b", "T1033"),
    (r"\b(uname|hostname|lsb_release)\b|/etc/(os-release|issue)|/proc/(version|cpuinfo)", "T1082"),
    (r"/etc/(passwd|shadow)", "T1003.008"),
    (r"/etc/passwd|\bgetent\s+passwd", "T1087.001"),
    (r"\b(ps|top|pstree)\b", "T1057"),
    (r"\b(ifconfig|route)\b|\bip\s+(a|addr|r|route)\b|/etc/(hosts|resolv\.conf)", "T1016"),
    (r"\b(netstat|ss|lsof)\b", "T1049"),
    (r"\b(ls|find|locate|tree|du)\b", "T1083"),
    (r"\.bash_history|\bhistory\b(?!\s+-c)", "T1552.003"),
    (r"\.aws/credentials|config\.php|\.env\b|id_rsa|\.pgpass|\.my\.cnf|\bgrep\b.*passw",
     "T1552.001"),
    (r"\bsudo\b", "T1548.003"),
    (r"\b(nmap|masscan|nc|ncat|netcat)\b", "T1046"),
    (r"\b(ping|arp|nmap\s+-sn)\b|/dev/tcp/", "T1018"),
    (r"\bssh\s+[\w.-]+@|\bscp\b", "T1021.004"),
    (r"\b(mysql|psql|redis-cli|mongosh?)\b.*\s-h\s", "T1021"),
    (r"\b(wget|curl|tftp)\b.*\b(https?|ftp)://", "T1105"),
    (r"\b(wget|curl)\b.*https?://", "T1071.001"),
    (r"\bcurl\b.*(-F|--data|-d|-T|--upload-file)\b|\bnc\b.*<", "T1048.003"),
    (r"\b(tar|zip|gzip|7z)\b", "T1560.001"),
    (r"\b(cat|cp|tar)\b.*(/opt/backup|/var/backups|\.sql|\.csv)", "T1005"),
    (r"authorized_keys", "T1098.004"),
    (r"\bcrontab\b|/etc/cron", "T1053.003"),
    (r"\b(useradd|adduser)\b", "T1136.001"),
    (r"\bhistory\s+-c\b|unset\s+HISTFILE|>\s*~?/?\S*\.bash_history", "T1070.003"),
    (r"\b(rm|shred|unlink)\b", "T1070.004"),
    (r"\b(chmod|chown)\b", "T1222.002"),
    (r"\b(xmrig|minerd|cpuminer)\b|stratum\+tcp", "T1496"),
    (r"\brm\s+-[a-z]*r[a-z]*f?\s+/(?:\s|$|\*)|\bmkfs\b|\bdd\b.*of=/dev/", "T1485"),
]
_COMPILED = [(re.compile(pattern), tid) for pattern, tid in _RULES]


def map_command(command: str) -> list[str]:
    """Technique IDs matched by one command line, de-duplicated, in rule order."""
    hits: list[str] = []
    for pattern, tid in _COMPILED:
        if tid not in hits and pattern.search(command):
            hits.append(tid)
    # Anything typed into the decoy shell is, by definition, shell execution.
    return ["T1059.004", *hits] if command.strip() else []


if any(tid not in TECHNIQUES for _, tid in _RULES):  # fail at import, not mid-incident
    raise RuntimeError("attack mapper references a technique missing from the catalog")
