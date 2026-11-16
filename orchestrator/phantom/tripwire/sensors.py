"""Mocked perimeter sensor.

There is no packet capture here. Each scenario replays the event sequence a
real sensor (Zeek, Suricata, sshd auth logs) would report for that attack, and
the detectors downstream treat it exactly like live input.
"""

from __future__ import annotations

import random
from collections.abc import Iterator

from ..models import NetEvent, NetEventKind

# Roughly the head of nmap's default port frequency list.
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
             3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

COMMON_USERS = ["root", "admin", "ubuntu", "oracle", "postgres", "deploy", "git", "svc_backup"]

SCENARIOS = ("nmap_scan", "ssh_bruteforce", "full_intrusion", "poisoned_model")


def _nmap(src: str, t0: float, rng: random.Random) -> Iterator[NetEvent]:
    ports = TOP_PORTS[:]
    rng.shuffle(ports)  # nmap randomises probe order by default
    t = t0
    for port in ports:
        t += rng.uniform(0.02, 0.12)
        yield NetEvent(ts=t, src_ip=src, dst_port=port, kind=NetEventKind.SYN)
    # -sV follow-up against the ports that looked open
    for port in (22, 80, 3306):
        t += rng.uniform(0.2, 0.5)
        yield NetEvent(ts=t, src_ip=src, dst_port=port, kind=NetEventKind.BANNER_GRAB,
                       client_banner="Nmap-Service-Probe")


def _ssh_bruteforce(src: str, t0: float, rng: random.Random, succeed: bool) -> Iterator[NetEvent]:
    t = t0
    for i in range(14):
        t += rng.uniform(0.3, 0.9)
        user = "root" if i < 9 else rng.choice(COMMON_USERS)
        yield NetEvent(ts=t, src_ip=src, dst_port=22, kind=NetEventKind.SSH_AUTH_FAIL,
                       username=user, client_banner="SSH-2.0-libssh_0.10.6")
    if succeed:
        # The decoy bastion is meant to be broken into: it "accepts" a weak
        # account so the attacker commits to the fake environment.
        t += 0.8
        yield NetEvent(ts=t, src_ip=src, dst_port=22, kind=NetEventKind.SSH_AUTH_OK,
                       username="svc_backup", client_banner="SSH-2.0-libssh_0.10.6")


def scenario_events(name: str, src_ip: str, t0: float, seed: int = 7) -> list[NetEvent]:
    rng = random.Random(seed)  # noqa: S311 - simulation timing, not security
    if name == "nmap_scan":
        return list(_nmap(src_ip, t0, rng))
    if name == "ssh_bruteforce":
        return list(_ssh_bruteforce(src_ip, t0, rng, succeed=False))
    if name in ("full_intrusion", "poisoned_model"):
        scan = list(_nmap(src_ip, t0, rng))
        return scan + list(_ssh_bruteforce(src_ip, scan[-1].ts + 4.0, rng, succeed=True))
    raise ValueError(f"unknown scenario: {name}")
