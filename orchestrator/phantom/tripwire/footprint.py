"""Builds a per-source profile of what an attacker is looking for."""

from __future__ import annotations

import re
from collections import OrderedDict

from ..models import Footprint, NetEvent, NetEventKind

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 2222: "ssh", 80: "http", 443: "http", 8080: "http", 8443: "http",
    3306: "mysql", 5432: "postgres", 6379: "redis", 445: "smb", 3389: "rdp",
    9200: "elasticsearch", 27017: "mongodb",
}

_TOOL_HINTS = (("libssh", "hydra"), ("paramiko", "paramiko-script"), ("nmap", "nmap"),
               ("go", "go-ssh-scanner"), ("medusa", "medusa"))

MAX_SOURCES = 4096
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_label(value: str, limit: int = 32) -> str:
    """Reduce attacker-supplied text to a boring identifier.

    Usernames and client banners end up inside the LLM prompt. Stripping them
    to [A-Za-z0-9._-] and truncating removes the room needed to smuggle
    instructions in (prompt injection via a crafted SSH username).
    """
    return _UNSAFE.sub("", value)[:limit]


class FootprintTracker:
    def __init__(self) -> None:
        self._by_source: OrderedDict[str, Footprint] = OrderedDict()

    def update(self, ev: NetEvent) -> Footprint:
        fp = self._by_source.get(ev.src_ip)
        if fp is None:
            fp = Footprint(src_ip=ev.src_ip, first_seen=ev.ts, last_seen=ev.ts)
            self._by_source[ev.src_ip] = fp
            if len(self._by_source) > MAX_SOURCES:
                self._by_source.popitem(last=False)
        self._by_source.move_to_end(ev.src_ip)
        fp.last_seen = max(fp.last_seen, ev.ts)

        if ev.dst_port not in fp.probed_ports and len(fp.probed_ports) < 256:
            fp.probed_ports.append(ev.dst_port)
        service = PORT_SERVICES.get(ev.dst_port)
        if service and service not in fp.services_of_interest:
            fp.services_of_interest.append(service)

        if ev.kind in (NetEventKind.SYN, NetEventKind.BANNER_GRAB):
            self._note_tool(fp, "nmap")
            if ev.kind == NetEventKind.BANNER_GRAB:
                fp.scan_profile = "version_detection"
            elif fp.scan_profile == "none":
                fp.scan_profile = "port_sweep"
        if ev.kind == NetEventKind.SSH_AUTH_FAIL:
            fp.auth_failures += 1
        if ev.username:
            name = sanitize_label(ev.username)
            if name and name not in fp.usernames_tried and len(fp.usernames_tried) < 12:
                fp.usernames_tried.append(name)
        if ev.client_banner:
            lowered = ev.client_banner.lower()
            for needle, tool in _TOOL_HINTS:
                if needle in lowered:
                    self._note_tool(fp, tool)

        fp.sophistication = self._score(fp)
        return fp

    def get(self, src_ip: str) -> Footprint | None:
        return self._by_source.get(src_ip)

    @staticmethod
    def _note_tool(fp: Footprint, tool: str) -> None:
        if tool not in fp.tooling:
            fp.tooling.append(tool)

    @staticmethod
    def _score(fp: Footprint) -> int:
        # Rough heuristic used to decide how much bait to lay out: breadth of
        # recon, version fingerprinting and multi-stage behaviour all add up.
        score = min(len(fp.probed_ports), 40)
        score += 20 if fp.scan_profile == "version_detection" else 0
        score += 15 if fp.auth_failures and len(fp.probed_ports) > 5 else 0
        score += 5 * min(len(fp.tooling), 3)
        return min(score, 100)
