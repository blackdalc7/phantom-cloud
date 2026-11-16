"""LLM wrapper.

`LLMClient` is the only thing the orchestrator knows about. `MockLLM` stands in
for a hosted model: it reads the same prompt a real model would get and answers
with a compose file, deterministically, so the pipeline is testable offline.
Swapping in a real provider means implementing one async method.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Protocol

import yaml

from ..compose.catalog import ROLE_TO_REF

_FOOTPRINT_RE = re.compile(r"<footprint>\s*(\{.*?\})\s*</footprint>", re.S)

_HOST_PREFIX = {"ssh-bastion": "vpn-gw", "intranet-web": "intranet-web", "database": "fin-db",
                "cache": "session-cache"}

# What a manipulated or simply careless model might send back. Used to prove
# the policy guard holds when the planner cannot be trusted.
HOSTILE_COMPOSE = """\
services:
  ops-agent:
    image: alpine:3.20
    privileged: true
    network_mode: host
    pid: host
    command: ["sleep", "infinity"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
    environment:
      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}
"""


class LLMClient(Protocol):
    async def complete(self, system: str, user: str) -> str: ...


class MockLLM:
    def __init__(self, hostile_responses: int = 0) -> None:
        # Number of upcoming calls that should return HOSTILE_COMPOSE.
        self.hostile_responses = hostile_responses
        self.calls: list[dict[str, str]] = []

    async def complete(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        if self.hostile_responses > 0:
            self.hostile_responses -= 1
            return HOSTILE_COMPOSE
        match = _FOOTPRINT_RE.search(user)
        brief = json.loads(match.group(1)) if match else {}
        return _render(brief)


def _pick_roles(brief: dict[str, Any]) -> list[str]:
    if brief.get("mode") == "expand":
        existing = set(brief.get("existing_roles", []))
        return [r for r in brief.get("requested_roles", []) if r in ROLE_TO_REF
                and r not in existing]
    interest = set(brief.get("services_of_interest", []))
    roles = ["ssh-bastion"]  # every environment has a way in
    if "http" in interest or len(roles) < 2:
        roles.append("intranet-web")
    # Hold the database back unless the scan was thorough: a careful intruder
    # finds it "by themselves" later, when the grid expands around them.
    if "mysql" in interest and brief.get("sophistication", 0) >= 70:
        roles.append("database")
    if "redis" in interest and brief.get("sophistication", 0) >= 70:
        roles.append("cache")
    return roles[:4]


def _render(brief: dict[str, Any]) -> str:
    # Stable per-attacker numbering so hostnames look assigned, not generated.
    seed = int(hashlib.sha256(str(brief.get("source", "")).encode()).hexdigest()[:4], 16)
    services: dict[str, Any] = {}
    for i, role in enumerate(_pick_roles(brief)):
        host = f"{_HOST_PREFIX[role]}-{(seed + i) % 4 + 1:02d}"
        svc: dict[str, Any] = {
            "image": ROLE_TO_REF[role],
            "hostname": host,
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "networks": ["corp"],
        }
        if role == "database":
            svc["environment"] = {"MYSQL_ROOT_PASSWORD": "{{canary:db_password}}",
                                  "MYSQL_DATABASE": "ledger"}
        services[host] = svc
    doc = {"services": services, "networks": {"corp": {"internal": True}}}
    return yaml.safe_dump(doc, sort_keys=False)
