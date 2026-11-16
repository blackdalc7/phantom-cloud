"""Dry-run runtime.

Runs the whole pipeline (plan, guard, harden, "deploy") without talking to
Docker. This is the default, so the project can be demoed on a laptop without
starting a single container.
"""

from __future__ import annotations

import hashlib

from ..compose.policy import HARDENING
from ..models import ContainerSpec, DeployedDecoy


class SimulatedRuntime:
    name = "simulated"

    def __init__(self) -> None:
        self._sessions: dict[str, list[DeployedDecoy]] = {}

    async def deploy(self, session_id: str, specs: list[ContainerSpec]) -> list[DeployedDecoy]:
        existing = self._sessions.setdefault(session_id, [])
        # One fake /24 per session, like the per-session bridge the real runtime creates.
        subnet = int(hashlib.sha256(session_id.encode()).hexdigest()[:2], 16) % 200 + 20
        deployed = []
        for spec in specs:
            host = 10 + len(existing)
            decoy = DeployedDecoy(
                id=hashlib.sha256(spec.name.encode()).hexdigest()[:12],
                name=spec.name, image=spec.image, role=spec.role, hostname=spec.hostname,
                ip=f"10.13.{subnet}.{host}", port=spec.container_port,
                hardening=list(HARDENING) + (["non-root user"] if spec.user else []),
            )
            existing.append(decoy)
            deployed.append(decoy)
        return deployed

    async def reap(self, session_id: str) -> int:
        return len(self._sessions.pop(session_id, []))

    async def reap_all(self) -> int:
        count = sum(len(v) for v in self._sessions.values())
        self._sessions.clear()
        return count
