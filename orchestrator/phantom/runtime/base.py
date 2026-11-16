"""Runtime interface: where hardened container specs become decoys."""

from __future__ import annotations

from typing import Protocol

from ..models import ContainerSpec, DeployedDecoy


class Runtime(Protocol):
    name: str

    async def deploy(self, session_id: str, specs: list[ContainerSpec]) -> list[DeployedDecoy]: ...

    async def reap(self, session_id: str) -> int: ...

    async def reap_all(self) -> int: ...
