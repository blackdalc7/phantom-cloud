"""Docker runtime.

Takes hardened specs from the policy guard and starts them with the Docker SDK.
The isolation settings below are fixed in code: nothing from the LLM output can
reach them.

Every object we create carries `phantom.managed=true`, and cleanup only ever
selects by that label, so the reaper cannot touch containers it did not start.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..compose.catalog import CATALOG
from ..compose.policy import HARDENING
from ..models import ContainerSpec, DeployedDecoy

MANAGED = "phantom.managed"
SESSION = "phantom.session"


class DockerRuntime:
    name = "docker"

    def __init__(self, client: Any | None = None) -> None:
        if client is None:
            import docker  # imported lazily so the simulated mode has no Docker dependency

            client = docker.from_env()
        self._client = client

    async def deploy(self, session_id: str, specs: list[ContainerSpec]) -> list[DeployedDecoy]:
        # The SDK is blocking; keep it off the event loop.
        return await asyncio.to_thread(self._deploy, session_id, specs)

    async def reap(self, session_id: str) -> int:
        return await asyncio.to_thread(self._reap, {MANAGED: "true", SESSION: session_id})

    async def reap_all(self) -> int:
        return await asyncio.to_thread(self._reap, {MANAGED: "true"})

    def _deploy(self, session_id: str, specs: list[ContainerSpec]) -> list[DeployedDecoy]:
        labels = {MANAGED: "true", SESSION: session_id}
        net_name = f"phantom-{session_id}"
        if not self._client.networks.list(names=[net_name]):
            # internal=True: no default gateway, so nothing in here can reach
            # the internet or the host's LAN. One network per attacker also
            # keeps separate intrusions from seeing each other.
            self._client.networks.create(net_name, driver="bridge", internal=True, labels=labels)

        deployed = []
        for spec in specs:
            if spec.image not in CATALOG:
                # The guard already checked this; refuse again at the last hop.
                raise PermissionError(f"image not in catalog: {spec.image}")
            container = self._client.containers.run(
                spec.image,
                name=spec.name,
                hostname=spec.hostname,
                detach=True,
                network=net_name,
                labels={**labels, "phantom.role": spec.role},
                environment=dict(spec.environment),
                user=spec.user,
                privileged=False,
                cap_drop=["ALL"],                         # no kernel capabilities at all
                security_opt=["no-new-privileges:true"],  # setuid binaries can't escalate
                read_only=True,                           # nothing persists in the image
                tmpfs=dict(spec.tmpfs),
                mem_limit=spec.mem_limit,
                memswap_limit=spec.mem_limit,             # no swap on top of the limit
                pids_limit=spec.pids_limit,               # fork bombs stay small
                nano_cpus=spec.nano_cpus,
                ipc_mode="private",
                init=True,
                restart_policy={"Name": "no"},
            )
            container.reload()
            nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            deployed.append(DeployedDecoy(
                id=container.id[:12], name=spec.name, image=spec.image, role=spec.role,
                hostname=spec.hostname, ip=nets.get(net_name, {}).get("IPAddress", ""),
                port=spec.container_port,
                hardening=list(HARDENING) + (["non-root user"] if spec.user else []),
            ))
        return deployed

    def _reap(self, labels: dict[str, str]) -> int:
        selector = {"label": [f"{k}={v}" for k, v in labels.items()]}
        removed = 0
        for container in self._client.containers.list(all=True, filters=selector):
            container.remove(force=True)
            removed += 1
        for network in self._client.networks.list(filters=selector):
            network.remove()
        return removed
