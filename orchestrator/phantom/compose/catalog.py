"""The only images the grid will ever run.

The LLM chooses *which* decoys to deploy, but it chooses from this list. An
image reference that is not here is rejected before Docker hears about it, so
a manipulated model cannot pull an arbitrary image.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DecoyImage:
    ref: str                      # exact repo:tag the compose file must use
    role: str                     # what the decoy pretends to be
    port: int                     # the service port inside the container
    user: str | None = None       # non-root uid:gid to run as
    writable: tuple[str, ...] = ()  # tmpfs mounts needed with a read-only rootfs
    env_allow: frozenset[str] = field(default_factory=frozenset)
    mem_limit: str = "128m"


CATALOG: dict[str, DecoyImage] = {
    img.ref: img
    for img in (
        DecoyImage(ref="cowrie/cowrie:latest", role="ssh-bastion", port=2222,
                   writable=("/tmp",), mem_limit="256m"),  # noqa: S108
        DecoyImage(ref="nginxinc/nginx-unprivileged:1.27-alpine", role="intranet-web", port=8080,
                   user="101:101", writable=("/tmp",)),  # noqa: S108
        DecoyImage(ref="mysql:8.4", role="database", port=3306, user="999:999",
                   writable=("/var/lib/mysql", "/var/run/mysqld", "/tmp"),  # noqa: S108
                   env_allow=frozenset({"MYSQL_ROOT_PASSWORD", "MYSQL_DATABASE"}),
                   mem_limit="512m"),
        DecoyImage(ref="redis:7.4-alpine", role="cache", port=6379, user="999:1000",
                   writable=("/data",)),
    )
}

ROLE_TO_REF = {img.role: img.ref for img in CATALOG.values()}
