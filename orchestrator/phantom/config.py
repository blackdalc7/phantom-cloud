"""Runtime configuration. Everything comes from the environment, nothing is baked in."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHANTOM_", env_file=".env", extra="ignore")

    # Bearer token for the control API. If unset, a random one is generated at
    # startup, so there is never a default credential to forget about.
    api_token: SecretStr | None = None

    # Loopback by default: the dashboard's server-side proxy is the only client.
    host: str = "127.0.0.1"
    port: int = Field(default=8400, ge=1, le=65535)

    # "simulated" keeps the whole pipeline but stops short of touching Docker.
    runtime: Literal["simulated", "docker"] = "simulated"

    # >1 compresses scenario timings (tests and demos). Detection itself runs
    # on event timestamps, so scaling never changes what gets detected.
    time_scale: float = Field(default=1.0, gt=0, le=10_000)

    # Hard caps so a noisy attacker cannot make us exhaust the host.
    max_sessions: int = Field(default=6, ge=1, le=32)
    max_decoys_per_session: int = Field(default=4, ge=1, le=8)
    session_ttl_seconds: int = Field(default=900, ge=10)

    # Optional append-only evidence file (JSON lines).
    data_dir: Path | None = None

    # Key for honeytoken MACs. Ephemeral unless provided, which is fine for a
    # lab; set it if tokens must stay attributable across restarts.
    canary_key: SecretStr | None = None
