"""Shared data models. Pydantic is used at every trust boundary."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NetEventKind(StrEnum):
    SYN = "syn"
    BANNER_GRAB = "banner_grab"
    SSH_AUTH_FAIL = "ssh_auth_fail"
    SSH_AUTH_OK = "ssh_auth_ok"


class NetEvent(BaseModel):
    """One observation from a perimeter sensor."""

    model_config = ConfigDict(frozen=True)

    ts: float
    src_ip: str
    dst_port: int = Field(ge=1, le=65535)
    kind: NetEventKind
    username: str | None = None
    client_banner: str | None = None


class AlertKind(StrEnum):
    PORT_SCAN = "port_scan"
    SSH_BRUTEFORCE = "ssh_bruteforce"


class Alert(BaseModel):
    id: str
    ts: float
    kind: AlertKind
    src_ip: str
    confidence: float = Field(ge=0, le=1)
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    techniques: list[str] = Field(default_factory=list)


class Footprint(BaseModel):
    """What we have learned about one source address so far."""

    src_ip: str
    first_seen: float
    last_seen: float
    probed_ports: list[int] = Field(default_factory=list)
    services_of_interest: list[str] = Field(default_factory=list)
    tooling: list[str] = Field(default_factory=list)
    usernames_tried: list[str] = Field(default_factory=list)
    auth_failures: int = 0
    scan_profile: str = "none"
    sophistication: int = Field(default=0, ge=0, le=100)


class ContainerSpec(BaseModel):
    """A fully hardened container request. Only the policy guard builds these."""

    model_config = ConfigDict(frozen=True)

    name: str
    image: str
    role: str
    hostname: str
    container_port: int
    environment: dict[str, str] = Field(default_factory=dict)
    tmpfs: dict[str, str] = Field(default_factory=dict)
    user: str | None = None
    mem_limit: str = "256m"
    pids_limit: int = 128
    nano_cpus: int = 500_000_000


class DeployedDecoy(BaseModel):
    id: str
    name: str
    image: str
    role: str
    hostname: str
    ip: str
    port: int
    hardening: list[str] = Field(default_factory=list)


class SessionState(StrEnum):
    DETECTED = "detected"
    PLANNING = "planning"
    DEPLOYED = "deployed"
    ENGAGED = "engaged"
    CLOSED = "closed"
    FAILED = "failed"


class Session(BaseModel):
    id: str
    src_ip: str
    opened_at: float
    state: SessionState = SessionState.DETECTED
    persona: str = ""
    alerts: list[Alert] = Field(default_factory=list)
    footprint: Footprint | None = None
    decoys: list[DeployedDecoy] = Field(default_factory=list)
    techniques: dict[str, int] = Field(default_factory=dict)
    plan_source: str = ""
    guard_rejections: int = 0
    commands: int = 0
    canary_hits: int = 0


class Event(BaseModel):
    """A single item on the grid's event stream (also what the dashboard sees)."""

    model_config = ConfigDict(frozen=True)

    seq: int
    ts: float
    kind: str
    session_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
