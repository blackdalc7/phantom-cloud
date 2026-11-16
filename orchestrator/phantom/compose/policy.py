"""Policy guard for LLM-generated Docker Compose.

The model's output is treated like any other untrusted input. It goes through
two stages:

1. evaluate(): parse the YAML defensively and reject anything outside a small
   allowlist. A file asking for `privileged`, a host mount or an unknown image
   never gets further than this function.
2. harden(): the accepted file is *not* handed to Docker. We read only the
   decisions we want from it (which catalog images, what hostnames) and build
   the container request ourselves with fixed security settings.

So a compose file has to be clean to be accepted, and even then its own
security options are ignored in favour of ours.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..models import ContainerSpec
from .catalog import CATALOG

MAX_BYTES = 16_384
MAX_SERVICES = 4

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_ENV_VALUE_RE = re.compile(r"^[A-Za-z0-9 ._:/@+=,-]{0,128}$")
_CANARY_RE = re.compile(r"^\{\{canary:(db_password|access_key|api_token)\}\}$")

_TOP_ALLOWED = {"services", "networks", "name"}
_SERVICE_ALLOWED = {
    "image", "hostname", "environment", "expose", "networks", "labels", "read_only", "cap_drop",
    "security_opt", "mem_limit", "pids_limit", "cpus", "tmpfs", "user", "restart", "depends_on",
}
# Keys that would weaken isolation, each with the reason it is refused.
_SERVICE_FORBIDDEN = {
    "privileged": "gives the container full control of the host kernel",
    "volumes": "host paths (including docker.sock) must never be mounted",
    "volumes_from": "would inherit another container's mounts",
    "cap_add": "decoys run with every capability dropped",
    "devices": "exposes host devices",
    "device_cgroup_rules": "exposes host devices",
    "network_mode": "host or shared network namespaces break isolation",
    "pid": "shares the host process namespace",
    "ipc": "shares the host IPC namespace",
    "uts": "shares the host UTS namespace",
    "userns_mode": "disables user namespace remapping",
    "cgroup_parent": "escapes resource accounting",
    "sysctls": "changes kernel parameters",
    "ports": "decoys are never published on a host interface",
    "build": "images come from the catalog, never from a build context",
    "command": "would replace the image's vetted entrypoint",
    "entrypoint": "would replace the image's vetted entrypoint",
    "env_file": "reads files from the orchestrator host",
    "extends": "pulls in configuration from other files",
    "extra_hosts": "can point the decoy at real hosts",
    "links": "legacy cross-container wiring",
    "secrets": "reads files from the orchestrator host",
    "configs": "reads files from the orchestrator host",
    "runtime": "selects an alternative container runtime",
    "dns": "decoys have no egress and need no resolver",
}
_NETWORK_ALLOWED = {"internal", "driver", "labels"}


@dataclass(frozen=True)
class Violation:
    rule: str
    path: str
    detail: str


@dataclass(frozen=True)
class ServiceRequest:
    name: str
    image: str
    hostname: str
    environment: dict[str, str]


@dataclass
class PolicyReport:
    violations: list[Violation] = field(default_factory=list)
    services: list[ServiceRequest] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def add(self, rule: str, path: str, detail: str) -> None:
        self.violations.append(Violation(rule, path, detail))


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys.

    PyYAML normally keeps the last duplicate silently. That is the classic way
    to show a validator one value and a second parser another, so we refuse it.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError(f"duplicate key: {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _parse(raw: str, report: PolicyReport) -> dict[str, Any] | None:
    if len(raw.encode("utf-8", errors="replace")) > MAX_BYTES:
        report.add("yaml.size", "$", f"document is larger than {MAX_BYTES} bytes")
        return None
    try:
        for token in yaml.scan(raw):
            # Anchors/aliases allow exponential expansion ("billion laughs")
            # and custom tags have no business in a compose file.
            if isinstance(token, yaml.AnchorToken | yaml.AliasToken | yaml.TagToken):
                report.add("yaml.feature", "$", "anchors, aliases and tags are not allowed")
                return None
        doc = yaml.load(raw, Loader=_StrictLoader)  # noqa: S506 - subclass of SafeLoader
    except yaml.YAMLError as exc:
        report.add("yaml.parse", "$", str(exc).splitlines()[0][:160])
        return None
    if not isinstance(doc, dict):
        report.add("yaml.shape", "$", "top level must be a mapping")
        return None
    return doc


def evaluate(raw: str, max_services: int = MAX_SERVICES) -> PolicyReport:
    report = PolicyReport()
    doc = _parse(raw, report)
    if doc is None:
        return report

    for key in doc:
        if key not in _TOP_ALLOWED:
            report.add("top.key", str(key), "top-level key is not allowed")

    networks = _check_networks(doc.get("networks"), report)

    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        report.add("services.missing", "services", "at least one service is required")
        return report
    if len(services) > max_services:
        report.add("services.count", "services", f"at most {max_services} services per plan")

    hostnames: set[str] = set()
    for name, body in services.items():
        path = f"services.{name}"
        if not isinstance(name, str) or not _NAME_RE.match(name):
            report.add("service.name", path, "service names must be short lowercase labels")
            continue
        if not isinstance(body, dict):
            report.add("service.shape", path, "service must be a mapping")
            continue
        request = _check_service(name, body, networks, report)
        if request is None:
            continue
        if request.hostname in hostnames:
            report.add("service.hostname", f"{path}.hostname", "hostnames must be unique")
        hostnames.add(request.hostname)
        report.services.append(request)

    if not report.ok:
        report.services.clear()  # never hand back a partially valid plan
    return report


def _check_networks(networks: Any, report: PolicyReport) -> set[str]:
    declared: set[str] = set()
    if networks is None:
        return declared
    if not isinstance(networks, dict):
        report.add("network.shape", "networks", "networks must be a mapping")
        return declared
    for name, body in networks.items():
        path = f"networks.{name}"
        declared.add(str(name))
        if not isinstance(body, dict):
            report.add("network.internal", path, "network must set internal: true")
            continue
        for key in body:
            if key not in _NETWORK_ALLOWED:
                report.add("network.key", f"{path}.{key}", "network option is not allowed")
        if body.get("internal") is not True:
            # internal: true removes the default route, so a decoy that gets
            # compromised cannot be used to attack anything outside the grid.
            report.add("network.internal", path, "network must set internal: true")
        if body.get("driver", "bridge") != "bridge":
            report.add("network.driver", f"{path}.driver", "only the bridge driver is allowed")
    return declared


def _check_service(name: str, body: dict[str, Any], networks: set[str],
                   report: PolicyReport) -> ServiceRequest | None:
    path = f"services.{name}"
    before = len(report.violations)

    for key in body:
        if key in _SERVICE_FORBIDDEN:
            report.add("service.forbidden", f"{path}.{key}", _SERVICE_FORBIDDEN[key])
        elif key not in _SERVICE_ALLOWED:
            report.add("service.unknown", f"{path}.{key}", "key is not on the allowlist")

    image = body.get("image")
    spec = CATALOG.get(image) if isinstance(image, str) else None
    if spec is None:
        report.add("image.allowlist", f"{path}.image", "image is not in the decoy catalog")

    hostname = body.get("hostname", name)
    if not isinstance(hostname, str) or not _NAME_RE.match(hostname):
        report.add("service.hostname", f"{path}.hostname", "hostname must be a lowercase label")
        hostname = name

    environment = _check_environment(body.get("environment"), spec, path, report)

    if "expose" in body and spec is not None:
        exposed = body["expose"]
        if not isinstance(exposed, list) or any(str(p) != str(spec.port) for p in exposed):
            report.add("service.expose", f"{path}.expose",
                       f"only the image's service port ({spec.port}) may be exposed")
    if body.get("read_only", True) is not True:
        report.add("service.read_only", f"{path}.read_only", "root filesystem must be read-only")
    if "cap_drop" in body and body["cap_drop"] != ["ALL"]:
        report.add("service.cap_drop", f"{path}.cap_drop", "cap_drop must be exactly [ALL]")
    for opt in _as_list(body.get("security_opt")):
        # seccomp/apparmor "unconfined" are the usual ways to quietly widen a sandbox.
        if opt not in ("no-new-privileges:true", "no-new-privileges=true", "no-new-privileges"):
            report.add("service.security_opt", f"{path}.security_opt",
                       f"security option {str(opt)[:40]!r} is not allowed")
    user = body.get("user")
    if user is not None and str(user).split(":")[0] in ("0", "root"):
        report.add("service.user", f"{path}.user", "decoys must not run as root")
    if body.get("restart", "no") not in ("no", "on-failure"):
        report.add("service.restart", f"{path}.restart", "decoys must not restart themselves")
    for mount in _as_list(body.get("tmpfs")):
        if spec is not None and str(mount).split(":")[0] not in spec.writable:
            report.add("service.tmpfs", f"{path}.tmpfs", "tmpfs path is not needed by this image")
    for net in _as_list(body.get("networks")):
        if net not in networks:
            report.add("service.network", f"{path}.networks",
                       "service references an undeclared network")
    labels = body.get("labels") or {}
    if not isinstance(labels, dict):
        report.add("service.labels", f"{path}.labels", "labels must be a mapping")
    elif any(str(k).startswith("phantom.") for k in labels):
        # phantom.* labels decide what the reaper may remove; only we set them.
        report.add("service.labels", f"{path}.labels", "the phantom.* label namespace is reserved")

    if len(report.violations) > before or spec is None:
        return None
    return ServiceRequest(name=name, image=spec.ref, hostname=hostname, environment=environment)


def _check_environment(env: Any, spec, path: str, report: PolicyReport) -> dict[str, str]:
    if env is None:
        return {}
    if isinstance(env, list):
        pairs = dict(str(item).partition("=")[::2] for item in env)
    elif isinstance(env, dict):
        pairs = {str(k): "" if v is None else str(v) for k, v in env.items()}
    else:
        report.add("env.shape", f"{path}.environment", "environment must be a mapping or list")
        return {}
    clean: dict[str, str] = {}
    for key, value in pairs.items():
        kpath = f"{path}.environment.{key[:40]}"
        if not _ENV_KEY_RE.match(key) or (spec is not None and key not in spec.env_allow):
            report.add("env.key", kpath, "variable is not allowed for this image")
        elif _CANARY_RE.match(value):
            clean[key] = value
        elif "$" in value or not _ENV_VALUE_RE.match(value):
            # `${VAR}` would be interpolated from the orchestrator's own
            # environment by compose tooling, leaking host secrets into a decoy.
            report.add("env.value", kpath, "value has disallowed characters or interpolation")
        else:
            clean[key] = value
    return clean


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


HARDENING = ("cap_drop=ALL", "no-new-privileges", "read-only rootfs",
             "internal network (no egress)", "no host ports", "pids/memory/cpu limits")


def harden(report: PolicyReport, session_id: str,
           mint_canary: Callable[[str], str]) -> list[ContainerSpec]:
    """Turn accepted service requests into container specs with fixed security settings."""
    if not report.ok:
        raise ValueError("refusing to harden a rejected plan")
    specs = []
    for req in report.services:
        image = CATALOG[req.image]
        env = {}
        for key, value in req.environment.items():
            m = _CANARY_RE.match(value)
            # Secrets are minted here, per session. The model only ever sees a placeholder.
            env[key] = mint_canary(m.group(1)) if m else value
        specs.append(ContainerSpec(
            name=f"phantom-{session_id}-{req.name}",
            image=image.ref, role=image.role, hostname=req.hostname, container_port=image.port,
            environment=env, user=image.user, mem_limit=image.mem_limit,
            tmpfs={p: "rw,noexec,nosuid,nodev,size=64m" for p in image.writable},
        ))
    return specs
