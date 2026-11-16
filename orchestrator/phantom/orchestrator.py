"""The grid: turns a tripwire alert into a live, monitored decoy environment.

    sensor event -> detectors -> session -> LLM plan -> policy guard
                 -> hardened deploy -> attacker interaction -> ATT&CK mapping

Every step publishes to the event bus, which feeds both the dashboard and the
signed evidence ledger.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time

from .attack import TECHNIQUES, map_command
from .canary import CanaryMint
from .compose import evaluate, harden
from .config import Settings
from .deception import INTRUSION_PLAYBOOK, FakeShell
from .events import EventBus
from .llm import SYSTEM_PROMPT, LLMClient, MockLLM, build_brief, build_user_prompt
from .models import Alert, ContainerSpec, Footprint, NetEvent, Session, SessionState
from .runtime import DockerRuntime, Runtime, SimulatedRuntime
from .tripwire import FootprintTracker, PortScanDetector, SSHBruteForceDetector, scenario_events

log = logging.getLogger("phantom.grid")

PLAN_ATTEMPTS = 3
PERSONAS = ("Halcyon Freight Systems", "Northgate Mutual", "Verity Biolabs", "Orrin & Vale LLP")
ACTIVE = (SessionState.DETECTED, SessionState.PLANNING, SessionState.DEPLOYED,
          SessionState.ENGAGED)

# Used when the model fails the guard on every attempt. It goes through the
# same guard as model output, so the fallback can never drift from policy.
FALLBACK_COMPOSE = """\
services:
  vpn-gw-01:
    image: cowrie/cowrie:latest
    hostname: vpn-gw-01
    networks: [corp]
  intranet-web-01:
    image: nginxinc/nginx-unprivileged:1.27-alpine
    hostname: intranet-web-01
    networks: [corp]
networks:
  corp:
    internal: true
"""


class Grid:
    def __init__(self, settings: Settings | None = None, *, llm: LLMClient | None = None,
                 runtime: Runtime | None = None, bus: EventBus | None = None) -> None:
        self.settings = settings or Settings()
        self.bus = bus or EventBus()
        self.llm: LLMClient = llm or MockLLM()
        if runtime is None:
            runtime = DockerRuntime() if self.settings.runtime == "docker" else SimulatedRuntime()
        self.runtime: Runtime = runtime
        key = self.settings.canary_key
        self.canary = CanaryMint(key.get_secret_value().encode() if key else None)

        self.sessions: dict[str, Session] = {}
        self._by_source: dict[str, str] = {}
        self._shells: dict[str, FakeShell] = {}
        self._secrets: dict[str, dict[str, str]] = {}
        self._expanded: set[str] = set()
        self._engaging: dict[str, asyncio.Task] = {}
        self._tasks: set[asyncio.Task] = set()

        self._tracker = FootprintTracker()
        self._detectors = (PortScanDetector(), SSHBruteForceDetector())

    # -- lifecycle --------------------------------------------------------

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception():
            log.error("background task failed", exc_info=task.exception())

    async def start(self) -> None:
        self.bus.publish("grid.armed", runtime=self.runtime.name,
                         max_sessions=self.settings.max_sessions)
        self._spawn(self._reaper())

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        # Never leave decoys running once the thing watching them is gone.
        await self.runtime.reap_all()

    async def _reaper(self) -> None:
        while True:
            await asyncio.sleep(5)
            cutoff = time.time() - self.settings.session_ttl_seconds
            for s in list(self.sessions.values()):
                if s.state in ACTIVE and s.opened_at < cutoff:
                    await self.close(s.id, reason="ttl")

    async def _sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(seconds, 0) / self.settings.time_scale)

    # -- detection --------------------------------------------------------

    async def ingest(self, ev: NetEvent) -> list[Alert]:
        """Feed one sensor event through the tripwire."""
        footprint = self._tracker.update(ev)
        alerts = [a for d in self._detectors if (a := d.observe(ev))]
        for alert in alerts:
            await self._on_alert(alert, footprint)
        return alerts

    async def _on_alert(self, alert: Alert, footprint: Footprint) -> None:
        session = self.sessions.get(self._by_source.get(alert.src_ip, ""))
        is_new = session is None
        if is_new:
            if sum(s.state in ACTIVE for s in self.sessions.values()) >= self.settings.max_sessions:
                # Deception is a finite resource. Past the cap we still alert,
                # but do not let one noisy campaign spawn containers forever.
                self.bus.publish("grid.saturated", src_ip=alert.src_ip, alert=alert.model_dump())
                return
            digest = hashlib.sha256(alert.src_ip.encode()).digest()
            session = Session(id=secrets.token_hex(5), src_ip=alert.src_ip, opened_at=time.time(),
                              persona=PERSONAS[digest[0] % len(PERSONAS)])
            self.sessions[session.id] = session
            self._by_source[alert.src_ip] = session.id
            self.bus.publish("session.opened", session.id, src_ip=session.src_ip,
                             persona=session.persona)

        session.alerts.append(alert)
        session.footprint = footprint.model_copy(deep=True)
        self.bus.publish("tripwire.alert", session.id, alert=alert.model_dump(),
                         footprint=session.footprint.model_dump())
        for tid in alert.techniques:
            self._hit(session, tid, source="tripwire")
        if is_new:
            self._engaging[session.id] = self._spawn(self._engage(session))

    def _hit(self, session: Session, tid: str, source: str) -> None:
        tech = TECHNIQUES.get(tid)
        if tech is None:
            return
        session.techniques[tid] = session.techniques.get(tid, 0) + 1
        self.bus.publish("attack.technique", session.id, id=tid, name=tech.name,
                         tactic=tech.tactic, severity=tech.severity,
                         count=session.techniques[tid], source=source)

    def _set_state(self, session: Session, state: SessionState, **extra) -> None:
        session.state = state
        self.bus.publish("session.state", session.id, state=state.value, **extra)

    # -- planning and deployment -------------------------------------------

    def _secret(self, session_id: str, kind: str) -> str:
        # One token per kind per session, so the password in the web config is
        # the same one the database decoy is started with.
        bucket = self._secrets.setdefault(session_id, {})
        if kind not in bucket:
            bucket[kind] = self.canary.mint(session_id, kind)
        return bucket[kind]

    async def _plan(self, session: Session, mode: str = "initial",
                    requested_roles: list[str] | None = None) -> list[ContainerSpec]:
        assert session.footprint is not None
        room = self.settings.max_decoys_per_session - len(session.decoys)
        if room <= 0:
            return []
        brief = build_brief(session.footprint, session.persona, mode,
                            existing_roles=[d.role for d in session.decoys],
                            requested_roles=requested_roles)
        feedback: list[str] = []
        for attempt in range(1, PLAN_ATTEMPTS + 1):
            prompt = build_user_prompt(brief, feedback)
            self.bus.publish("llm.request", session.id, attempt=attempt, mode=mode,
                             prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest())
            raw = await self.llm.complete(SYSTEM_PROMPT, prompt)
            report = evaluate(raw, max_services=min(room, 4))
            self.bus.publish(
                "guard.verdict", session.id, attempt=attempt, mode=mode, accepted=report.ok,
                output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                violations=[{"rule": v.rule, "path": v.path, "detail": v.detail}
                            for v in report.violations[:25]],
                services=[{"name": s.name, "image": s.image} for s in report.services])
            if report.ok:
                session.plan_source = session.plan_source or "llm"
                return self._dedupe(session, harden(
                    report, session.id, lambda kind: self._secret(session.id, kind)))
            session.guard_rejections += 1
            # Tell the model what failed, as rule ids only. Echoing its own
            # text back would give injected content a second pass at the prompt.
            feedback = [f"{v.rule} at {v.path}" for v in report.violations[:20]]

        if mode != "initial":
            return []
        report = evaluate(FALLBACK_COMPOSE)
        session.plan_source = "fallback"
        self.bus.publish("guard.fallback", session.id, reason="model output rejected "
                         f"{PLAN_ATTEMPTS} times")
        return harden(report, session.id, lambda kind: self._secret(session.id, kind))

    @staticmethod
    def _dedupe(session: Session, specs: list[ContainerSpec]) -> list[ContainerSpec]:
        taken = {d.hostname for d in session.decoys} | {d.name for d in session.decoys}
        return [s for s in specs if s.hostname not in taken and s.name not in taken]

    async def _deploy(self, session: Session, specs: list[ContainerSpec]) -> None:
        for decoy in await self.runtime.deploy(session.id, specs):
            session.decoys.append(decoy)
            self.bus.publish("decoy.deployed", session.id, **decoy.model_dump())

    async def _engage(self, session: Session) -> None:
        try:
            self._set_state(session, SessionState.PLANNING)
            await self._sleep(0.6)
            specs = await self._plan(session)
            await self._deploy(session, specs)
            bastion = next((d for d in session.decoys if d.role == "ssh-bastion"),
                           session.decoys[0])
            self._shells[session.id] = FakeShell(
                hostname=bastion.hostname, persona=session.persona,
                secrets={k: self._secret(session.id, k)
                         for k in ("access_key", "api_token", "db_password")},
                peers=lambda: session.decoys)
            self._set_state(session, SessionState.DEPLOYED, plan_source=session.plan_source)
        except Exception as exc:  # noqa: BLE001 - any failure must end in cleanup
            log.exception("engagement failed for %s", session.id)
            await self.runtime.reap(session.id)
            self._set_state(session, SessionState.FAILED, error=type(exc).__name__)

    async def _expand(self, session: Session, command: str) -> None:
        """Grow the environment in the direction the intruder is looking."""
        wanted = ["cache"] if "6379" in command else ["database"]
        have = {d.role for d in session.decoys}
        wanted = [r for r in wanted if r not in have]
        if not wanted:
            return
        specs = await self._plan(session, mode="expand", requested_roles=wanted)
        if specs:
            await self._deploy(session, specs)
            self.bus.publish("grid.expanded", session.id, roles=[s.role for s in specs],
                             trigger=command[:120])

    # -- interaction ------------------------------------------------------

    async def exec(self, session_id: str, command: str, actor: str = "attacker") -> dict:
        """Run one command in the session's emulated shell and record it."""
        session, shell = self.sessions.get(session_id), self._shells.get(session_id)
        if session is None or shell is None or session.state not in (
                SessionState.DEPLOYED, SessionState.ENGAGED):
            raise LookupError("session has no live shell")
        if session.state == SessionState.DEPLOYED:
            self._set_state(session, SessionState.ENGAGED)

        techniques = map_command(command)
        # Internal recon is the cue to expand, before answering, so the new
        # decoy is already there for the scan to "find".
        if {"T1046", "T1018"} & set(techniques) and session_id not in self._expanded:
            self._expanded.add(session_id)
            await self._expand(session, command)

        prompt = shell.prompt
        output = shell.run(command)
        session.commands += 1
        self.bus.publish("shell.io", session_id, prompt=prompt, command=command, output=output,
                         techniques=techniques, actor=actor)
        for tid in techniques:
            self._hit(session, tid, source="shell")

        # A token in the *output* means the bait was read; a token in a later
        # *command* means stolen credentials are being used.
        for hit in self.canary.scan(output):
            self.bus.publish("canary.exposed", session_id, kind=hit.kind, token=_mask(hit.token))
        for hit in self.canary.scan(command):
            session.canary_hits += 1
            self.bus.publish("canary.triggered", session_id, kind=hit.kind,
                             token=_mask(hit.token), minted_for=hit.session_id)
        return {"prompt": prompt, "output": output, "techniques": techniques}

    async def _play(self, session: Session) -> None:
        for step in INTRUSION_PLAYBOOK:
            await self._sleep(step.pause)
            if session.state not in (SessionState.DEPLOYED, SessionState.ENGAGED):
                return
            db = next((d for d in session.decoys if d.role == "database"), None)
            bastion = session.decoys[0]
            await self.exec(session.id, step.command.format(
                subnet=bastion.ip.rsplit(".", 1)[0],
                db_host=db.hostname if db else "fin-db",
                db_password=self._secret(session.id, "db_password")))

    # -- scenarios (the mocked tripwire input) ------------------------------

    def start_scenario(self, name: str, src_ip: str) -> None:
        self._spawn(self._run_scenario(name, src_ip))

    async def _run_scenario(self, name: str, src_ip: str) -> None:
        self.bus.publish("scenario.started", scenario=name, src_ip=src_ip)
        if name == "poisoned_model" and isinstance(self.llm, MockLLM):
            self.llm.hostile_responses = 1
        events = scenario_events(name, src_ip, t0=time.time())
        previous = events[0].ts
        for ev in events:
            await self._sleep(ev.ts - previous)
            previous = ev.ts
            await self.ingest(ev)
        session = self.sessions.get(self._by_source.get(src_ip, ""))
        if session is None:
            return
        if session.id in self._engaging:
            await self._engaging[session.id]
        if name in ("full_intrusion", "poisoned_model") and session.state == SessionState.DEPLOYED:
            await self._play(session)

    async def close(self, session_id: str, reason: str = "operator") -> bool:
        session = self.sessions.get(session_id)
        if session is None or session.state not in ACTIVE:
            return False
        removed = await self.runtime.reap(session_id)
        self._shells.pop(session_id, None)
        self._by_source.pop(session.src_ip, None)
        self._set_state(session, SessionState.CLOSED, reason=reason, reaped=removed)
        return True


def _mask(token: str) -> str:
    # Enough to recognise a token on screen, not enough to reuse it.
    return token[:6] + "…" + token[-4:]
