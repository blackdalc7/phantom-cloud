"""End-to-end runs of the grid in simulated mode (mock sensor, mock LLM, dry-run runtime)."""

from conftest import wait_for

from phantom.config import Settings
from phantom.evidence import verify_head
from phantom.llm import SYSTEM_PROMPT, MockLLM
from phantom.models import SessionState
from phantom.orchestrator import Grid
from phantom.tripwire import scenario_events


def kinds(grid, session_id=None):
    return [e.kind for e in grid.bus.history() if session_id in (None, e.session_id)]


def only_session(grid):
    assert len(grid.sessions) == 1
    return next(iter(grid.sessions.values()))


async def run_to_completion(grid, scenario, src="203.0.113.77"):
    grid.start_scenario(scenario, src)
    await wait_for(lambda: len(grid._tasks) == 1)  # only the TTL reaper is left
    return only_session(grid)


async def test_port_scan_opens_a_session_and_deploys_decoys(grid):
    session = await run_to_completion(grid, "nmap_scan")
    assert session.state == SessionState.DEPLOYED
    assert session.plan_source == "llm"
    assert {d.role for d in session.decoys} == {"ssh-bastion", "intranet-web"}
    order = kinds(grid, session.id)
    assert order.index("session.opened") < order.index("tripwire.alert") \
        < order.index("guard.verdict") < order.index("decoy.deployed")


async def test_bruteforce_alone_also_triggers_the_grid(grid):
    session = await run_to_completion(grid, "ssh_bruteforce")
    assert session.state == SessionState.DEPLOYED
    assert "T1110.001" in session.techniques


async def test_full_intrusion_walks_the_kill_chain(grid):
    session = await run_to_completion(grid, "full_intrusion")
    assert session.state == SessionState.ENGAGED
    assert session.commands == 21

    # Internal recon made the grid grow a database for the intruder to find.
    assert "database" in {d.role for d in session.decoys}
    assert "grid.expanded" in kinds(grid)

    tactics_hit = {e.data["tactic"] for e in grid.bus.history() if e.kind == "attack.technique"}
    assert len(tactics_hit) >= 10
    for technique in ("T1595", "T1110.001", "T1078", "T1552.001", "T1046", "T1098.004", "T1105",
                      "T1048.003", "T1070.003"):
        assert technique in session.techniques, technique

    # Reading the bait is "exposed"; using the stolen DB password is "triggered".
    assert "canary.exposed" in kinds(grid)
    triggered = [e for e in grid.bus.history() if e.kind == "canary.triggered"]
    assert len(triggered) == 1 and triggered[0].data["minted_for"] == session.id
    assert session.canary_hits == 1


async def test_database_decoy_uses_the_same_honeytoken_as_the_web_config(grid):
    captured = []
    real_deploy = grid.runtime.deploy

    async def spy(session_id, specs):
        captured.extend(specs)
        return await real_deploy(session_id, specs)

    grid.runtime.deploy = spy
    session = await run_to_completion(grid, "full_intrusion")
    db = next(s for s in captured if s.role == "database")
    password = db.environment["MYSQL_ROOT_PASSWORD"]
    assert grid.canary.lookup(password).session_id == session.id
    assert password in grid._shells[session.id].fs["/var/www/html/config.php"]


async def test_hostile_model_output_is_blocked_then_recovered(grid):
    session = await run_to_completion(grid, "poisoned_model")
    verdicts = [e.data for e in grid.bus.history() if e.kind == "guard.verdict"]
    assert verdicts[0]["accepted"] is False
    assert any(v["rule"] == "service.forbidden" for v in verdicts[0]["violations"])
    assert verdicts[1]["accepted"] is True
    assert session.guard_rejections == 1 and session.plan_source == "llm"
    # Nothing from the rejected plan reached the runtime.
    assert all(d.image != "alpine:3.20" for d in session.decoys)
    # The retry tells the model which rules failed, never its own text back.
    retry_prompt = grid.llm.calls[1]["user"]
    assert "<feedback>" in retry_prompt and "docker.sock" not in retry_prompt


async def test_model_that_never_complies_falls_back_to_a_vetted_template(settings):
    grid = Grid(settings, llm=MockLLM(hostile_responses=99))
    await grid.start()
    try:
        session = await run_to_completion(grid, "nmap_scan")
        assert session.plan_source == "fallback" and session.guard_rejections == 3
        assert session.state == SessionState.DEPLOYED
        assert "guard.fallback" in kinds(grid)
    finally:
        await grid.shutdown()


async def test_model_receives_the_system_prompt_and_sanitised_footprint(grid):
    await run_to_completion(grid, "nmap_scan")
    call = grid.llm.calls[0]
    assert call["system"] == SYSTEM_PROMPT
    assert '"source": "203.0.113.77"' in call["user"] and "<catalog>" in call["user"]


async def test_session_cap_stops_container_sprawl():
    grid = Grid(Settings(_env_file=None, time_scale=5000, max_sessions=2))
    await grid.start()
    try:
        for i in range(4):
            for ev in scenario_events("nmap_scan", f"203.0.113.{i + 1}", t0=0.0):
                await grid.ingest(ev)
        assert len(grid.sessions) == 2
        assert kinds(grid).count("grid.saturated") == 2
    finally:
        await grid.shutdown()


async def test_repeat_alerts_from_one_source_share_a_session(grid):
    session = await run_to_completion(grid, "full_intrusion")
    assert len(session.alerts) == 3  # scan, brute force, successful login
    assert kinds(grid).count("session.opened") == 1


async def test_close_reaps_decoys_and_frees_the_source(grid):
    session = await run_to_completion(grid, "nmap_scan")
    assert await grid.close(session.id)
    assert session.state == SessionState.CLOSED
    assert await grid.runtime.reap(session.id) == 0   # already gone
    assert await grid.close(session.id) is False      # idempotent
    closed = [e for e in grid.bus.history() if e.kind == "session.state"][-1]
    assert closed.data["reaped"] == 2


async def test_expired_sessions_are_reaped(settings):
    grid = Grid(settings)
    await grid.start()
    try:
        session = await run_to_completion(grid, "nmap_scan")
        session.opened_at -= settings.session_ttl_seconds + 1
        grid._spawn(_one_reaper_pass(grid))
        await wait_for(lambda: session.state == SessionState.CLOSED)
    finally:
        await grid.shutdown()


async def _one_reaper_pass(grid):
    import time
    cutoff = time.time() - grid.settings.session_ttl_seconds
    for s in list(grid.sessions.values()):
        if s.opened_at < cutoff:
            await grid.close(s.id, reason="ttl")


async def test_failed_deploy_cleans_up_and_marks_the_session(settings):
    class BrokenRuntime:
        name = "broken"
        reaped: list[str] = []

        async def deploy(self, session_id, specs):
            raise RuntimeError("daemon unavailable")

        async def reap(self, session_id):
            self.reaped.append(session_id)
            return 0

        async def reap_all(self):
            return 0

    grid = Grid(settings, runtime=BrokenRuntime())
    await grid.start()
    try:
        session = await run_to_completion(grid, "nmap_scan")
        assert session.state == SessionState.FAILED
        assert grid.runtime.reaped == [session.id]
    finally:
        await grid.shutdown()


async def test_everything_that_happened_is_in_the_signed_ledger(grid):
    await run_to_completion(grid, "full_intrusion")
    ledger = grid.bus.ledger
    assert len(ledger.entries()) == len(grid.bus.history())
    assert verify_head(ledger.head(), ledger.entries())
