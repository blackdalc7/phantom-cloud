import httpx
import pytest
from conftest import wait_for

from phantom.api import create_app
from phantom.models import SessionState

TOKEN = "test-token-not-a-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
async def client(settings):
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.grid = app.state.grid
            yield c


async def deployed_session(client, scenario="nmap_scan"):
    r = await client.post("/api/simulate", json={"scenario": scenario}, headers=AUTH)
    assert r.status_code == 202
    grid = client.grid
    await wait_for(lambda: any(s.state == SessionState.DEPLOYED for s in grid.sessions.values()))
    return next(iter(grid.sessions.values()))


async def test_health_is_public_and_minimal(client):
    r = await client.get("/api/health")
    assert r.status_code == 200 and set(r.json()) == {"status", "version"}


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/state"), ("GET", "/api/events"), ("GET", "/api/stream"),
    ("GET", "/api/evidence/verify"), ("POST", "/api/simulate"),
    ("POST", "/api/sessions/x/exec"), ("POST", "/api/sessions/x/close"),
    ("POST", "/api/canary/lookup"),
])
@pytest.mark.parametrize("headers", [
    {}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN[:-1]},
    {"Authorization": "Basic " + TOKEN},
])
async def test_every_other_route_requires_the_token(client, method, path, headers):
    r = await client.request(method, path, headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


async def test_generated_token_when_none_is_configured():
    from phantom.config import Settings
    a = create_app(Settings(_env_file=None))
    b = create_app(Settings(_env_file=None))
    assert len(a.state.api_token) >= 32 and a.state.api_token != b.state.api_token


async def test_security_headers_on_every_response(client):
    for r in (await client.get("/api/health"), await client.get("/api/state"),
              await client.get("/api/nope")):
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["cache-control"] == "no-store"


async def test_docs_are_not_served(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert (await client.get(path)).status_code == 404


@pytest.mark.parametrize("body", [
    {"scenario": "rm -rf"},
    {"scenario": "nmap_scan", "source_ip": "8.8.8.8"},          # a real address
    {"scenario": "nmap_scan", "source_ip": "10.0.0.5"},
    {"scenario": "nmap_scan", "source_ip": "not-an-ip"},
    {"scenario": "nmap_scan", "extra": True},
    {},
])
async def test_simulate_rejects_bad_input(client, body):
    r = await client.post("/api/simulate", json=body, headers=AUTH)
    assert r.status_code == 422
    assert client.grid.sessions == {}


async def test_simulate_then_state_and_events(client):
    r = await client.post("/api/simulate", headers=AUTH,
                          json={"scenario": "nmap_scan", "source_ip": "198.51.100.7"})
    assert r.json()["source_ip"] == "198.51.100.7"
    await wait_for(lambda: any(s.state == SessionState.DEPLOYED
                               for s in client.grid.sessions.values()))

    state = (await client.get("/api/state", headers=AUTH)).json()
    assert state["runtime"] == "simulated"
    assert state["sessions"][0]["src_ip"] == "198.51.100.7"
    assert len(state["matrix"]) == 13
    assert len(state["ledger"]["signature"]) == 128

    events = (await client.get("/api/events", headers=AUTH)).json()
    assert events[0]["kind"] == "grid.armed"
    later = (await client.get(f"/api/events?after={events[-1]['seq']}", headers=AUTH)).json()
    assert later == []


async def test_operator_can_type_into_the_decoy_shell(client):
    session = await deployed_session(client)
    r = await client.post(f"/api/sessions/{session.id}/exec", headers=AUTH,
                          json={"command": "cat /etc/passwd"})
    body = r.json()
    assert r.status_code == 200 and "svc_backup" in body["output"]
    assert "T1003.008" in body["techniques"]
    assert session.state == SessionState.ENGAGED


@pytest.mark.parametrize("command", ["", "x" * 257, "ls\x00-la", "ls\n whoami", "\x1b[2J"])
async def test_exec_validates_commands(client, command):
    session = await deployed_session(client)
    r = await client.post(f"/api/sessions/{session.id}/exec", headers=AUTH,
                          json={"command": command})
    assert r.status_code == 422


async def test_exec_and_close_on_unknown_session(client):
    assert (await client.post("/api/sessions/nope/exec", headers=AUTH,
                              json={"command": "id"})).status_code == 404
    assert (await client.post("/api/sessions/nope/close", headers=AUTH)).status_code == 404


async def test_close_session(client):
    session = await deployed_session(client)
    assert (await client.post(f"/api/sessions/{session.id}/close", headers=AUTH)).json() == {
        "closed": True}
    assert session.state == SessionState.CLOSED
    r = await client.post(f"/api/sessions/{session.id}/exec", headers=AUTH, json={"command": "id"})
    assert r.status_code == 404


async def test_canary_lookup_attributes_a_stolen_token(client):
    session = await deployed_session(client)
    out = (await client.post(f"/api/sessions/{session.id}/exec", headers=AUTH,
                             json={"command": "cat ~/.aws/credentials"})).json()["output"]
    token = out.split("aws_access_key_id = ")[1].split()[0]
    hit = (await client.post("/api/canary/lookup", headers=AUTH, json={"token": token})).json()
    assert hit == {"genuine": True, "kind": "access_key", "session_id": session.id}
    miss = (await client.post("/api/canary/lookup", headers=AUTH,
                              json={"token": "PHKAAAAAAAAAAAAAAAAA"})).json()
    assert miss == {"genuine": False}


async def test_evidence_endpoint_reports_a_valid_chain(client):
    await deployed_session(client)
    body = (await client.get("/api/evidence/verify", headers=AUTH)).json()
    assert body["ok"] is True and body["first_bad_seq"] is None
    assert body["head"]["entries"] >= len(body["tail"]) > 0


async def test_mutating_calls_are_rate_limited(client):
    codes = [(await client.post("/api/canary/lookup", headers=AUTH,
                                json={"token": "PHKAAAAAAAAAAAAAAAAA"})).status_code
             for _ in range(35)]
    assert codes[:30] == [200] * 30 and set(codes[30:]) == {429}


async def test_stream_replays_history_then_follows_live_events(settings):
    """Drive the SSE generator directly; ASGITransport buffers streaming bodies."""
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        grid = app.state.grid
        route = next(r for r in app.routes if getattr(r, "path", "") == "/api/stream")
        response = await route.endpoint(after=0, last_event_id=None)
        chunks = response.body_iterator
        first = await anext(chunks)
        assert first.startswith("id: 1\nevent: grid\ndata: ") and '"grid.armed"' in first
        grid.bus.publish("probe", n=1)
        assert '"probe"' in await anext(chunks)
        await chunks.aclose()
        assert grid.bus.subscriber_count == 0
        assert response.media_type == "text/event-stream"
