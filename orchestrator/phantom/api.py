"""HTTP control plane for the grid."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import __version__
from .attack import matrix
from .config import Settings
from .evidence import verify_chain
from .models import Event
from .orchestrator import Grid

MAX_STREAMS = 32
KEEPALIVE_SECONDS = 15

# RFC 5737 documentation ranges. Simulated attackers may only come from these,
# so the tool can't be used to fabricate "evidence" against a real address.
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: Literal["nmap_scan", "ssh_bruteforce", "full_intrusion", "poisoned_model"]
    source_ip: str | None = None

    @field_validator("source_ip")
    @classmethod
    def _documentation_range(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("not an IP address") from exc
        if not any(addr in net for net in DOC_NETS):
            raise ValueError("source_ip must be in an RFC 5737 documentation range")
        return str(addr)


class ExecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=256)

    @field_validator("command")
    @classmethod
    def _printable(cls, value: str) -> str:
        if not value.isprintable():
            raise ValueError("control characters are not allowed")
        return value


class CanaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=8, max_length=64)


class RateLimiter:
    """Sliding-window limit on state-changing calls (per process)."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self._hits: deque[float] = deque()

    def check(self) -> None:
        now = time.monotonic()
        while self._hits and now - self._hits[0] > self.window:
            self._hits.popleft()
        if len(self._hits) >= self.limit:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": "10"})
        self._hits.append(now)


def _sse(event: Event) -> str:
    return f"id: {event.seq}\nevent: grid\ndata: {event.model_dump_json()}\n\n"


def create_app(settings: Settings | None = None, grid: Grid | None = None) -> FastAPI:
    settings = settings or Settings()
    grid = grid or Grid(settings)
    token = (settings.api_token.get_secret_value() if settings.api_token
             else secrets.token_urlsafe(32))
    limiter = RateLimiter(limit=30, window=60)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await grid.start()
        yield
        await grid.shutdown()

    # Interactive docs are off: one less unauthenticated surface on a security tool.
    app = FastAPI(title="Phantom Cloud", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.grid = grid
    app.state.api_token = token

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        # The API only ever returns JSON or an event stream, so the browser is
        # told it may not render, frame, sniff or cache any of it.
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Cross-Origin-Resource-Policy": "same-origin",
        })
        return response

    def authed(authorization: Annotated[str | None, Header()] = None) -> None:
        supplied = (authorization or "").removeprefix("Bearer ")
        # compare_digest: checking the token must not leak it through timing.
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            raise HTTPException(401, "missing or invalid token",
                                headers={"WWW-Authenticate": "Bearer"})

    def limited() -> None:
        limiter.check()

    Auth = Depends(authed)  # noqa: N806

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/state", dependencies=[Auth])
    async def state() -> dict:
        return {
            "runtime": grid.runtime.name,
            "limits": {"max_sessions": settings.max_sessions,
                       "max_decoys_per_session": settings.max_decoys_per_session},
            "sessions": [s.model_dump() for s in grid.sessions.values()],
            "matrix": matrix(),
            "ledger": grid.bus.ledger.head().model_dump(),
        }

    @app.get("/api/events", dependencies=[Auth])
    async def events(after: Annotated[int, Query(ge=0)] = 0) -> list[dict]:
        return [e.model_dump() for e in grid.bus.history(after)]

    @app.get("/api/stream", dependencies=[Auth])
    async def stream(after: Annotated[int, Query(ge=0)] = 0,
                     last_event_id: Annotated[str | None, Header()] = None):
        if grid.bus.subscriber_count >= MAX_STREAMS:
            raise HTTPException(503, "too many open streams")
        if last_event_id and last_event_id.isdigit():
            after = max(after, int(last_event_id))  # EventSource reconnect
        if after > grid.bus.last_seq:
            after = 0  # client is ahead of us: we restarted, so replay from the start
        # Subscribe before reading history so nothing falls in the gap;
        # duplicates are filtered by sequence number below.
        queue = grid.bus.subscribe()

        async def generate():
            last = after
            try:
                for event in grid.bus.history(after):
                    last = event.seq
                    yield _sse(event)
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), KEEPALIVE_SECONDS)
                    except TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    if event is None:
                        return
                    if event.seq > last:
                        last = event.seq
                        yield _sse(event)
            finally:
                grid.bus.unsubscribe(queue)

        return StreamingResponse(generate(), media_type="text/event-stream",
                                 headers={"X-Accel-Buffering": "no"})

    @app.post("/api/simulate", status_code=202, dependencies=[Auth, Depends(limited)])
    async def simulate(body: SimulateRequest) -> dict:
        src = body.source_ip or f"203.0.113.{secrets.randbelow(200) + 20}"
        grid.start_scenario(body.scenario, src)
        return {"accepted": True, "scenario": body.scenario, "source_ip": src}

    @app.post("/api/sessions/{session_id}/exec", dependencies=[Auth, Depends(limited)])
    async def exec_command(session_id: str, body: ExecRequest) -> dict:
        try:
            return await grid.exec(session_id, body.command, actor="operator")
        except LookupError as exc:
            raise HTTPException(404, "no live shell for that session") from exc

    @app.post("/api/sessions/{session_id}/close", dependencies=[Auth, Depends(limited)])
    async def close_session(session_id: str) -> dict:
        if not await grid.close(session_id):
            raise HTTPException(404, "no active session with that id")
        return {"closed": True}

    @app.get("/api/evidence/verify", dependencies=[Auth])
    async def evidence() -> dict:
        ledger = grid.bus.ledger
        entries = ledger.entries()
        ok, bad_seq = verify_chain(entries)
        return {"ok": ok, "first_bad_seq": bad_seq, "head": ledger.head().model_dump(),
                "tail": [e.model_dump() for e in entries[-8:]]}

    @app.post("/api/canary/lookup", dependencies=[Auth, Depends(limited)])
    async def canary_lookup(body: CanaryRequest) -> dict:
        hit = grid.canary.lookup(body.token)
        if hit is None:
            return {"genuine": False}
        return {"genuine": True, "kind": hit.kind, "session_id": hit.session_id}

    @app.exception_handler(Exception)
    async def unhandled(_: Request, __: Exception) -> JSONResponse:
        # Never send a stack trace to a client.
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app
