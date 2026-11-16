"""In-process event bus with a bounded replay buffer.

The dashboard rebuilds its whole view from this stream, so late subscribers get
recent history first and live events after.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from .evidence import EvidenceLedger
from .models import Event

HISTORY = 2000
SUBSCRIBER_QUEUE = 1024


class EventBus:
    def __init__(self, ledger: EvidenceLedger | None = None) -> None:
        self._seq = 0
        self._history: deque[Event] = deque(maxlen=HISTORY)
        self._subscribers: set[asyncio.Queue[Event | None]] = set()
        self.ledger = ledger or EvidenceLedger()

    def publish(self, kind: str, session_id: str | None = None, /, **data: Any) -> Event:
        self._seq += 1
        event = Event(seq=self._seq, ts=time.time(), kind=kind, session_id=session_id, data=data)
        self._history.append(event)
        self.ledger.append(ts=event.ts, kind=kind, session_id=session_id, payload=data)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # A stalled client must not back-pressure the orchestrator.
                # Drop it; the sentinel tells its stream to end and reconnect.
                self._subscribers.discard(queue)
                _drain(queue)
                queue.put_nowait(None)
        return event

    def history(self, after: int = 0) -> list[Event]:
        return [e for e in self._history if e.seq > after]

    def subscribe(self) -> asyncio.Queue[Event | None]:
        queue: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event | None]) -> None:
        self._subscribers.discard(queue)

    @property
    def last_seq(self) -> int:
        return self._seq

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


def _drain(queue: asyncio.Queue[Event | None]) -> None:
    while not queue.empty():
        queue.get_nowait()
