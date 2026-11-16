"""Tripwire detectors.

Both detectors are small sliding-window state machines keyed by source address.
They only ever look at event timestamps (never the wall clock), so the same
event sequence always produces the same alerts.
"""

from __future__ import annotations

import uuid
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field

from ..models import Alert, AlertKind, NetEvent, NetEventKind

# Per-source state is attacker-controlled input (anyone can spoof new sources),
# so it is capped and evicted least-recently-seen first.
MAX_SOURCES = 4096


class _LRU(OrderedDict):
    def touch(self, key: str, factory):
        if key in self:
            self.move_to_end(key)
        else:
            self[key] = factory()
            if len(self) > MAX_SOURCES:
                self.popitem(last=False)
        return self[key]


@dataclass
class _ScanState:
    probes: deque = field(default_factory=deque)  # (ts, port, kind)
    muted_until: float = 0.0


class PortScanDetector:
    """Flags a source that touches many distinct ports.

    Two windows run side by side: a short one for ordinary sweeps and a long
    one so that a scanner throttled to a few probes a minute (nmap -T1/-T2)
    still adds up to an alert.
    """

    def __init__(self, fast_window: float = 10.0, fast_ports: int = 15,
                 slow_window: float = 600.0, slow_ports: int = 30,
                 cooldown: float = 120.0) -> None:
        self.fast_window, self.fast_ports = fast_window, fast_ports
        self.slow_window, self.slow_ports = slow_window, slow_ports
        self.cooldown = cooldown
        self._sources: _LRU = _LRU()

    def observe(self, ev: NetEvent) -> Alert | None:
        if ev.kind not in (NetEventKind.SYN, NetEventKind.BANNER_GRAB):
            return None
        st: _ScanState = self._sources.touch(ev.src_ip, _ScanState)
        st.probes.append((ev.ts, ev.dst_port, ev.kind))
        while st.probes and ev.ts - st.probes[0][0] > self.slow_window:
            st.probes.popleft()
        if ev.ts < st.muted_until:
            return None

        fast = {p for t, p, _ in st.probes if ev.ts - t <= self.fast_window}
        slow = {p for _, p, _ in st.probes}
        if len(fast) >= self.fast_ports:
            profile, ports, threshold = "fast_sweep", fast, self.fast_ports
        elif len(slow) >= self.slow_ports:
            profile, ports, threshold = "low_and_slow", slow, self.slow_ports
        else:
            return None

        # Reading banners after the SYN means the tool is fingerprinting
        # service versions (nmap -sV), which is a step past a plain sweep.
        grabs = sum(1 for _, _, k in st.probes if k == NetEventKind.BANNER_GRAB)
        if grabs:
            profile = "version_detection"
        st.muted_until = ev.ts + self.cooldown

        span = max(ev.ts - st.probes[0][0], 0.001)
        techniques = ["T1595", "T1046"]
        return Alert(
            id=uuid.uuid4().hex[:12], ts=ev.ts, kind=AlertKind.PORT_SCAN, src_ip=ev.src_ip,
            confidence=round(min(0.99, 0.55 + 0.2 * len(ports) / threshold), 2),
            summary=f"Port scan ({profile.replace('_', ' ')}): {len(ports)} ports probed",
            evidence={"profile": profile, "distinct_ports": len(ports),
                      "sample_ports": sorted(ports)[:12], "banner_grabs": grabs,
                      "probes_per_second": round(len(st.probes) / span, 1)},
            techniques=techniques,
        )


@dataclass
class _AuthState:
    failures: deque = field(default_factory=deque)  # (ts, username)
    muted_until: float = 0.0
    alerted: bool = False


class SSHBruteForceDetector:
    """Flags repeated SSH authentication failures from one source.

    The username spread separates the two common variants: hammering one
    account (password guessing) versus trying a few passwords across many
    accounts to stay under lockout thresholds (password spraying).
    """

    def __init__(self, window: float = 60.0, threshold: int = 6, cooldown: float = 120.0) -> None:
        self.window, self.threshold, self.cooldown = window, threshold, cooldown
        self._sources: _LRU = _LRU()

    def observe(self, ev: NetEvent) -> Alert | None:
        if ev.kind == NetEventKind.SSH_AUTH_OK:
            return self._on_success(ev)
        if ev.kind != NetEventKind.SSH_AUTH_FAIL:
            return None
        st: _AuthState = self._sources.touch(ev.src_ip, _AuthState)
        st.failures.append((ev.ts, ev.username or ""))
        while st.failures and ev.ts - st.failures[0][0] > self.window:
            st.failures.popleft()
        if ev.ts < st.muted_until or len(st.failures) < self.threshold:
            return None

        per_user = Counter(u for _, u in st.failures)
        spraying = len(per_user) >= 4 and max(per_user.values()) <= 3
        variant, technique = (("password_spraying", "T1110.003") if spraying
                              else ("password_guessing", "T1110.001"))
        st.muted_until = ev.ts + self.cooldown
        st.alerted = True
        return Alert(
            id=uuid.uuid4().hex[:12], ts=ev.ts, kind=AlertKind.SSH_BRUTEFORCE, src_ip=ev.src_ip,
            confidence=round(min(0.99, 0.6 + 0.05 * len(st.failures)), 2),
            summary=f"SSH brute force ({variant.replace('_', ' ')}): "
                    f"{len(st.failures)} failures in {int(self.window)}s",
            evidence={"variant": variant, "failures": len(st.failures),
                      "distinct_usernames": len(per_user), "client_banner": ev.client_banner},
            techniques=[technique],
        )

    def _on_success(self, ev: NetEvent) -> Alert | None:
        st: _AuthState | None = self._sources.get(ev.src_ip)
        if st is None or not st.alerted:
            return None
        # A login right after a guessing run is the worst case: the guess worked.
        st.alerted = False
        return Alert(
            id=uuid.uuid4().hex[:12], ts=ev.ts, kind=AlertKind.SSH_BRUTEFORCE, src_ip=ev.src_ip,
            confidence=0.97,
            summary=f"SSH login succeeded after brute force (user {ev.username or '?'})",
            evidence={"variant": "successful_login", "username": ev.username},
            techniques=["T1078", "T1133"],
        )
