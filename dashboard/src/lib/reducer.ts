import type { Decoy, GridEvent, GridState, SessionView, TermLine } from "./types";

// The whole dashboard is a fold over the orchestrator's event stream: replaying
// the same events always rebuilds the same screen, including after a reconnect.

const MAX_LINES = 600;

export const initialState: GridState = {
  lastSeq: 0,
  runtime: "",
  maxSessions: 0,
  order: [],
  sessions: {},
  notices: [],
};

const str = (value: unknown, fallback = ""): string =>
  typeof value === "string" ? value : fallback;
const num = (value: unknown, fallback = 0): number =>
  typeof value === "number" ? value : fallback;

function newSession(id: string, event: GridEvent): SessionView {
  return {
    id,
    srcIp: str(event.data.src_ip),
    persona: str(event.data.persona),
    state: "detected",
    planSource: "",
    alerts: [],
    decoys: [],
    verdicts: [],
    lines: [],
    techniques: {},
    canaryHits: 0,
  };
}

function withLines(session: SessionView, ...lines: TermLine[]): SessionView {
  return { ...session, lines: [...session.lines, ...lines].slice(-MAX_LINES) };
}

function applyToSession(session: SessionView, event: GridEvent): SessionView {
  const { seq, data } = event;
  const sys = (text: string, kind: TermLine["kind"] = "system"): TermLine => ({ seq, kind, text });

  switch (event.kind) {
    case "tripwire.alert": {
      const alert = data.alert as { id: string; summary: string; confidence: number };
      return withLines(
        { ...session, alerts: [...session.alerts, alert] },
        sys(`[tripwire] ${alert.summary} · confidence ${Math.round(alert.confidence * 100)}%`),
      );
    }
    case "session.state": {
      const state = str(data.state);
      const next = { ...session, state, planSource: str(data.plan_source, session.planSource) };
      if (state === "planning") return withLines(next, sys("[planner] generating decoy environment"));
      if (state === "closed") return withLines(next, sys("[grid] session closed, decoys reaped"));
      if (state === "failed") return withLines(next, sys("[grid] deployment failed", "alert"));
      return next;
    }
    case "guard.verdict": {
      const violations = (data.violations ?? []) as SessionVerdictViolation[];
      const accepted = data.accepted === true;
      const verdict = {
        seq,
        attempt: num(data.attempt),
        mode: str(data.mode),
        accepted,
        digest: str(data.output_sha256),
        violations,
      };
      const line = accepted
        ? sys(`[guard] plan accepted on attempt ${verdict.attempt}`)
        : sys(`[guard] model output REJECTED · ${violations.length} policy violations`, "alert");
      return withLines({ ...session, verdicts: [...session.verdicts, verdict] }, line);
    }
    case "guard.fallback":
      return withLines(session, sys("[guard] falling back to vetted template", "alert"));
    case "decoy.deployed": {
      const decoy = data as unknown as Decoy;
      return withLines(
        { ...session, decoys: [...session.decoys, decoy] },
        sys(`[deploy] ${decoy.hostname} (${decoy.role}) up at ${decoy.ip}:${decoy.port}`),
      );
    }
    case "grid.expanded":
      return withLines(session, sys("[grid] intruder is exploring: environment expanded"));
    case "shell.io": {
      const lines: TermLine[] = [
        {
          seq,
          kind: "input",
          text: str(data.command),
          prompt: str(data.prompt),
          techniques: (data.techniques ?? []) as string[],
          operator: data.actor === "operator",
        },
      ];
      const output = str(data.output);
      if (output) lines.push({ seq, kind: "output", text: output });
      return withLines(session, ...lines);
    }
    case "attack.technique": {
      const id = str(data.id);
      return { ...session, techniques: { ...session.techniques, [id]: num(data.count, 1) } };
    }
    case "canary.exposed":
      return withLines(session, sys(`[canary] honeytoken read (${str(data.kind)}) ${str(data.token)}`, "crypto"));
    case "canary.triggered":
      return withLines(
        { ...session, canaryHits: session.canaryHits + 1 },
        sys(`[canary] STOLEN CREDENTIAL USED (${str(data.kind)}) ${str(data.token)}`, "alert"),
      );
    default:
      return session;
  }
}

type SessionVerdictViolation = { rule: string; path: string; detail: string };

export function reduce(state: GridState, event: GridEvent): GridState {
  // seq 1 again means the orchestrator restarted: start from a clean slate.
  if (event.seq === 1 && state.lastSeq > 0) state = initialState;
  if (event.seq <= state.lastSeq) return state; // replayed on reconnect
  const base = { ...state, lastSeq: event.seq };

  if (event.kind === "grid.armed") {
    return { ...base, runtime: str(event.data.runtime), maxSessions: num(event.data.max_sessions) };
  }
  if (event.kind === "grid.saturated") {
    const text = `Session cap reached: alert from ${str(event.data.src_ip)} logged, no decoys spawned`;
    return { ...base, notices: [...base.notices, { seq: event.seq, text }].slice(-4) };
  }

  const id = event.session_id;
  if (!id) return base;
  const existing = base.sessions[id];
  if (event.kind === "session.opened") {
    return {
      ...base,
      order: [id, ...base.order],
      sessions: { ...base.sessions, [id]: newSession(id, event) },
    };
  }
  if (!existing) return base;
  return { ...base, sessions: { ...base.sessions, [id]: applyToSession(existing, event) } };
}
