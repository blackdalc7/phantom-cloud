export type GridEvent = {
  seq: number;
  ts: number;
  kind: string;
  session_id: string | null;
  // Event payloads come from the orchestrator; fields are narrowed where they are read.
  data: Record<string, unknown>;
};

export type TechniqueDef = { id: string; name: string; severity: 1 | 2 | 3 };
export type TacticColumn = { id: string; name: string; techniques: TechniqueDef[] };

export type Decoy = {
  id: string;
  hostname: string;
  image: string;
  role: string;
  ip: string;
  port: number;
  hardening: string[];
};

export type Verdict = {
  seq: number;
  attempt: number;
  mode: string;
  accepted: boolean;
  digest: string;
  violations: { rule: string; path: string; detail: string }[];
};

export type LineKind = "system" | "input" | "output" | "alert" | "crypto";

export type TermLine = {
  seq: number;
  kind: LineKind;
  text: string;
  prompt?: string;
  techniques?: string[];
  operator?: boolean;
};

export type SessionView = {
  id: string;
  srcIp: string;
  persona: string;
  state: string;
  planSource: string;
  alerts: { id: string; summary: string; confidence: number }[];
  decoys: Decoy[];
  verdicts: Verdict[];
  lines: TermLine[];
  techniques: Record<string, number>;
  canaryHits: number;
};

export type GridState = {
  lastSeq: number;
  runtime: string;
  maxSessions: number;
  order: string[];
  sessions: Record<string, SessionView>;
  notices: { seq: number; text: string }[];
};

export type LedgerStatus = {
  ok: boolean;
  head: { entries: number; head: string; signature: string; public_key: string };
};
