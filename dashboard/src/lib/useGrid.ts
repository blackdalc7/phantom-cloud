"use client";

import { useCallback, useEffect, useReducer, useState } from "react";
import { initialState, reduce } from "./reducer";
import type { GridEvent, LedgerStatus, TacticColumn } from "./types";

const API = "/api/phantom";

export async function post(path: string, body: unknown = {}): Promise<Response> {
  return fetch(`${API}/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function useGrid() {
  const [state, dispatch] = useReducer(reduce, initialState);
  const [connected, setConnected] = useState(false);
  const [matrix, setMatrix] = useState<TacticColumn[]>([]);
  const [ledger, setLedger] = useState<LedgerStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API}/state`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((body) => !cancelled && setMatrix(body.matrix))
      .catch(() => undefined); // the header already shows the grid as offline
    return () => {
      cancelled = true;
    };
  }, [connected]);

  useEffect(() => {
    // EventSource reconnects by itself and resends the last event id, so a
    // dropped connection resumes where it left off.
    const source = new EventSource(`${API}/stream`);
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.addEventListener("grid", (message) => {
      try {
        dispatch(JSON.parse((message as MessageEvent<string>).data) as GridEvent);
      } catch {
        // A malformed frame is dropped rather than allowed to break the view.
      }
    });
    return () => source.close();
  }, []);

  const refreshLedger = useCallback(async () => {
    const r = await fetch(`${API}/evidence/verify`).catch(() => null);
    if (r?.ok) setLedger((await r.json()) as LedgerStatus);
  }, []);

  // Re-verify shortly after activity settles instead of on every event.
  useEffect(() => {
    if (state.lastSeq === 0) return;
    const timer = setTimeout(refreshLedger, 800);
    return () => clearTimeout(timer);
  }, [state.lastSeq, refreshLedger]);

  return { state, connected, matrix, ledger };
}
