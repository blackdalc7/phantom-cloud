"use client";

import { useState } from "react";
import { useGrid } from "@/lib/useGrid";
import { AttackMatrix } from "./AttackMatrix";
import { DecoyPanel } from "./DecoyPanel";
import { GuardPanel } from "./GuardPanel";
import { Header } from "./Header";
import { LedgerPanel } from "./LedgerPanel";
import { ScenarioPanel } from "./ScenarioPanel";
import { SessionList } from "./SessionList";
import { Terminal } from "./Terminal";

export function Dashboard() {
  const { state, connected, matrix, ledger } = useGrid();
  const [picked, setPicked] = useState<string | null>(null);

  // Follow the newest session unless the analyst pinned one.
  const activeId = picked && state.sessions[picked] ? picked : state.order[0];
  const session = activeId ? state.sessions[activeId] : undefined;
  const live = Object.values(state.sessions).filter(
    (s) => s.state !== "closed" && s.state !== "failed",
  ).length;

  return (
    <div className="mx-auto flex max-w-[1680px] flex-col gap-4 p-4 lg:p-6">
      <Header connected={connected} runtime={state.runtime} live={live} max={state.maxSessions} />

      {state.notices.length > 0 && (
        <p role="status" className="glass border-crimson/30 px-4 py-2 font-mono text-xs text-crimson">
          {state.notices[state.notices.length - 1]?.text}
        </p>
      )}

      <main className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        <div className="flex flex-col gap-4 lg:col-span-3">
          <ScenarioPanel disabled={!connected} />
          <SessionList
            sessions={state.order.map((id) => state.sessions[id]).filter((s) => s !== undefined)}
            activeId={activeId}
            onPick={setPicked}
          />
          <LedgerPanel ledger={ledger} />
        </div>

        <div className="lg:col-span-6">
          <Terminal session={session} />
        </div>

        <div className="flex flex-col gap-4 lg:col-span-3">
          <DecoyPanel session={session} />
          <GuardPanel session={session} />
        </div>

        <div className="lg:col-span-12">
          <AttackMatrix columns={matrix} hits={session?.techniques ?? {}} />
        </div>
      </main>
    </div>
  );
}
