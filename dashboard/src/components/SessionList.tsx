import type { SessionView } from "@/lib/types";

const STATE_STYLE: Record<string, string> = {
  detected: "text-white/60 border-white/20",
  planning: "text-amethyst border-amethyst/40",
  deployed: "text-cyan border-cyan/40",
  engaged: "text-crimson border-crimson/50",
  closed: "text-white/35 border-white/10",
  failed: "text-crimson border-crimson/50",
};

type Props = { sessions: SessionView[]; activeId?: string; onPick: (id: string) => void };

export function SessionList({ sessions, activeId, onPick }: Props) {
  return (
    <section className="glass flex min-h-40 flex-col p-4" aria-labelledby="sessions-title">
      <h2 id="sessions-title" className="label">Threat actors</h2>
      {sessions.length === 0 ? (
        <p className="mt-3 text-sm text-white/40">Perimeter is quiet. No tripwires have fired.</p>
      ) : (
        <ul className="thin-scroll mt-3 flex max-h-[26rem] flex-col gap-2 overflow-y-auto">
          {sessions.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onClick={() => onPick(s.id)}
                aria-pressed={s.id === activeId}
                data-testid="session-card"
                className={`w-full rounded-lg border p-3 text-left transition ${
                  s.id === activeId ? "border-cyan/50 bg-cyan/[0.06]" : "border-white/10 hover:border-white/25"
                }`}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm text-white">{s.srcIp}</span>
                  <span
                    data-testid="session-state"
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATE_STYLE[s.state] ?? ""}`}
                  >
                    {s.state}
                  </span>
                </span>
                <span className="mt-1 block truncate text-xs text-white/45">
                  shown: {s.persona}
                </span>
                <span className="mt-2 flex gap-3 font-mono text-[11px] text-white/55">
                  <span>{s.alerts.length} alerts</span>
                  <span>{s.decoys.length} decoys</span>
                  <span>{Object.keys(s.techniques).length} TTPs</span>
                  {s.canaryHits > 0 && <span className="text-crimson">canary hit</span>}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
