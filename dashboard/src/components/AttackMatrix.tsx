import type { TacticColumn } from "@/lib/types";

type Props = { columns: TacticColumn[]; hits: Record<string, number> };

// Observed techniques light up; critical ones (severity 3) switch to crimson.
function cellStyle(count: number, severity: number): string {
  if (!count) return "border-white/[0.07] text-white/30";
  if (severity === 3) return "border-crimson/60 bg-crimson/[0.12] text-white";
  if (severity === 2) return "border-cyan/60 bg-cyan/[0.12] text-white";
  return "border-cyan/30 bg-cyan/[0.05] text-white/85";
}

export function AttackMatrix({ columns, hits }: Props) {
  const observed = Object.keys(hits).length;
  const tactics = columns.filter((c) => c.techniques.some((t) => hits[t.id])).length;

  return (
    <section className="glass p-4" aria-labelledby="matrix-title">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="matrix-title" className="label">MITRE ATT&CK coverage</h2>
        <p className="font-mono text-xs text-white/50" data-testid="matrix-summary">
          <span className="text-cyan">{observed}</span> techniques across{" "}
          <span className="text-cyan">{tactics}</span>/{columns.length || 13} tactics
        </p>
      </div>

      <div className="thin-scroll mt-3 overflow-x-auto pb-1">
        <div className="grid min-w-[1180px] grid-flow-col auto-cols-fr gap-2">
          {columns.map((column) => (
            <div key={column.id} className="flex flex-col gap-1.5">
              <h3 className="flex h-9 flex-col justify-end border-b border-white/10 pb-1 text-[11px] font-medium leading-tight text-white/70">
                {column.name}
              </h3>
              {column.techniques.map((t) => {
                const count = hits[t.id] ?? 0;
                return (
                  <div
                    // Re-keying on the count restarts the pulse each time a technique is seen again.
                    key={`${t.id}-${count}`}
                    data-testid={`technique-${t.id}`}
                    data-hit={count > 0}
                    title={`${t.id} ${t.name}`}
                    className={`rounded-md border px-2 py-1.5 transition-colors ${cellStyle(count, t.severity)} ${count ? "animate-hit" : ""}`}
                  >
                    <div className="flex items-center justify-between font-mono text-[10px]">
                      <span className={count ? (t.severity === 3 ? "text-crimson" : "text-cyan") : ""}>{t.id}</span>
                      {count > 0 && <span className="text-white/60">×{count}</span>}
                    </div>
                    <div className="mt-0.5 text-[11px] leading-snug">{t.name}</div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
