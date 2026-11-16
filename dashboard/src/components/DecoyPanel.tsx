import type { SessionView } from "@/lib/types";

export function DecoyPanel({ session }: { session?: SessionView }) {
  const decoys = session?.decoys ?? [];
  return (
    <section className="glass p-4" aria-labelledby="decoys-title">
      <h2 id="decoys-title" className="label">Decoy grid</h2>
      {decoys.length === 0 ? (
        <p className="mt-3 text-sm text-white/40">Nothing deployed.</p>
      ) : (
        <ul className="mt-3 flex flex-col gap-2">
          {decoys.map((d) => (
            <li key={d.id} data-testid="decoy" className="rounded-lg border border-white/10 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm text-white">{d.hostname}</span>
                <span className="font-mono text-[11px] text-white/45">{d.ip}:{d.port}</span>
              </div>
              <p className="mt-0.5 truncate font-mono text-[11px] text-white/40">{d.image}</p>
              <ul className="mt-2 flex flex-wrap gap-1" aria-label="Isolation settings">
                {d.hardening.map((h) => (
                  <li key={h} className="rounded bg-cyan/[0.08] px-1.5 py-0.5 font-mono text-[10px] text-cyan/80">
                    {h}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
