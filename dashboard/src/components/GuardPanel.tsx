import type { SessionView } from "@/lib/types";

export function GuardPanel({ session }: { session?: SessionView }) {
  const verdicts = session?.verdicts ?? [];
  return (
    <section className="glass p-4" aria-labelledby="guard-title">
      <h2 id="guard-title" className="label">Policy guard</h2>
      <p className="mt-1 text-xs text-white/45">Every LLM plan is validated before Docker sees it.</p>
      {verdicts.length === 0 ? (
        <p className="mt-3 text-sm text-white/40">No plans evaluated.</p>
      ) : (
        <ol className="mt-3 flex flex-col gap-2">
          {verdicts.map((v) => (
            <li key={v.seq} data-testid="verdict" data-accepted={v.accepted}
                className={`rounded-lg border p-3 ${v.accepted ? "border-cyan/25" : "border-crimson/40 bg-crimson/[0.05]"}`}>
              <div className="flex items-center justify-between font-mono text-xs">
                <span className={v.accepted ? "text-cyan" : "text-crimson"}>
                  {v.accepted ? "ACCEPTED" : "REJECTED"}
                </span>
                <span className="text-white/40">{v.mode} · attempt {v.attempt}</span>
              </div>
              <p className="mt-1 truncate font-mono text-[11px] text-amethyst" title="SHA-256 of the model output">
                sha256:{v.digest.slice(0, 24)}…
              </p>
              {v.violations.length > 0 && (
                <ul className="thin-scroll mt-2 flex max-h-32 flex-col gap-1 overflow-y-auto">
                  {v.violations.map((x, i) => (
                    <li key={i} className="font-mono text-[11px] text-white/60">
                      <span className="text-crimson">{x.path.split(".").pop()}</span> {x.detail}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
