import type { LedgerStatus } from "@/lib/types";

export function LedgerPanel({ ledger }: { ledger: LedgerStatus | null }) {
  return (
    <section className="glass p-4" aria-labelledby="ledger-title">
      <h2 id="ledger-title" className="label">Evidence ledger</h2>
      {!ledger ? (
        <p className="mt-3 text-sm text-white/40">Awaiting first entry.</p>
      ) : (
        <dl className="mt-3 flex flex-col gap-2 font-mono text-[11px]">
          <div className="flex items-center justify-between">
            <dt className="text-white/40">chain</dt>
            <dd data-testid="ledger-status" className={ledger.ok ? "text-amethyst" : "text-crimson"}>
              {ledger.ok ? "INTACT" : "BROKEN"} · {ledger.head.entries} entries
            </dd>
          </div>
          <div>
            <dt className="text-white/40">head (sha-256)</dt>
            <dd data-testid="ledger-head" className="break-all text-amethyst">{ledger.head.head}</dd>
          </div>
          <div>
            <dt className="text-white/40">signature (ed25519)</dt>
            <dd className="truncate text-amethyst/70">{ledger.head.signature}</dd>
          </div>
        </dl>
      )}
    </section>
  );
}
