type Props = { connected: boolean; runtime: string; live: number; max: number };

export function Header({ connected, runtime, live, max }: Props) {
  return (
    <header className="glass flex flex-wrap items-center justify-between gap-4 px-5 py-4">
      <div className="flex items-baseline gap-3">
        <h1 className="font-mono text-lg font-semibold tracking-[0.2em] text-white">
          PHANTOM<span className="text-cyan">/</span>CLOUD
        </h1>
        <span className="hidden text-sm text-white/45 sm:inline">Threat actor dashboard</span>
      </div>

      <dl className="flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-xs">
        <div className="flex items-center gap-2" data-testid="grid-status">
          <span
            aria-hidden
            className={`size-2 rounded-full ${connected ? "bg-cyan shadow-[0_0_10px] shadow-cyan" : "bg-crimson"}`}
          />
          <dt className="sr-only">Grid</dt>
          <dd className={connected ? "text-cyan" : "text-crimson"}>
            {connected ? "GRID ARMED" : "GRID OFFLINE"}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-white/40">runtime</dt>
          <dd data-testid="runtime">{runtime || "—"}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-white/40">sessions</dt>
          <dd>
            {live}
            <span className="text-white/40">/{max || "—"}</span>
          </dd>
        </div>
      </dl>
    </header>
  );
}
