"use client";

import { type FormEvent, useEffect, useRef, useState } from "react";
import type { LineKind, SessionView } from "@/lib/types";
import { post } from "@/lib/useGrid";

const LINE_STYLE: Record<LineKind, string> = {
  system: "text-cyan/70",
  input: "text-white",
  output: "text-white/60",
  alert: "text-crimson",
  crypto: "text-amethyst",
};

export function Terminal({ session }: { session?: SessionView }) {
  const scroller = useRef<HTMLDivElement>(null);
  const [command, setCommand] = useState("");
  const lineCount = session?.lines.length ?? 0;
  const interactive = session?.state === "deployed" || session?.state === "engaged";

  // Follow new output, unless the analyst has scrolled up to read something.
  const pinned = useRef(true);
  function onScroll() {
    const el = scroller.current;
    if (el) pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
  }
  useEffect(() => {
    const el = scroller.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [lineCount, session?.id]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const text = command.trim();
    if (!text || !session) return;
    setCommand("");
    await post(`sessions/${session.id}/exec`, { command: text }).catch(() => undefined);
  }

  return (
    <section className="glass flex h-[44rem] flex-col overflow-hidden" aria-labelledby="terminal-title">
      <header className="flex items-center justify-between border-b border-white/[0.07] px-4 py-2.5">
        <h2 id="terminal-title" className="label">Live session</h2>
        <span className="font-mono text-xs text-white/50">
          {session ? `${session.srcIp} → ${session.decoys[0]?.hostname ?? "…"}` : "no session"}
        </span>
      </header>

      <div
        ref={scroller}
        onScroll={onScroll}
        role="log"
        aria-live="polite"
        aria-label="Attacker terminal"
        data-testid="terminal"
        className="thin-scroll flex-1 overflow-y-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed"
      >
        {!session && (
          <p className="text-white/35">
            Waiting for a tripwire. Launch a simulation to watch the grid respond.
          </p>
        )}
        {session?.lines.map((line, i) => (
          // Text is rendered as text nodes only: attacker-controlled output can never become markup.
          <div key={`${line.seq}-${i}`} className={`whitespace-pre-wrap break-words ${LINE_STYLE[line.kind]}`}>
            {line.kind === "input" ? (
              <>
                <span className={line.operator ? "text-amethyst" : "text-cyan"}>{line.prompt} </span>
                {line.text}
                {line.techniques?.slice(1).map((t) => (
                  <span key={t} className="ml-2 rounded border border-white/15 px-1 text-[10px] text-white/50">
                    {t}
                  </span>
                ))}
              </>
            ) : (
              line.text
            )}
          </div>
        ))}
        {interactive && <span aria-hidden className="animate-blink text-cyan">▍</span>}
      </div>

      <form onSubmit={submit} className="flex items-center gap-2 border-t border-white/[0.07] px-4 py-2.5">
        <label htmlFor="seat" className="font-mono text-xs text-amethyst">attacker seat $</label>
        <input
          id="seat"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          disabled={!interactive}
          maxLength={256}
          autoComplete="off"
          spellCheck={false}
          placeholder={interactive ? "type a command into the decoy (emulated, never executed)" : "available once decoys are deployed"}
          className="min-w-0 flex-1 bg-transparent font-mono text-[12.5px] text-white placeholder:text-white/25 focus:outline-none disabled:cursor-not-allowed"
        />
      </form>
    </section>
  );
}
