"use client";

import { useState } from "react";
import { post } from "@/lib/useGrid";

const SCENARIOS = [
  { id: "full_intrusion", name: "Full intrusion", hint: "scan → brute force → hands on keyboard", primary: true },
  { id: "nmap_scan", name: "Port scan", hint: "nmap sweep with version detection" },
  { id: "ssh_bruteforce", name: "SSH brute force", hint: "password guessing against the bastion" },
  { id: "poisoned_model", name: "Poisoned planner", hint: "LLM returns a container-escape config" },
] as const;

export function ScenarioPanel({ disabled }: { disabled: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function launch(scenario: string) {
    setBusy(true);
    setError("");
    try {
      const response = await post("simulate", { scenario });
      if (!response.ok) setError(response.status === 429 ? "Rate limited, wait a moment" : "Launch failed");
    } catch {
      setError("Orchestrator unreachable");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="glass p-4" aria-labelledby="tripwire-title">
      <h2 id="tripwire-title" className="label">Tripwire simulation</h2>
      <p className="mt-1 text-xs text-white/45">
        Replays sensor events from a documentation-range address. No real traffic is generated.
      </p>
      <div className="mt-3 flex flex-col gap-2">
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            type="button"
            disabled={disabled || busy}
            onClick={() => launch(s.id)}
            data-testid={`scenario-${s.id}`}
            className={`rounded-lg border px-3 py-2 text-left transition disabled:cursor-not-allowed disabled:opacity-40 ${
              "primary" in s
                ? "border-cyan/50 bg-cyan/10 hover:bg-cyan/20"
                : "border-white/10 bg-white/[0.02] hover:border-cyan/40"
            }`}
          >
            <span className={`block text-sm font-medium ${"primary" in s ? "text-cyan" : "text-white/90"}`}>
              {s.name}
            </span>
            <span className="block text-xs text-white/45">{s.hint}</span>
          </button>
        ))}
      </div>
      {error && <p role="alert" className="mt-2 font-mono text-xs text-crimson">{error}</p>}
    </section>
  );
}
