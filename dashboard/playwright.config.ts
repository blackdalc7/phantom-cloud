import { randomBytes } from "node:crypto";
import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

// The suite runs against the real stack: the FastAPI orchestrator (simulated
// runtime, so no containers) and a production build of the dashboard.
const API_PORT = 8411;
const WEB_PORT = 3411;

// A throwaway token per run, shared by both servers through the environment.
process.env.PHANTOM_API_TOKEN ??= randomBytes(32).toString("base64url");

const venvBin = process.platform === "win32" ? "Scripts/python.exe" : "bin/python";
const python = process.env.PHANTOM_PYTHON ?? path.join("..", "orchestrator", ".venv", venvBin);

export default defineConfig({
  testDir: "./e2e",
  workers: 1, // tests share one grid
  retries: 0,
  timeout: 45_000,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "off",
  },
  projects: [
    {
      name: "chromium",
      // PW_CHANNEL=msedge|chrome reuses an installed browser instead of a download.
      use: { ...devices["Desktop Chrome"], channel: process.env.PW_CHANNEL || undefined },
    },
  ],
  webServer: [
    {
      command: `"${python}" -m phantom`,
      cwd: path.join("..", "orchestrator"),
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      reuseExistingServer: false,
      env: {
        PHANTOM_API_TOKEN: process.env.PHANTOM_API_TOKEN,
        PHANTOM_PORT: String(API_PORT),
        PHANTOM_RUNTIME: "simulated",
        PHANTOM_TIME_SCALE: "25",
        PHANTOM_MAX_SESSIONS: "12",
      },
    },
    {
      command: `npm run build && npx next start -H 127.0.0.1 -p ${WEB_PORT}`,
      url: `http://127.0.0.1:${WEB_PORT}`,
      reuseExistingServer: false,
      timeout: 180_000,
      env: {
        PHANTOM_API_TOKEN: process.env.PHANTOM_API_TOKEN,
        PHANTOM_API_URL: `http://127.0.0.1:${API_PORT}`,
        NEXT_TELEMETRY_DISABLED: "1",
      },
    },
  ],
});
