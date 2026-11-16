import { expect, test } from "@playwright/test";

test("pages ship a nonce-based CSP and hardening headers", async ({ request }) => {
  const first = await request.get("/");
  const second = await request.get("/");
  const headers = first.headers();
  const csp = headers["content-security-policy"] ?? "";

  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("connect-src 'self'");
  expect(csp).not.toContain("unsafe-inline");
  expect(csp).not.toContain("unsafe-eval");

  const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
  expect(nonce).toBeTruthy();
  expect(second.headers()["content-security-policy"]).not.toContain(nonce!); // fresh per request

  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["referrer-policy"]).toBe("no-referrer");
  expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
  expect(headers["permissions-policy"]).toContain("camera=()");
  expect(headers["x-powered-by"]).toBeUndefined();
});

test("the orchestrator token never reaches the browser", async ({ page }) => {
  const token = process.env.PHANTOM_API_TOKEN!;
  expect(token.length).toBeGreaterThan(20);

  const bodies: string[] = [];
  page.on("response", async (response) => {
    const type = response.headers()["content-type"] ?? "";
    if (/javascript|html|json/.test(type)) bodies.push(await response.text().catch(() => ""));
  });
  await page.goto("/");
  await expect(page.getByTestId("grid-status")).toContainText("GRID ARMED");
  expect(bodies.length).toBeGreaterThan(3);
  expect(bodies.some((body) => body.includes(token))).toBe(false);
});

test("the API proxy only forwards allowlisted routes", async ({ request }) => {
  expect((await request.get("/api/phantom/state")).status()).toBe(200);
  for (const path of ["health", "docs", "sessions%2F..%2Fstate", "stream/../../health","state/extra", "canary/lookup"]) {
    expect((await request.get(`/api/phantom/${path}`)).status(), path).toBe(404);
  }
  const bad = await request.post("/api/phantom/sessions/NOT-AN-ID/exec", { data: { command: "id" } });
  expect(bad.status()).toBe(404);
});

test("the API proxy refuses cross-site and malformed writes", async ({ request }) => {
  const crossSite = await request.post("/api/phantom/simulate", {
    headers: { Origin: "https://evil.example" },
    data: { scenario: "nmap_scan" },
  });
  expect(crossSite.status()).toBe(403);

  // A plain HTML form cannot send JSON, so form-encoded bodies are refused outright.
  const form = await request.post("/api/phantom/simulate", { form: { scenario: "nmap_scan" } });
  expect(form.status()).toBe(415);

  const huge = await request.post("/api/phantom/canary/lookup", { data: { token: "x".repeat(5000) } });
  expect(huge.status()).toBe(413);

  // Validation errors from the orchestrator pass straight through.
  const invalid = await request.post("/api/phantom/simulate", {
    data: { scenario: "nmap_scan", source_ip: "8.8.8.8" },
  });
  expect(invalid.status()).toBe(422);
});
