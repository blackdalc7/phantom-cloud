import { expect, test, type Page } from "@playwright/test";

// Fail a test on any console error; a CSP violation shows up here too.
function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
}

async function openDashboard(page: Page) {
  await page.goto("/");
  await expect(page.getByTestId("grid-status")).toContainText("GRID ARMED");
}

test("idle grid renders with the design system and no console errors", async ({ page }) => {
  const errors = watchConsole(page);
  await openDashboard(page);

  await expect(page.getByRole("heading", { name: "PHANTOM/CLOUD" })).toBeVisible();
  await expect(page.getByTestId("runtime")).toHaveText("simulated");
  await expect(page.locator("[data-testid^='technique-']")).toHaveCount(34);

  const body = page.locator("body");
  await expect(body).toHaveCSS("background-color", "rgb(5, 5, 5)");
  await expect(body).toHaveCSS("font-family", /Inter Variable/);
  await expect(page.getByTestId("terminal")).toHaveCSS("font-family", /JetBrains Mono Variable/);
  expect(errors).toEqual([]);
});

test("full intrusion: terminal, decoys, ATT&CK matrix, honeytoken and ledger all update live", async ({ page }) => {
  const errors = watchConsole(page);
  await openDashboard(page);
  await page.getByTestId("scenario-full_intrusion").click();

  const terminal = page.getByTestId("terminal");
  await expect(page.getByTestId("session-card")).toHaveCount(1);
  await expect(terminal).toContainText("[tripwire] Port scan");
  await expect(terminal).toContainText("[guard] plan accepted");

  // The attacker's shell session streams in.
  await expect(terminal).toContainText("$ whoami");
  await expect(terminal).toContainText("uid=1001(svc_backup)");
  await expect(terminal).toContainText("history -c", { timeout: 20_000 });
  await expect(page.getByTestId("session-state").first()).toHaveText("engaged");

  // Internal recon made the grid grow a database decoy.
  await expect(page.getByTestId("decoy")).toHaveCount(3);
  await expect(page.getByTestId("decoy").last()).toContainText("mysql:8.4");
  await expect(page.getByTestId("decoy").first()).toContainText("cap_drop=ALL");

  for (const id of ["T1595", "T1110.001", "T1078", "T1552.001", "T1046", "T1105", "T1048.003"]) {
    await expect(page.getByTestId(`technique-${id}`)).toHaveAttribute("data-hit", "true");
  }
  await expect(page.getByTestId("technique-T1496")).toHaveAttribute("data-hit", "false");
  await expect(page.getByTestId("matrix-summary")).toContainText(/1[0-3]\/13 tactics/);

  await expect(terminal).toContainText("STOLEN CREDENTIAL USED");
  await expect(page.getByTestId("ledger-status")).toContainText("INTACT");
  await expect(page.getByTestId("ledger-head")).toHaveText(/^[a-f0-9]{64}$/);
  expect(errors).toEqual([]);

  // PHANTOM_SCREENSHOT=1 refreshes the image used in the README.
  if (process.env.PHANTOM_SCREENSHOT) {
    await page.setViewportSize({ width: 1600, height: 1560 });
    await page.screenshot({ path: "../docs/dashboard.png" });
  }
});

test("poisoned planner: the hostile compose file is rejected and shown as such", async ({ page }) => {
  await openDashboard(page);
  await page.getByTestId("scenario-poisoned_model").click();

  const verdicts = page.getByTestId("verdict");
  await expect(verdicts).toHaveCount(2);
  await expect(verdicts.first()).toHaveAttribute("data-accepted", "false");
  await expect(verdicts.first()).toContainText("REJECTED");
  await expect(verdicts.first()).toContainText("docker.sock");
  await expect(verdicts.nth(1)).toHaveAttribute("data-accepted", "true");
  // Only catalog images were deployed.
  await expect(page.getByTestId("decoy").first()).toBeVisible();
  await expect(page.getByTestId("decoy").filter({ hasText: "alpine:3.20" })).toHaveCount(0);
});

test("attacker seat: typed commands are answered and hostile markup stays inert", async ({ page }) => {
  let dialogs = 0;
  page.on("dialog", (dialog) => {
    dialogs += 1;
    void dialog.dismiss();
  });
  await openDashboard(page);
  // Sessions from earlier tests are replayed on load; wait for the new one to
  // be selected and deployed so the command goes to the right shell.
  const cards = page.getByTestId("session-card");
  const before = await cards.count();
  await page.getByTestId("scenario-nmap_scan").click();
  await expect(cards).toHaveCount(before + 1);
  await expect(page.getByTestId("session-state").first()).toHaveText("deployed");

  const seat = page.getByLabel("attacker seat $");
  await expect(seat).toBeEnabled();
  await seat.fill("cat /etc/passwd");
  await seat.press("Enter");
  const terminal = page.getByTestId("terminal");
  await expect(terminal).toContainText("svc_backup:x:1001");
  await expect(page.getByTestId("technique-T1003.008")).toHaveAttribute("data-hit", "true");

  await seat.fill("echo <img src=x onerror=alert(1)><script>alert(2)</script>");
  await seat.press("Enter");
  await expect(terminal).toContainText("<img src=x onerror=alert(1)>");
  await expect(terminal.locator("img, script")).toHaveCount(0);
  expect(dialogs).toBe(0);
});

test("layout holds on a phone-sized viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openDashboard(page);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
  await expect(page.getByTestId("scenario-full_intrusion")).toBeVisible();
});
