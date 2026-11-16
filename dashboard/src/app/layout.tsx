import type { Metadata, Viewport } from "next";
import { connection } from "next/server";
import type { ReactNode } from "react";
// Fonts are bundled with the app, so the CSP can keep font-src at 'self'.
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "Phantom Cloud",
  description: "Threat actor dashboard for the Phantom Cloud deception grid",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#050505" };

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Render per request: the CSP nonce set in proxy.ts must be fresh every time.
  await connection();
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
