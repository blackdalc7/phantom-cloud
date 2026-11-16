import type { NextRequest } from "next/server";

// Backend-for-frontend. The orchestrator's bearer token lives only in this
// server process; the browser never sees it and can only reach the routes
// listed below.

export const dynamic = "force-dynamic";

const UPSTREAM = process.env.PHANTOM_API_URL ?? "http://127.0.0.1:8400";
const MAX_BODY_BYTES = 2048;

const ROUTES: Record<"GET" | "POST", RegExp[]> = {
  GET: [/^state$/, /^stream$/, /^events$/, /^evidence\/verify$/],
  POST: [/^simulate$/, /^sessions\/[a-f0-9]{10}\/(exec|close)$/, /^canary\/lookup$/],
};

function json(status: number, detail: string) {
  return Response.json({ detail }, { status, headers: { "Cache-Control": "no-store" } });
}

async function forward(request: NextRequest, method: "GET" | "POST", path: string[]) {
  const token = process.env.PHANTOM_API_TOKEN;
  if (!token) return json(503, "PHANTOM_API_TOKEN is not configured");

  const target = path.join("/");
  if (!ROUTES[method].some((route) => route.test(target))) return json(404, "not found");

  let body: string | undefined;
  if (method === "POST") {
    // This proxy attaches credentials, so a cross-site page must not be able
    // to drive it. Browsers always send Origin on cross-origin POSTs.
    const origin = request.headers.get("origin");
    if (origin && new URL(origin).host !== request.headers.get("host")) {
      return json(403, "cross-origin request refused");
    }
    if (request.headers.get("sec-fetch-site") === "cross-site") {
      return json(403, "cross-origin request refused");
    }
    if (!request.headers.get("content-type")?.startsWith("application/json")) {
      return json(415, "expected application/json");
    }
    body = await request.text();
    if (body.length > MAX_BODY_BYTES) return json(413, "request body too large");
  }

  const url = new URL(`/api/${target}`, UPSTREAM);
  const after = request.nextUrl.searchParams.get("after");
  if (after && /^\d{1,12}$/.test(after)) url.searchParams.set("after", after);

  const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const lastEventId = request.headers.get("last-event-id");
  if (lastEventId && /^\d{1,12}$/.test(lastEventId)) headers["Last-Event-ID"] = lastEventId;

  let upstream: Response;
  try {
    // Passing the signal closes the upstream stream when the browser tab goes away.
    upstream = await fetch(url, { method, headers, body, signal: request.signal, cache: "no-store" });
  } catch {
    return json(502, "orchestrator unreachable");
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-store, no-transform",
      "X-Accel-Buffering": "no",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

type Context = { params: Promise<{ path: string[] }> };

export async function GET(request: NextRequest, { params }: Context) {
  return forward(request, "GET", (await params).path);
}

export async function POST(request: NextRequest, { params }: Context) {
  return forward(request, "POST", (await params).path);
}
