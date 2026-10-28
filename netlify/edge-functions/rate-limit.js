const WINDOW_MS = 60_000;
const MAX_REQUESTS = 60;
const hits = new Map(); // ip -> { count, resetAt }

export default async (request, context) => {
  const ip = context.ip || request.headers.get("x-nf-client-connection-ip") || "unknown";
  const now = Date.now();

  if (hits.size > 5000) {
    for (const [key, v] of hits) if (v.resetAt <= now) hits.delete(key);
  }

  let entry = hits.get(ip);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 0, resetAt: now + WINDOW_MS };
    hits.set(ip, entry);
  }
  entry.count++;

  if (entry.count > MAX_REQUESTS) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return new Response("Too Many Requests", {
      status: 429,
      headers: {
        "Retry-After": String(retryAfter),
        "Content-Type": "text/plain",
        "Cache-Control": "no-store",
      },
    });
  }

  return; // under the limit: continue to the site
};

export const config = { path: "/*" };