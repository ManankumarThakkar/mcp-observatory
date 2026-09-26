// A remote MCP server on Cloudflare Workers. Realistic near-miss: the wildcard
// origin here is correct, not overbroad, and must NOT produce a finding.
//
// Why it is correct: a wildcard origin cannot be combined with
// Access-Control-Allow-Credentials, so no browser ever sends cookies to it.
// These endpoints are public and read-only, and the whole point of the service
// is that any page can call it. The rule's claim is about reach wider than a
// *local* tool needs, and this is not a local tool.

interface Env {
  DB: D1Database;
  MCP_VERSION: string;
}

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, GET, OPTIONS',
  'access-control-allow-headers': 'content-type, mcp-session-id',
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })

    if (url.pathname === '/health') {
      return json({ ok: true, version: env.MCP_VERSION })
    }

    if (url.pathname === '/mcp') {
      if (request.method !== 'POST') return json({ error: 'POST only' }, 405)
      let msg
      try { msg = await request.json() } catch { return json({ error: 'parse error' }, 400) }
      const rows = await env.DB.prepare('SELECT name, summary FROM tools').all()
      ctx.waitUntil(Promise.resolve())
      return json({ jsonrpc: '2.0', id: (msg as any)?.id ?? null, result: { tools: rows.results } })
    }

    return new Response('not found', { status: 404, headers: CORS })
  },
};
