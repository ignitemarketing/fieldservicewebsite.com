export interface Env {
  ASSETS: Fetcher;
  POSTMARK_SERVER_TOKEN: string;
  // Workers rate-limit binding (wrangler.jsonc `ratelimits`); absent in local runs.
  WAITLIST_LIMITER?: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_FSM = ['Jobber', 'ServiceTitan', 'Housecall Pro', 'Other', ''];

// Where signup notifications go, and the verified Postmark sender they come from.
const NOTIFY_TO = 'colin+newco@colingreig.com';
const NOTIFY_FROM = 'newco@jdmbuysell.com';

// A real signup is well under 1 KB; anything bigger is junk or abuse.
const MAX_BODY_BYTES = 4096;
const MAX_SOURCE_CHARS = 100;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

async function handleWaitlist(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method_not_allowed' }, 405, { allow: 'POST' });
  }

  // Browser form posts from our own pages send Sec-Fetch-Site and/or Origin.
  const origin = request.headers.get('origin');
  const sameOrigin =
    request.headers.get('sec-fetch-site') === 'same-origin' ||
    (origin !== null && origin === new URL(request.url).origin);
  if (!sameOrigin) {
    return json({ ok: false, error: 'forbidden' }, 403);
  }

  // Cheap rejects before the body is read.
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > MAX_BODY_BYTES) {
    return json({ ok: false, error: 'payload_too_large' }, 413);
  }
  if (env.WAITLIST_LIMITER) {
    const key = request.headers.get('cf-connecting-ip') || 'unknown';
    const { success } = await env.WAITLIST_LIMITER.limit({ key });
    if (!success) {
      return json({ ok: false, error: 'rate_limited' }, 429, { 'retry-after': '60' });
    }
  }

  let data: Record<string, unknown>;
  try {
    // content-length can be absent (chunked) or wrong, so cap the bytes actually read.
    const raw = await request.text();
    if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
      return json({ ok: false, error: 'payload_too_large' }, 413);
    }
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = JSON.parse(raw);
    } else {
      const form = await new Response(raw, { headers: { 'content-type': ct } }).formData();
      data = Object.fromEntries(form.entries());
    }
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      throw new Error('not an object');
    }
  } catch {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  // Honeypot: bots fill this hidden field — silently accept, send nothing.
  if (typeof data.company === 'string' && data.company.trim() !== '') {
    return json({ ok: true });
  }

  const email = String(data.email ?? '').trim().toLowerCase();
  const fsm = String(data.fsm ?? '').trim();
  const source = String(data.source ?? '').trim().slice(0, MAX_SOURCE_CHARS) || 'unknown';
  const page = String(data.page ?? '').slice(0, 300);

  if (!EMAIL_RE.test(email) || email.length > 254) {
    return json({ ok: false, error: 'invalid_email' }, 422);
  }
  if (!ALLOWED_FSM.includes(fsm)) {
    return json({ ok: false, error: 'invalid_fsm' }, 422);
  }

  const referrer = (request.headers.get('referer') || '').slice(0, 300);
  const ua = (request.headers.get('user-agent') || '').slice(0, 300);
  const country = request.headers.get('cf-ipcountry') || '';

  const textBody = [
    'New waitlist signup',
    '',
    `Source:   ${source}`,
    `Email:    ${email}`,
    `FSM:      ${fsm || '(not provided)'}`,
    `Page:     ${page || '/'}`,
    `Country:  ${country || '(unknown)'}`,
    `Referrer: ${referrer || '(none)'}`,
    `Agent:    ${ua || '(unknown)'}`,
  ].join('\n');

  try {
    const res = await fetch('https://api.postmarkapp.com/email', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-Postmark-Server-Token': env.POSTMARK_SERVER_TOKEN,
      },
      body: JSON.stringify({
        From: NOTIFY_FROM,
        To: NOTIFY_TO,
        ReplyTo: email,
        Subject: `[newco] Waitlist: ${source} — ${email}`,
        TextBody: textBody,
        MessageStream: 'outbound',
      }),
    });
    if (!res.ok) {
      return json({ ok: false, error: 'server_error' }, 500);
    }
  } catch {
    return json({ ok: false, error: 'server_error' }, 500);
  }

  return json({ ok: true });
}

// Browser security headers for responses the Worker produces. Static assets
// are served by Cloudflare without running this Worker, so public/_headers
// carries the same set for them: keep the two in sync.
// script-src 'self' relies on astro.config.mjs keeping the waitlist script out
// of the HTML (vite assetsInlineLimit: 0); inline styles are still used.
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

function withSecurityHeaders(res: Response): Response {
  // Redirects and 101s can have immutable headers; copy into a fresh Response.
  const headers = new Headers(res.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  // Upgrade plain HTTP. 308 keeps the method for non-GET requests (a POST must not turn into a GET).
  if (url.protocol === 'http:') {
    url.protocol = 'https:';
    return Response.redirect(url.toString(), request.method === 'GET' || request.method === 'HEAD' ? 301 : 308);
  }
  if (url.pathname === '/api/waitlist') {
    return handleWaitlist(request, env);
  }
  // Everything else is a static asset from the Astro build output.
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return withSecurityHeaders(await route(request, env));
  },
};
