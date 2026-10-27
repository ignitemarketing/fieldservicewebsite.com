export interface Env {
  ASSETS: Fetcher;
  POSTMARK_SERVER_TOKEN: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_FSM = ['Jobber', 'ServiceTitan', 'Housecall Pro', 'Other', ''];

// Where signup notifications go, and the verified Postmark sender they come from.
const NOTIFY_TO = 'colin+newco@colingreig.com';
const NOTIFY_FROM = 'newco@jdmbuysell.com';

async function handleWaitlist(request: Request, env: Env): Promise<Response> {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });

  let data: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await request.json();
    } else {
      const form = await request.formData();
      data = Object.fromEntries(form.entries());
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
  const source = String(data.source ?? '').trim() || 'unknown';
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
  if (url.pathname === '/api/waitlist' && request.method === 'POST') {
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
