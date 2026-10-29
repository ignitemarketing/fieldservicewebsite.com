export interface Env {
  ASSETS: Fetcher;
}

// Browser security headers. wrangler.jsonc runs the Worker first for every
// path except /_astro/*, so this is the one place the Content-Security-Policy
// is defined; public/_headers deliberately does not carry a CSP, because the
// Worker would overwrite it.
// script-src 'self' relies on astro.config.mjs keeping the waitlist script out
// of the HTML (vite assetsInlineLimit: 0); inline styles are still used.
// challenges.cloudflare.com (script-src and frame-src) is the Turnstile widget on the waitlist form.
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-src https://challenges.cloudflare.com; " +
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
  // Everything else is a static asset from the Astro build output.
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return withSecurityHeaders(await route(request, env));
  },
};
