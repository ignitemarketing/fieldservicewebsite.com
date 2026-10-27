import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://fieldservicewebsite.com',
  integrations: [sitemap()],
  build: { inlineStylesheets: 'auto' },
  // Ship the waitlist script as /_astro/*.js, not inline, so the CSP can use script-src 'self'.
  vite: { build: { assetsInlineLimit: 0 } },
});
