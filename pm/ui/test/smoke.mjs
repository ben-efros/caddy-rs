// Headless smoke test for the proxy-manager UI.
//
// The Rust side proves the HTTP seam (shell at `/`, assets, SPA fallback, JSON-only `/api/v1`).
// This test proves the other half: that the bundle actually renders, talks to the documented API
// shapes, and survives a full sign-in → host list → host creation round trip.
//
// It runs the *source* modules through esbuild (with CSS stripped) inside jsdom, so a broken
// template, a missing element id, or a wrong JSON field name fails here instead of in a browser.
//
// Usage: node test/smoke.mjs   (after `npm install`)

import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

// --- bundle the source without CSS ---------------------------------------------------------

const bundled = await build({
  entryPoints: [path.join(root, 'src/main.js')],
  bundle: true,
  format: 'esm',
  write: false,
  loader: { '.css': 'empty' },
  logLevel: 'silent',
});
const code = bundled.outputFiles[0].text;

// --- fake API ------------------------------------------------------------------------------

const calls = [];
let session = null;

function json(status, body, headers = {}) {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const hosts = [
  { id: 1, domains: ['app.example.com'], kind: 'proxy', enabled: true, revision: 1, tlsMode: 'disabled' },
  { id: 2, domains: ['old.example.com'], kind: 'redirect', enabled: false, revision: 2, tlsMode: 'auto' },
];

async function fakeFetch(input, init = {}) {
  const url = new URL(String(input), 'http://127.0.0.1:81');
  const method = init.method || 'GET';
  const body = init.body ? JSON.parse(init.body) : undefined;
  calls.push({ method, path: url.pathname + url.search, body, headers: init.headers || {} });

  if (url.pathname === '/api/v1/setup') return json(200, { configured: true });
  if (url.pathname === '/api/v1/version') return json(200, { version: '0.1.0', caddyRs: '0.1.0-trial.5' });
  if (url.pathname === '/api/v1/health') return json(200, { status: 'ok', setup: true });

  if (url.pathname === '/api/v1/auth/login') {
    assert.equal(body.username, 'admin');
    assert.equal(body.password, 'secret');
    session = { access_token: 'access-1', refresh_token: 'refresh-1' };
    return json(200, session);
  }
  if (url.pathname === '/api/v1/auth/me') {
    return json(200, {
      id: 1,
      username: 'admin',
      role: { name: 'admin' },
      totp_enabled: false,
      auth_epoch: 0,
    });
  }
  if (url.pathname === '/api/v1/auth/logout') return json(204, null);

  if (url.pathname === '/api/v1/hosts' && method === 'GET') {
    return json(200, { items: hosts, total: hosts.length, limit: 50, offset: 0 });
  }
  if (url.pathname === '/api/v1/hosts' && method === 'POST') {
    assert.deepEqual(body, {
      domains: ['new.example.com'],
      tls: { mode: 'disabled', sslForced: false, hstsEnabled: false, hstsSubdomains: false },
      spec: {
        kind: 'proxy',
        spec: {
          upstream: { scheme: 'http', host: '10.0.0.9', port: 8080 },
          websocket: false,
          preserveHost: true,
        },
      },
      enabled: true,
    });
    return json(201, { id: 3, ...body, revision: 1 }, { etag: '"h3-r1"' });
  }
  if (url.pathname === '/api/v1/hosts/1') {
    return json(
      200,
      {
        id: 1,
        domains: ['app.example.com'],
        tls: { mode: 'disabled', certificateId: null, autoPolicyId: null, sslForced: false, hstsEnabled: false, hstsSubdomains: false },
        enabled: true,
        spec: {
          kind: 'proxy',
          spec: { upstream: { scheme: 'http', host: '10.0.0.5', port: 8080 }, websocket: true, preserveHost: true },
        },
        revision: 1,
      },
      { etag: '"h1-r1"' },
    );
  }

  if (url.pathname === '/api/v1/certificates') {
    return json(200, {
      items: [
        {
          policyId: 1,
          origin: 'auto_generated',
          name: 'Certificate intent for secure.example.com',
          domains: ['secure.example.com'],
          issuer: 'letsencrypt',
          challenge: 'http01',
          enabled: true,
          revision: 1,
          status: 'pending',
        },
      ],
      total: 1,
      limit: 200,
      offset: 0,
    });
  }
  if (url.pathname === '/api/v1/config') return json(200, { apps: { http: { servers: {} } } }, { etag: 'W/"abc"' });
  if (url.pathname === '/api/v1/config/revisions') {
    return json(200, {
      items: [{ revision: 4, hash: 'deadbeef', status: 'applied', changed: true, recordedAtUnix: 1_700_000_000 }],
      total: 1,
      limit: 50,
      offset: 0,
    });
  }

  return json(404, { error: { code: 'NOT_FOUND', message: `no route ${method} ${url.pathname}` } });
}

// --- jsdom harness -------------------------------------------------------------------------

const dom = new JSDOM('<!DOCTYPE html><html><body><div id="app"></div></body></html>', {
  url: 'http://127.0.0.1:81/',
  pretendToBeVisual: true,
});

globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.localStorage = dom.window.localStorage;
globalThis.history = dom.window.history;
globalThis.location = dom.window.location;
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.FormData = dom.window.FormData;
globalThis.URLSearchParams = dom.window.URLSearchParams;
globalThis.fetch = fakeFetch;

const tick = () => new Promise((resolve) => setTimeout(resolve, 20));

// --- run -----------------------------------------------------------------------------------

await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
await tick();

const app = document.getElementById('app');
assert.match(app.textContent, /Sign in to manage hosts/, 'login page renders');

// Sign in.
const form = document.querySelector('#auth-form');
form.querySelector('#username').value = 'admin';
form.querySelector('#password').value = 'secret';
form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
await tick();
await tick();

assert.equal(dom.window.location.pathname, '/', 'redirected to the dashboard after login');
assert.equal(localStorage.getItem('pm.access_token'), 'access-1', 'access token stored');
assert.match(document.body.textContent, /Dashboard/, 'dashboard renders');
assert.match(document.body.textContent, /app\.example\.com/, 'dashboard lists hosts');

// Hosts page.
document.querySelector('[data-nav="/hosts"]').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
await tick();
await tick();
assert.equal(dom.window.location.pathname, '/hosts');
assert.match(document.body.textContent, /old\.example\.com/, 'hosts table renders rows');

// Open the create form and submit it.
document.querySelector('#create-host').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
await tick();
await tick();

const hostForm = document.querySelector('#host-form');
assert.ok(hostForm, 'host form opens');
hostForm.querySelector('#domains').value = 'new.example.com';
hostForm.querySelector('#upstream-host').value = '10.0.0.9';
hostForm.querySelector('#upstream-port').value = '8080';
hostForm.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
await tick();
await tick();

const created = calls.find((call) => call.method === 'POST' && call.path === '/api/v1/hosts');
assert.ok(created, 'host creation was sent');
assert.equal(created.headers.authorization, 'Bearer access-1', 'bearer token attached');

// The remaining pages must render against the same fake API: a template that dereferences a
// missing field throws here instead of in the browser.
for (const [path, needle] of [
  ['/certificates', 'secure.example.com'],
  ['/config', 'Assembled Caddy JSON'],
  ['/settings', 'Session and server facts'],
]) {
  document.querySelector(`[data-nav="${path}"]`).dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await tick();
  await tick();
  assert.equal(dom.window.location.pathname, path, `navigated to ${path}`);
  assert.match(document.body.textContent, new RegExp(needle), `${path} renders`);
}

// Back to the dashboard for the sign-out button, which lives in the shared header.
document.querySelector('[data-nav="/"]').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
await tick();

// Sign out.
document.querySelector('#logout-btn').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
await tick();
await tick();
assert.equal(dom.window.location.pathname, '/login', 'signed out to the login page');
assert.equal(localStorage.getItem('pm.access_token'), null, 'access token cleared');
const logout = calls.find((call) => call.path === '/api/v1/auth/logout');
assert.deepEqual(logout.body, { refreshToken: 'refresh-1' }, 'logout revokes the refresh token by body');

console.log('ui smoke test passed:', calls.length, 'API calls');
