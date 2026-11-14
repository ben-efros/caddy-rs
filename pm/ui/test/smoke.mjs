// Headless smoke test for the proxy-manager UI.
//
// The Rust side proves the HTTP seam (shell at `/`, assets, SPA fallback, JSON-only `/api/v1`).
// This test proves the other half: that the React bundle actually renders, talks to the documented
// API shapes, and survives a full sign-in → token refresh → host list → host creation round trip.
//
// It bundles the *source* entry (with CSS stripped) through esbuild and runs it inside jsdom, so a
// broken component, a missing element id, a wrong JSON field name or a broken refresh path fails
// here instead of in a browser.
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
  entryPoints: [path.join(root, 'src/main.tsx')],
  bundle: true,
  format: 'esm',
  write: false,
  loader: { '.css': 'empty' },
  jsx: 'automatic',
  jsxImportSource: 'react',
  define: { 'process.env.NODE_ENV': '"development"' },
  logLevel: 'silent',
});
const code = bundled.outputFiles[0].text;

// --- fake API ------------------------------------------------------------------------------

const calls = [];
let session = null;
// When set, the next `/hosts` GET with the old access token is rejected the way the real API
// rejects an expired JWT: 403 plus `WWW-Authenticate: Bearer error="invalid_token"`.
let expireAccessOnce = false;

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

// Global security headers as the API returns them (snake_case DTO keys, defaults applied).
let globalHeaders = {
  content_security_policy: "default-src 'self'",
  x_frame_options: 'DENY',
  x_content_type_options: 'nosniff',
  referrer_policy: 'strict-origin-when-cross-origin',
};
// Host 2 stores an explicit override; host 1 has none and inherits the global config.
const hostHeaders = {
  2: { content_security_policy: "default-src 'none'", referrer_policy: 'no-referrer' },
};

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
  if (url.pathname === '/api/v1/auth/refresh') {
    assert.equal(body.refresh_token, session.refresh_token, 'refresh sends the current refresh token');
    session = { access_token: 'access-2', refresh_token: 'refresh-2' };
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
    if (expireAccessOnce && init.headers?.authorization === 'Bearer access-1') {
      expireAccessOnce = false;
      return json(
        403,
        { error: { code: 'INVALID_TOKEN', message: 'access token expired' } },
        { 'www-authenticate': 'Bearer error="invalid_token"' },
      );
    }
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

  // Security headers: global config plus one host with an explicit override.
  if (url.pathname === '/api/v1/security-headers' && method === 'GET') {
    return json(200, globalHeaders);
  }
  if (url.pathname === '/api/v1/security-headers' && method === 'PUT') {
    if (String(body.content_security_policy || '').includes('forbidden')) {
      return json(422, {
        error: {
          code: 'VALIDATION',
          message: 'content_security_policy contains a forbidden source',
          location: 'security_headers.content_security_policy',
        },
      });
    }
    globalHeaders = body;
    return json(200, globalHeaders);
  }
  if (url.pathname === '/api/v1/hosts/1/security-headers' && method === 'GET') {
    return json(200, globalHeaders);
  }
  if (url.pathname === '/api/v1/hosts/2' && method === 'GET') {
    return json(
      200,
      {
        id: 2,
        domains: ['old.example.com'],
        tls: { mode: 'auto', certificateId: null, autoPolicyId: 1, sslForced: false, hstsEnabled: false, hstsSubdomains: false },
        enabled: false,
        spec: {
          kind: 'redirect',
          spec: { scheme: 'https', target: 'new.example.com', status: 301, preservePath: true },
        },
        revision: 2,
        securityHeaders: hostHeaders[2],
      },
      { etag: '"h2-r2"' },
    );
  }
  if (url.pathname === '/api/v1/hosts/2/security-headers' && method === 'GET') {
    return json(200, hostHeaders[2]);
  }
  if (url.pathname === '/api/v1/hosts/2/security-headers' && method === 'PUT') {
    assert.equal(init.headers?.['if-match'], '"h2-r2"', 'host save sends If-Match with the host revision');
    hostHeaders[2] = body;
    return json(200, hostHeaders[2], { etag: '"h2-r3"' });
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

// Node 26 exposes some of these as getter-only globals, so define rather than assign.
const globals = {
  window: dom.window,
  document: dom.window.document,
  navigator: dom.window.navigator,
  localStorage: dom.window.localStorage,
  history: dom.window.history,
  location: dom.window.location,
  HTMLElement: dom.window.HTMLElement,
  HTMLInputElement: dom.window.HTMLInputElement,
  HTMLSelectElement: dom.window.HTMLSelectElement,
  HTMLTextAreaElement: dom.window.HTMLTextAreaElement,
  HTMLButtonElement: dom.window.HTMLButtonElement,
  Element: dom.window.Element,
  Node: dom.window.Node,
  Event: dom.window.Event,
  MouseEvent: dom.window.MouseEvent,
  KeyboardEvent: dom.window.KeyboardEvent,
  FormData: dom.window.FormData,
  URLSearchParams: dom.window.URLSearchParams,
  getComputedStyle: dom.window.getComputedStyle,
  requestAnimationFrame: dom.window.requestAnimationFrame.bind(dom.window),
  cancelAnimationFrame: dom.window.cancelAnimationFrame.bind(dom.window),
  fetch: fakeFetch,
};
for (const [key, value] of Object.entries(globals)) {
  Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 25));
const settle = async () => {
  for (let i = 0; i < 3; i += 1) await tick();
};
const click = (selector) => {
  const element = document.querySelector(selector);
  assert.ok(element, `element ${selector} exists`);
  element.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
};

// Controlled React inputs keep a value tracker; a plain `element.value = x` is invisible to React.
// Write through the prototype setter so the component's onChange fires like a real keystroke.
const setValue = (selector, value) => {
  const element = document.querySelector(selector);
  assert.ok(element, `element ${selector} exists`);
  const prototype =
    element instanceof dom.window.HTMLSelectElement
      ? dom.window.HTMLSelectElement.prototype
      : element instanceof dom.window.HTMLTextAreaElement
        ? dom.window.HTMLTextAreaElement.prototype
        : dom.window.HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(element, value);
  element.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  element.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
};

// --- run -----------------------------------------------------------------------------------

await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
await settle();

assert.match(document.body.textContent, /Sign in to manage hosts/, 'login page renders');
assert.ok(document.querySelector('#auth-form'), 'login form renders');

// Sign in.
const form = document.querySelector('#auth-form');
form.querySelector('#username').value = 'admin';
form.querySelector('#password').value = 'secret';
form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
await settle();
await settle();

assert.equal(dom.window.location.pathname, '/', 'redirected to the dashboard after login');
assert.equal(localStorage.getItem('pm.access_token'), 'access-1', 'access token stored');
assert.match(document.body.textContent, /Dashboard/, 'dashboard renders');
assert.match(document.body.textContent, /app\.example\.com/, 'dashboard lists hosts');

// Token refresh: the first authenticated request on the Hosts page is rejected with the API's
// 403 + WWW-Authenticate marker, so the client must refresh, rotate tokens and retry once.
expireAccessOnce = true;
click('[data-nav="/hosts"]');
await settle();
await settle();

assert.equal(dom.window.location.pathname, '/hosts', 'navigated to the hosts page');
const refresh = calls.find((call) => call.path === '/api/v1/auth/refresh');
assert.ok(refresh, 'expired access token triggers POST /auth/refresh');
assert.equal(refresh.method, 'POST');
assert.deepEqual(refresh.body, { refresh_token: 'refresh-1' }, 'refresh uses the stored refresh token');
assert.equal(localStorage.getItem('pm.access_token'), 'access-2', 'rotated access token stored');
assert.equal(localStorage.getItem('pm.refresh_token'), 'refresh-2', 'rotated refresh token stored');
const retried = calls
  .filter((call) => call.method === 'GET' && call.path.split('?')[0] === '/api/v1/hosts')
  .at(-1);
assert.ok(retried, 'hosts request was retried after the refresh');
assert.equal(retried.headers.authorization, 'Bearer access-2', 'request retried with the new access token');
assert.match(document.body.textContent, /old\.example\.com/, 'hosts table renders rows after the refresh');

// Open the create form and submit it.
click('#create-host');
await settle();

const hostForm = document.querySelector('#host-form');
assert.ok(hostForm, 'host form opens');
hostForm.querySelector('#domains').value = 'new.example.com';
hostForm.querySelector('#upstream-host').value = '10.0.0.9';
hostForm.querySelector('#upstream-port').value = '8080';
hostForm.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
await settle();

const created = calls.find((call) => call.method === 'POST' && call.path === '/api/v1/hosts');
assert.ok(created, 'host creation was sent');
assert.equal(created.headers.authorization, 'Bearer access-2', 'bearer token attached');

// --- security headers tab -------------------------------------------------------------------
click('#security-headers-tab-button');
await settle();
await settle();

assert.equal(dom.window.location.pathname, '/hosts', 'security headers tab stays on the hosts route');
assert.ok(document.querySelector('#global-security-headers'), 'global security headers panel renders');
for (const id of [
  'global-csp',
  'global-xfo',
  'global-hsts-enabled',
  'global-referrer',
  'global-permissions-add',
  'global-xcto',
]) {
  assert.ok(document.querySelector(`#${id}`), `${id} renders in the global panel`);
}
assert.ok(
  document.querySelector('#host-security-headers-inherited'),
  'host 1 renders inherited values (dimmed) instead of an override',
);
assert.match(document.body.textContent, /Global security headers/);

// CSP: typing updates the generated-header preview.
setValue('#global-csp', "default-src 'self'; img-src 'self' data:");
await settle();
assert.match(
  document.querySelector('#global-csp-preview').textContent,
  /Content-Security-Policy/,
  'CSP preview renders the generated header',
);
assert.match(
  document.querySelector('#global-csp-preview').textContent,
  /img-src/,
  'CSP preview reflects the edited value',
);

// HSTS: enabling preload must render the irreversible warning and the generated header.
click('#global-hsts-enabled');
await settle();
assert.ok(document.querySelector('#global-hsts-max-age'), 'HSTS max-age field appears when enabled');
click('#global-hsts-preload');
await settle();
assert.ok(
  document.querySelector('#global-hsts-preload-warning'),
  'preload warning banner renders',
);
assert.match(
  document.querySelector('#global-security-headers').textContent,
  /Strict-Transport-Security: max-age=/,
  'HSTS generated header renders',
);

// Save the global config: the PUT carries the snake_case DTO and the confirmation renders.
click('#save-global-security-headers');
await settle();
await settle();
const globalSave = calls.find(
  (call) => call.method === 'PUT' && call.path === '/api/v1/security-headers',
);
assert.ok(globalSave, 'saving the global panel sends PUT /api/v1/security-headers');
assert.equal(globalSave.body.content_security_policy, "default-src 'self'; img-src 'self' data:");
assert.equal(globalSave.body.strict_transport_security.preload, true);
assert.ok(document.querySelector('#global-security-headers-saved'), 'global save confirmation renders');

// An API validation failure is shown inline, with the server's location.
setValue('#global-csp', "default-src 'self' 'forbidden'");
await settle();
click('#save-global-security-headers');
await settle();
await settle();
const inlineError = document.querySelector('#global-security-headers .error-message');
assert.ok(inlineError, 'API validation error renders inline in the global panel');
assert.match(inlineError.textContent, /forbidden/, 'the server message is shown');

// Per-host override: host 2 stores its own config, so the panel shows an override, not inheritance.
setValue('#security-headers-host', '2');
await settle();
await settle();
assert.ok(document.querySelector('#host-security-headers-override'), 'host 2 shows its own override');
assert.equal(document.querySelector('#host-csp').value, "default-src 'none'");

setValue('#host-csp', "default-src 'self'");
await settle();
click('#save-host-security-headers');
await settle();
await settle();
const hostSave = calls.find(
  (call) => call.method === 'PUT' && call.path === '/api/v1/hosts/2/security-headers',
);
assert.ok(hostSave, 'saving the per-host panel sends PUT /api/v1/hosts/2/security-headers');
assert.equal(hostSave.body.content_security_policy, "default-src 'self'");
assert.ok(document.querySelector('#host-security-headers-saved'), 'host save confirmation renders');

// The remaining pages must render against the same fake API: a component that dereferences a
// missing field throws here instead of in the browser.
for (const [path, needle] of [
  ['/certificates', 'secure.example.com'],
  ['/config', 'Assembled Caddy JSON'],
  ['/settings', 'Session and server facts'],
]) {
  click(`[data-nav="${path}"]`);
  await settle();
  await settle();
  assert.equal(dom.window.location.pathname, path, `navigated to ${path}`);
  assert.match(document.body.textContent, new RegExp(needle), `${path} renders`);
}

// Back to the dashboard for the sign-out button, which lives in the shared header.
click('[data-nav="/"]');
await settle();

// Sign out.
click('#logout-btn');
await settle();
await settle();
assert.equal(dom.window.location.pathname, '/login', 'signed out to the login page');
assert.equal(localStorage.getItem('pm.access_token'), null, 'access token cleared');
const logout = calls.find((call) => call.path === '/api/v1/auth/logout');
assert.deepEqual(logout.body, { refreshToken: 'refresh-2' }, 'logout revokes the refresh token by body');

console.log('ui smoke test passed:', calls.length, 'API calls');
