// Thin client for the proxy-manager management API.
//
// Everything is same-origin (`/api/v1`) and uses `fetch`, so the bundle has no runtime dependency
// and the server's Content-Security-Policy can stay `connect-src 'self'`.
//
// Session handling: the access token is a short-lived JWT sent as a bearer token; the refresh token
// is rotated by `POST /auth/refresh`. When the API rejects an access token it answers `403` *and*
// `WWW-Authenticate: Bearer error="invalid_token"` — the header is the only way to tell "session
// expired" apart from "you may not do that", so that is what triggers a refresh-and-retry.

const BASE = '/api/v1';

const ACCESS_KEY = 'pm.access_token';
const REFRESH_KEY = 'pm.refresh_token';

let accessToken = localStorage.getItem(ACCESS_KEY);
let refreshToken = localStorage.getItem(REFRESH_KEY);
let sessionListener = () => {};

export class ApiError extends Error {
  constructor(message, { status = 0, code = 'NETWORK_ERROR', location = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.location = location;
  }
}

export function onSessionChange(listener) {
  sessionListener = listener;
}

export function getAccessToken() {
  return accessToken;
}

export function isAuthenticated() {
  return Boolean(accessToken);
}

export function setSession(session) {
  accessToken = session.access_token || null;
  refreshToken = session.refresh_token || null;
  if (accessToken) localStorage.setItem(ACCESS_KEY, accessToken);
  else localStorage.removeItem(ACCESS_KEY);
  if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken);
  else localStorage.removeItem(REFRESH_KEY);
  sessionListener(isAuthenticated());
}

export function clearSession() {
  setSession({});
}

async function refreshSession() {
  if (!refreshToken) return false;
  const response = await fetch(`${BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!response.ok) {
    clearSession();
    return false;
  }
  setSession(await response.json());
  return true;
}

async function request(path, options = {}) {
  const { method = 'GET', body, headers = {}, auth = true, retry = true } = options;
  const requestHeaders = { ...headers };
  if (body !== undefined) requestHeaders['content-type'] = 'application/json';
  if (auth && accessToken) requestHeaders.authorization = `Bearer ${accessToken}`;

  const response = await fetch(BASE + path, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.headers.get('www-authenticate') && retry && refreshToken) {
    if (await refreshSession()) {
      return request(path, { ...options, retry: false });
    }
  }

  const etag = response.headers.get('etag');
  if (response.status === 204) return { data: null, etag, status: 204 };

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!response.ok) {
    const detail = (data && data.error) || {};
    throw new ApiError(detail.message || `${response.status} ${response.statusText}`, {
      status: response.status,
      code: detail.code || 'HTTP_ERROR',
      location: detail.location || null,
    });
  }

  return { data, etag, status: response.status };
}

// --- authentication -------------------------------------------------------------------------

export const auth = {
  setupStatus: () => request('/setup', { auth: false }),
  setup: (username, password, totpCode) =>
    request('/auth/setup', {
      method: 'POST',
      auth: false,
      body: { username, password, totp_code: totpCode || null },
    }),
  login: (username, password, totpCode) =>
    request('/auth/login', {
      method: 'POST',
      auth: false,
      body: { username, password, totp_code: totpCode || null },
    }),
  me: () => request('/auth/me'),
  logout: () =>
    request('/auth/logout', {
      method: 'POST',
      body: refreshToken ? { refreshToken } : {},
    }),
};

// --- hosts ----------------------------------------------------------------------------------

export const hosts = {
  list: (params = {}) => request(`/hosts${query(params)}`),
  get: (id) => request(`/hosts/${id}`),
  create: (payload) => request('/hosts', { method: 'POST', body: payload }),
  replace: (id, payload, etag) =>
    request(`/hosts/${id}`, { method: 'PUT', body: payload, headers: ifMatch(etag) }),
  remove: (id, etag) =>
    request(`/hosts/${id}`, { method: 'DELETE', headers: ifMatch(etag) }),
  setEnabled: (id, enabled, etag) =>
    request(`/hosts/${id}/${enabled ? 'enable' : 'disable'}`, {
      method: 'POST',
      headers: ifMatch(etag),
    }),
};

// --- certificates ---------------------------------------------------------------------------

export const certificates = {
  list: (params = {}) => request(`/certificates${query(params)}`),
  intent: (id) => request(`/certificates/intent/${id}`),
  createIntent: (payload) => request('/certificates/intent', { method: 'POST', body: payload }),
  custom: (id) => request(`/certificates/custom/${id}`),
  createCustom: (payload) => request('/certificates/custom', { method: 'POST', body: payload }),
  removeCustom: (id, etag) =>
    request(`/certificates/custom/${id}`, { method: 'DELETE', headers: ifMatch(etag) }),
};

// --- configuration --------------------------------------------------------------------------

export const config = {
  get: () => request('/config'),
  apply: () => request('/config/apply', { method: 'POST' }),
  revisions: (params = {}) => request(`/config/revisions${query(params)}`),
};

export const system = {
  health: () => request('/health', { auth: false }),
  version: () => request('/version', { auth: false }),
};

function query(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, value);
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : '';
}

function ifMatch(etag) {
  return { 'if-match': etag || '*' };
}
