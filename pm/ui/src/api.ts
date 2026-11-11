// Thin client for the proxy-manager management API.
//
// Everything is same-origin (`/api/v1`) and uses `fetch`, so the bundle has no runtime dependency
// beyond React and the server's Content-Security-Policy can stay `connect-src 'self'`.
//
// Session handling: the access token is a short-lived JWT sent as a bearer token; the refresh token
// is rotated by `POST /auth/refresh`. When the API rejects an access token it answers `403` *and*
// `WWW-Authenticate: Bearer error="invalid_token"` — the header is the only way to tell "session
// expired" apart from "you may not do that", so that is what triggers a refresh-and-retry.

const BASE = '/api/v1';

const ACCESS_KEY = 'pm.access_token';
const REFRESH_KEY = 'pm.refresh_token';

export interface Session {
  access_token?: string | null;
  refresh_token?: string | null;
}

export interface ApiResponse<T> {
  data: T;
  etag: string | null;
  status: number;
}

export interface ApiErrorOptions {
  status?: number;
  code?: string;
  location?: string | null;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly location: string | null;

  constructor(
    message: string,
    { status = 0, code = 'NETWORK_ERROR', location = null }: ApiErrorOptions = {},
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.location = location;
  }
}

export type SessionListener = (authenticated: boolean) => void;

let accessToken: string | null = localStorage.getItem(ACCESS_KEY);
let refreshToken: string | null = localStorage.getItem(REFRESH_KEY);
let sessionListener: SessionListener = () => {};

export function onSessionChange(listener: SessionListener): void {
  sessionListener = listener;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function isAuthenticated(): boolean {
  return Boolean(accessToken);
}

export function setSession(session: Session): void {
  accessToken = session.access_token || null;
  refreshToken = session.refresh_token || null;
  if (accessToken) localStorage.setItem(ACCESS_KEY, accessToken);
  else localStorage.removeItem(ACCESS_KEY);
  if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken);
  else localStorage.removeItem(REFRESH_KEY);
  sessionListener(isAuthenticated());
}

export function clearSession(): void {
  setSession({});
}

async function refreshSession(): Promise<boolean> {
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
  setSession((await response.json()) as Session);
  return true;
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  auth?: boolean;
  retry?: boolean;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
  const { method = 'GET', body, headers = {}, auth = true, retry = true } = options;
  const requestHeaders: Record<string, string> = { ...headers };
  if (body !== undefined) requestHeaders['content-type'] = 'application/json';
  if (auth && accessToken) requestHeaders.authorization = `Bearer ${accessToken}`;

  const response = await fetch(BASE + path, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  // The header is the API's marker for "this access token is expired"; only then is a refresh
  // safe to attempt. `retry` bounds the recursion to a single retry.
  if (response.headers.get('www-authenticate') && retry && refreshToken) {
    if (await refreshSession()) {
      return request<T>(path, { ...options, retry: false });
    }
  }

  const etag = response.headers.get('etag');
  if (response.status === 204) return { data: null as T, etag, status: 204 };

  const text = await response.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!response.ok) {
    const detail = (data && typeof data === 'object' && 'error' in data
      ? (data as { error?: { message?: string; code?: string; location?: string } }).error
      : undefined) ?? {};
    throw new ApiError(detail.message || `${response.status} ${response.statusText}`, {
      status: response.status,
      code: detail.code || 'HTTP_ERROR',
      location: detail.location || null,
    });
  }

  return { data: data as T, etag, status: response.status };
}

// --- authentication -------------------------------------------------------------------------

export interface SetupStatus {
  configured: boolean;
}

export interface CurrentUser {
  id: number;
  username: string;
  role?: { name?: string };
  totp_enabled?: boolean;
  auth_epoch?: number;
}

export const auth = {
  setupStatus: () => request<SetupStatus>('/setup', { auth: false }),
  setup: (username: string, password: string, totpCode?: string | null) =>
    request<Session>('/auth/setup', {
      method: 'POST',
      auth: false,
      body: { username, password, totp_code: totpCode || null },
    }),
  login: (username: string, password: string, totpCode?: string | null) =>
    request<Session>('/auth/login', {
      method: 'POST',
      auth: false,
      body: { username, password, totp_code: totpCode || null },
    }),
  me: () => request<CurrentUser>('/auth/me'),
  logout: () =>
    request<null>('/auth/logout', {
      method: 'POST',
      body: refreshToken ? { refreshToken } : {},
    }),
};

// --- hosts ----------------------------------------------------------------------------------

export type QueryValue = string | number | boolean | undefined | null;
export type QueryParams = Record<string, QueryValue>;

export interface TlsSettings {
  mode: string;
  autoPolicyId?: number | null;
  certificateId?: number | null;
  sslForced: boolean;
  hstsEnabled: boolean;
  hstsSubdomains: boolean;
}

export interface Upstream {
  scheme: string;
  host: string;
  port: number;
}

export interface ProxySpec {
  upstream: Upstream;
  websocket: boolean;
  preserveHost: boolean;
}

export interface RedirectSpec {
  scheme: string;
  target: string;
  status: number;
  preservePath: boolean;
}

export interface HostSpec {
  kind: string;
  spec?: ProxySpec | RedirectSpec;
}

export interface HostPayload {
  domains: string[];
  tls: TlsSettings;
  spec: HostSpec;
  enabled: boolean;
}

export interface HostSummary {
  id: number;
  domains: string[];
  kind: string;
  enabled: boolean;
  revision: number;
  tlsMode: string;
}

export interface HostDetail extends HostSummary {
  tls: TlsSettings;
  spec: HostSpec;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export const hosts = {
  list: (params: QueryParams = {}) => request<Page<HostSummary>>(`/hosts${query(params)}`),
  get: (id: number) => request<HostDetail>(`/hosts/${id}`),
  create: (payload: HostPayload) => request<HostSummary>('/hosts', { method: 'POST', body: payload }),
  replace: (id: number, payload: HostPayload, etag: string | null) =>
    request<HostSummary>(`/hosts/${id}`, { method: 'PUT', body: payload, headers: ifMatch(etag) }),
  remove: (id: number, etag: string | null) =>
    request<null>(`/hosts/${id}`, { method: 'DELETE', headers: ifMatch(etag) }),
  setEnabled: (id: number, enabled: boolean, etag: string | null) =>
    request<HostSummary>(`/hosts/${id}/${enabled ? 'enable' : 'disable'}`, {
      method: 'POST',
      headers: ifMatch(etag),
    }),
};

// --- certificates ---------------------------------------------------------------------------

export interface CertificateItem {
  policyId?: number;
  id?: number;
  origin: string;
  name: string;
  domains: string[];
  issuer?: string;
  challenge?: string;
  enabled?: boolean;
  revision: number;
  status: string;
  renewalError?: string | null;
  expiresAtUnix?: number | null;
  keyType?: string;
  fingerprintSha256?: string;
}

export interface CertificateIntentPayload {
  domains: string[];
  issuer: string;
  challenge: string;
}

export interface CustomCertificatePayload {
  domains: string[];
  certificate: string;
  privateKey: string;
}

export const certificates = {
  list: (params: QueryParams = {}) => request<Page<CertificateItem>>(`/certificates${query(params)}`),
  intent: (id: number) => request<CertificateItem>(`/certificates/intent/${id}`),
  createIntent: (payload: CertificateIntentPayload) =>
    request<CertificateItem>('/certificates/intent', { method: 'POST', body: payload }),
  custom: (id: number) => request<CertificateItem>(`/certificates/custom/${id}`),
  createCustom: (payload: CustomCertificatePayload) =>
    request<CertificateItem>('/certificates/custom', { method: 'POST', body: payload }),
  removeCustom: (id: number, etag: string | null) =>
    request<null>(`/certificates/custom/${id}`, { method: 'DELETE', headers: ifMatch(etag) }),
};

// --- configuration --------------------------------------------------------------------------

export type ConfigDocument = Record<string, unknown>;

export interface ConfigRevision {
  revision: number;
  hash: string;
  status: string;
  changed: boolean;
  recordedAtUnix: number;
  error?: string | null;
}

export interface ApplyResult {
  revision: number;
  changed: boolean;
  hash: string;
}

export const config = {
  get: () => request<ConfigDocument>('/config'),
  apply: () => request<ApplyResult>('/config/apply', { method: 'POST' }),
  revisions: (params: QueryParams = {}) =>
    request<Page<ConfigRevision>>(`/config/revisions${query(params)}`),
};

export interface VersionInfo {
  version: string;
  caddyRs: string;
}

export interface HealthInfo {
  status: string;
  setup: boolean;
}

export const system = {
  health: () => request<HealthInfo>('/health', { auth: false }),
  version: () => request<VersionInfo>('/version', { auth: false }),
};

function query(params: QueryParams): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : '';
}

function ifMatch(etag: string | null): Record<string, string> {
  return { 'if-match': etag || '*' };
}
