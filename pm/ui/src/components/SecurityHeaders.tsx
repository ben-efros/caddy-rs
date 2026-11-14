// Security headers editor.
//
// One controlled editor renders both the global configuration and a per-host override: the caller
// owns the value, this component only emits the next value. The schema mirrors
// `SecurityHeadersDto` in the proxy-manager API (snake_case JSON keys) so a value can be sent with
// `securityHeaders.putGlobal` / `putHost` unchanged.
//
// Each option carries inline documentation (purpose, default, security implication, example) and a
// link to the authoritative reference, because a security header is only as useful as the operator's
// understanding of what it turns off.

import { useEffect, useState, type ReactNode } from 'react';
import type { HstsConfig, SecurityHeadersConfig } from '../api';

/** The secure baseline the server applies when no configuration is stored yet. */
export function defaultSecurityHeaders(): SecurityHeadersConfig {
  return {
    content_security_policy: null,
    strict_transport_security: null,
    permissions_policy: null,
    x_frame_options: 'DENY',
    x_content_type_options: 'nosniff',
    referrer_policy: 'strict-origin-when-cross-origin',
  };
}

/** HSTS `preload` requires both subdomains and at least 180 days (matches the API validator). */
export const HSTS_PRELOAD_MIN_MAX_AGE = 15_552_000;

export const CSP_DIRECTIVES: { name: string; description: string }[] = [
  { name: 'default-src', description: 'Fallback for every directive not listed explicitly' },
  { name: 'script-src', description: 'Sources allowed to load JavaScript' },
  { name: 'style-src', description: 'Sources allowed to load stylesheets' },
  { name: 'img-src', description: 'Sources allowed to load images' },
  { name: 'connect-src', description: 'Targets allowed for fetch, XHR and WebSockets' },
  { name: 'font-src', description: 'Sources allowed to load web fonts' },
  { name: 'frame-src', description: 'Sources allowed in nested frames' },
  { name: 'frame-ancestors', description: 'Pages allowed to embed this page (replaces X-Frame-Options)' },
  { name: 'base-uri', description: 'URLs allowed in a document <base> element' },
  { name: 'form-action', description: 'Targets allowed for form submissions' },
  { name: 'object-src', description: 'Sources allowed for plugins and <object>' },
  { name: 'media-src', description: 'Sources allowed to load audio and video' },
  { name: 'worker-src', description: 'Sources allowed to start workers' },
  { name: 'manifest-src', description: 'Sources allowed to load the web app manifest' },
  { name: 'upgrade-insecure-requests', description: 'Rewrite http:// subresources to https://' },
  { name: 'sandbox', description: 'Apply a sandbox to the document' },
  { name: 'report-uri', description: 'Legacy endpoint for CSP violation reports' },
  { name: 'report-to', description: 'Reporting API group for CSP violation reports' },
];

export const CSP_SOURCES: { value: string; description: string }[] = [
  { value: "'self'", description: 'The page origin only' },
  { value: "'none'", description: 'No source is allowed' },
  { value: "'unsafe-inline'", description: 'Inline scripts/styles (weakens CSP)' },
  { value: "'unsafe-eval'", description: 'eval() and Function() (weakens CSP)' },
  { value: "'strict-dynamic'", description: 'Trust scripts loaded by an already trusted script' },
  { value: 'https:', description: 'Any HTTPS origin' },
  { value: 'data:', description: 'data: URLs (common for images)' },
];

export const X_FRAME_OPTIONS: { value: string; label: string; description: string }[] = [
  { value: '', label: 'Unset', description: 'Emit no X-Frame-Options header' },
  { value: 'DENY', label: 'DENY (recommended)', description: 'Refuse to render inside any frame' },
  {
    value: 'SAMEORIGIN',
    label: 'SAMEORIGIN',
    description: 'Allow framing only by pages on the same origin',
  },
  {
    value: 'ALLOW-FROM',
    label: 'ALLOW-FROM <uri>',
    description: 'Legacy allow-list of one origin; modern browsers ignore it',
  },
];

export const REFERRER_POLICIES: { value: string; label: string; description: string }[] = [
  {
    value: '',
    label: 'Unset',
    description: 'Emit no Referrer-Policy header; the browser default applies',
  },
  {
    value: 'no-referrer',
    label: 'no-referrer',
    description: 'Never send a Referer header (strongest privacy)',
  },
  {
    value: 'same-origin',
    label: 'same-origin',
    description: 'Send the full URL for same-origin requests only',
  },
  {
    value: 'strict-origin-when-cross-origin',
    label: 'strict-origin-when-cross-origin (recommended)',
    description: 'Full URL same-origin, origin only cross-origin, nothing on downgrade',
  },
  {
    value: 'no-referrer-when-downgrade',
    label: 'no-referrer-when-downgrade',
    description: 'Full URL except when downgrading to HTTP',
  },
  {
    value: 'origin-when-cross-origin',
    label: 'origin-when-cross-origin',
    description: 'Full URL same-origin, origin only cross-origin',
  },
  {
    value: 'unsafe-url',
    label: 'unsafe-url',
    description: 'Always send the full URL (leaks path and query data)',
  },
];

export const X_CONTENT_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'Unset' },
  { value: 'nosniff', label: 'nosniff (recommended)' },
];

export const PERMISSIONS_FEATURES: { name: string; description: string }[] = [
  { name: 'accelerometer', description: 'Motion sensors' },
  { name: 'camera', description: 'Camera capture' },
  { name: 'display-capture', description: 'Screen capture' },
  { name: 'fullscreen', description: 'Fullscreen API' },
  { name: 'geolocation', description: 'Location' },
  { name: 'gyroscope', description: 'Rotation sensors' },
  { name: 'magnetometer', description: 'Compass sensors' },
  { name: 'microphone', description: 'Microphone capture' },
  { name: 'payment', description: 'Payment Request API' },
  { name: 'usb', description: 'WebUSB' },
  { name: 'web-share', description: 'Web Share API' },
  { name: 'clipboard-read', description: 'Reading the clipboard' },
  { name: 'clipboard-write', description: 'Writing the clipboard' },
  { name: 'autoplay', description: 'Autoplaying media' },
];

const DOC_LINKS = {
  csp: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
  hsts: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
  xfo: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
  referrer: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
  permissions:
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
  xcto: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
};

export interface PermissionsRow {
  feature: string;
  allowlist: string;
}

/** Parse `camera=(self), microphone=()` into editable rows. */
export function parsePermissionsPolicy(value: string | null | undefined): PermissionsRow[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [feature, ...rest] = entry.split('=');
      const raw = rest.join('=').trim();
      const allowlist = raw.startsWith('(') && raw.endsWith(')') ? raw.slice(1, -1) : raw;
      return { feature: feature.trim(), allowlist: allowlist.trim() };
    });
}

/** Serialize rows back to `camera=(self), microphone=()`; empty rows are dropped. */
export function serializePermissionsPolicy(rows: PermissionsRow[]): string {
  return rows
    .filter((row) => row.feature.trim())
    .map((row) => {
      const allowlist = row.allowlist.trim();
      return allowlist ? `${row.feature.trim()}=(${allowlist})` : `${row.feature.trim()}=()`;
    })
    .join(', ');
}

/** Common starting policies offered by the CSP autocomplete. */
export const CSP_EXAMPLES: string[] = [
  "default-src 'self'",
  "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'",
];

/** Append a directive (with the safe `'self'` source) to a CSP value. */
export function insertDirective(current: string | null | undefined, directive: string): string {
  const trimmed = (current || '').trim();
  if (!trimmed) return `${directive} 'self'`;
  const parts = trimmed.split(';').map((part) => part.trim()).filter(Boolean);
  if (parts.some((part) => part.split(/\s+/)[0] === directive)) return trimmed;
  parts.push(`${directive} 'self'`);
  return parts.join('; ');
}

/** Normalize CSP whitespace so the preview matches what the server will emit. */
export function cspPreview(value: string | null | undefined): string {
  return (value || '').replace(/\s+/g, ' ').trim();
}

/** The `Strict-Transport-Security` value for an HSTS config. */
export function hstsValue(hsts: HstsConfig): string {
  const parts = [`max-age=${hsts.max_age}`];
  if (hsts.include_subdomains) parts.push('includeSubDomains');
  if (hsts.preload) parts.push('preload');
  return parts.join('; ');
}

export interface HeaderLine {
  name: string;
  value: string;
}

/** Effective response headers for a config; unset fields emit nothing. */
export function securityHeadersPreview(config: SecurityHeadersConfig): HeaderLine[] {
  const lines: HeaderLine[] = [];
  const csp = cspPreview(config.content_security_policy);
  if (csp) lines.push({ name: 'Content-Security-Policy', value: csp });
  if (config.strict_transport_security) {
    lines.push({
      name: 'Strict-Transport-Security',
      value: hstsValue(config.strict_transport_security),
    });
  }
  const permissions = (config.permissions_policy || '').trim();
  if (permissions) lines.push({ name: 'Permissions-Policy', value: permissions });
  if (config.x_frame_options) {
    lines.push({ name: 'X-Frame-Options', value: config.x_frame_options });
  }
  if (config.x_content_type_options) {
    lines.push({ name: 'X-Content-Type-Options', value: config.x_content_type_options });
  }
  if (config.referrer_policy) {
    lines.push({ name: 'Referrer-Policy', value: config.referrer_policy });
  }
  return lines;
}

/** Field-keyed validation messages; the server enforces the same rules. */
export function validateSecurityHeaders(config: SecurityHeadersConfig): Record<string, string> {
  const errors: Record<string, string> = {};
  const csp = (config.content_security_policy || '').trim();
  if (config.content_security_policy !== undefined && config.content_security_policy !== null) {
    if (!csp) errors.content_security_policy = 'Content-Security-Policy must not be blank.';
    else if (!csp.split(/\s+/).every((token) => token.length > 0)) {
      errors.content_security_policy = 'Content-Security-Policy contains an empty directive.';
    }
  }
  const hsts = config.strict_transport_security;
  if (hsts) {
    // The API rejects max-age below 180 days unconditionally (pm-core `validate`), not only when
    // preload is requested, so the editor must enforce the same floor before sending.
    if (!Number.isFinite(hsts.max_age) || hsts.max_age < HSTS_PRELOAD_MIN_MAX_AGE) {
      errors.strict_transport_security = `HSTS max-age must be at least ${HSTS_PRELOAD_MIN_MAX_AGE} seconds (180 days).`;
    } else if (hsts.preload && !hsts.include_subdomains) {
      errors.strict_transport_security = 'HSTS preload requires includeSubDomains.';
    }
  }
  const xfo = (config.x_frame_options || '').trim();
  if (xfo.startsWith('ALLOW-FROM')) {
    const uri = xfo.slice('ALLOW-FROM'.length).trim();
    if (!uri) errors.x_frame_options = 'ALLOW-FROM requires an origin URI.';
  }
  return errors;
}

interface FieldDocsProps {
  children: ReactNode;
  href: string;
}

function FieldDocs({ children, href }: FieldDocsProps): JSX.Element {
  return (
    <p className="form-hint field-docs">
      {children}{' '}
      <a href={href} target="_blank" rel="noopener noreferrer">
        Reference
      </a>
    </p>
  );
}

export interface SecurityHeadersEditorProps {
  /** Current value; the editor never mutates it. */
  value: SecurityHeadersConfig;
  onChange: (next: SecurityHeadersConfig) => void;
  /** When true, the values are inherited from the global config and shown dimmed. */
  inherited?: boolean;
  /** Prefix for element ids so the global and per-host editors can share a page. */
  idPrefix: string;
}

export function SecurityHeadersEditor({
  value,
  onChange,
  inherited = false,
  idPrefix,
}: SecurityHeadersEditorProps): JSX.Element {
  const [permissionsRows, setPermissionsRows] = useState<PermissionsRow[]>(() =>
    parsePermissionsPolicy(value.permissions_policy),
  );

  // The host selector swaps the value under the editor; keep the builder rows in sync.
  useEffect(() => {
    setPermissionsRows(parsePermissionsPolicy(value.permissions_policy));
  }, [value.permissions_policy]);

  const update = (patch: Partial<SecurityHeadersConfig>): void => {
    onChange({ ...value, ...patch });
  };

  const hsts = value.strict_transport_security || null;
  const setHsts = (patch: Partial<HstsConfig>): void => {
    const next: HstsConfig = hsts ?? {
      max_age: HSTS_PRELOAD_MIN_MAX_AGE,
      include_subdomains: true,
      preload: false,
    };
    update({ strict_transport_security: { ...next, ...patch } });
  };

  const updatePermissions = (rows: PermissionsRow[]): void => {
    setPermissionsRows(rows);
    update({ permissions_policy: serializePermissionsPolicy(rows) });
  };

  const errors = validateSecurityHeaders(value);
  const xfo = (value.x_frame_options || '').trim();
  const xfoValue = xfo.startsWith('ALLOW-FROM') ? 'ALLOW-FROM' : xfo;
  const xfoUri = xfo.startsWith('ALLOW-FROM') ? xfo.slice('ALLOW-FROM'.length).trim() : '';
  const preview = securityHeadersPreview(value);
  const classNames = ['security-headers-editor'];
  if (inherited) classNames.push('inherited');

  return (
    <div className={classNames.join(' ')}>
      {inherited ? (
        <p className="inherited-note">
          These values are inherited from the global configuration. Dimmed values are not stored on
          this host.
        </p>
      ) : null}

      <fieldset className="form-group">
        <legend>Content-Security-Policy</legend>
        <FieldDocs href={DOC_LINKS.csp}>
          Restricts which sources the browser may load. Default: unset (no CSP). A CSP is the
          strongest mitigation against cross-site scripting; start with{' '}
          <code>default-src 'self'</code> and widen deliberately.
        </FieldDocs>
        <input
          id={`${idPrefix}-csp`}
          name="content_security_policy"
          type="text"
          list={`${idPrefix}-csp-directives`}
          placeholder="default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
          value={value.content_security_policy || ''}
          onChange={(event) =>
            update({ content_security_policy: event.target.value || null })
          }
        />
        <datalist id={`${idPrefix}-csp-directives`}>
          {CSP_DIRECTIVES.map((directive) => (
            <option key={directive.name} value={directive.name}>
              {directive.description}
            </option>
          ))}
          {CSP_EXAMPLES.map((example) => (
            <option key={example} value={example} />
          ))}
        </datalist>
        <div className="csp-builder" id={`${idPrefix}-csp-builder`}>
          <span className="form-hint">Insert directive:</span>
          {CSP_DIRECTIVES.slice(0, 8).map((directive) => (
            <button
              key={directive.name}
              type="button"
              className="chip"
              title={directive.description}
              onClick={() => update({ content_security_policy: insertDirective(value.content_security_policy, directive.name) })}
            >
              {directive.name}
            </button>
          ))}
        </div>
        <p className="form-hint">
          Directive autocomplete: {CSP_DIRECTIVES.map((directive) => directive.name).join(', ')}.
          Sources: {CSP_SOURCES.map((source) => source.value).join(', ')}.
        </p>
        <p className="form-hint">
          Nonce hint: <code>'nonce-&lt;random&gt;'</code> must be generated per response and match a
          nonce in the document; a static header cannot rotate it, so prefer{' '}
          <code>'strict-dynamic'</code> unless the application emits matching nonces.
        </p>
        <div className="preview-block" id={`${idPrefix}-csp-preview`}>
          <span className="preview-label">Generated header</span>
          <code>
            {preview.find((line) => line.name === 'Content-Security-Policy')?.value
              ? `Content-Security-Policy: ${
                  preview.find((line) => line.name === 'Content-Security-Policy')?.value
                }`
              : '(no Content-Security-Policy)'}
          </code>
        </div>
        {errors.content_security_policy ? (
          <div className="inline-error">{errors.content_security_policy}</div>
        ) : null}
      </fieldset>

      <fieldset className="form-group">
        <legend>X-Frame-Options</legend>
        <FieldDocs href={DOC_LINKS.xfo}>
          Controls whether the page may be embedded in a frame. Default: <code>DENY</code>. Framing
          is how clickjacking works, so only relax it when the page must be embedded.
        </FieldDocs>
        <select
          id={`${idPrefix}-xfo`}
          name="x_frame_options"
          value={xfoValue}
          onChange={(event) => {
            const next = event.target.value;
            update({
              x_frame_options: next === 'ALLOW-FROM' ? 'ALLOW-FROM ' : next || null,
            });
          }}
        >
          {X_FRAME_OPTIONS.map((option) => (
            <option key={option.label} value={option.value}>
              {option.label} — {option.description}
            </option>
          ))}
        </select>
        {xfoValue === 'ALLOW-FROM' ? (
          <input
            id={`${idPrefix}-xfo-uri`}
            name="x_frame_options_uri"
            type="url"
            placeholder="https://partner.example.com"
            value={xfoUri}
            onChange={(event) =>
              update({ x_frame_options: `ALLOW-FROM ${event.target.value}`.trim() })
            }
          />
        ) : null}
        {xfoValue === 'SAMEORIGIN' ? (
          <div className="warning-banner" id={`${idPrefix}-xfo-warning`}>
            SAMEORIGIN requires the embedding page to share this exact origin (scheme, host and
            port).
          </div>
        ) : null}
        {xfoValue === 'ALLOW-FROM' ? (
          <div className="warning-banner">
            ALLOW-FROM is obsolete: modern browsers ignore it. Prefer a CSP{' '}
            <code>frame-ancestors</code> directive.
          </div>
        ) : null}
        {errors.x_frame_options ? (
          <div className="inline-error">{errors.x_frame_options}</div>
        ) : null}
      </fieldset>

      <fieldset className="form-group">
        <legend>Strict-Transport-Security (HSTS)</legend>
        <FieldDocs href={DOC_LINKS.hsts}>
          Tells browsers to use HTTPS for this host for <code>max-age</code> seconds. Default:
          unset. Once a browser has cached HSTS, plain HTTP is refused even if the header is later
          removed, so roll it out deliberately.
        </FieldDocs>
        <label className="checkbox">
          <input
            id={`${idPrefix}-hsts-enabled`}
            name="hsts_enabled"
            type="checkbox"
            checked={hsts !== null}
            onChange={(event) =>
              update({
                strict_transport_security: event.target.checked
                  ? { max_age: HSTS_PRELOAD_MIN_MAX_AGE, include_subdomains: true, preload: false }
                  : null,
              })
            }
          />
          Send Strict-Transport-Security
        </label>
        {hsts ? (
          <>
            <label htmlFor={`${idPrefix}-hsts-max-age`}>max-age (seconds)</label>
            <input
              id={`${idPrefix}-hsts-max-age`}
              name="hsts_max_age"
              type="number"
              min={HSTS_PRELOAD_MIN_MAX_AGE}
              value={hsts.max_age}
              onChange={(event) =>
                setHsts({ max_age: Number(event.target.value) || 0 })
              }
            />
            <label className="checkbox">
              <input
                id={`${idPrefix}-hsts-subdomains`}
                name="hsts_include_subdomains"
                type="checkbox"
                checked={hsts.include_subdomains}
                onChange={(event) => setHsts({ include_subdomains: event.target.checked })}
              />
              Include subdomains
            </label>
            <label className="checkbox">
              <input
                id={`${idPrefix}-hsts-preload`}
                name="hsts_preload"
                type="checkbox"
                checked={hsts.preload}
                onChange={(event) => setHsts({ preload: event.target.checked })}
              />
              Request preload
            </label>
            {hsts.preload ? (
              <div className="warning-banner" id={`${idPrefix}-hsts-preload-warning`}>
                Preload is irreversible — ensure the domain is on the HSTS preload list before
                enabling it, and keep includeSubDomains with max-age of at least 180 days.
              </div>
            ) : null}
            <div className="preview-block">
              <span className="preview-label">Generated header</span>
              <code>Strict-Transport-Security: {hstsValue(hsts)}</code>
            </div>
          </>
        ) : null}
        {errors.strict_transport_security ? (
          <div className="inline-error">{errors.strict_transport_security}</div>
        ) : null}
      </fieldset>

      <fieldset className="form-group">
        <legend>Referrer-Policy</legend>
        <FieldDocs href={DOC_LINKS.referrer}>
          Controls how much URL information the browser sends in the <code>Referer</code> header.
          Default: <code>strict-origin-when-cross-origin</code>. The full URL can leak paths, query
          strings and tokens to third parties.
        </FieldDocs>
        <select
          id={`${idPrefix}-referrer`}
          name="referrer_policy"
          value={value.referrer_policy || ''}
          onChange={(event) => update({ referrer_policy: event.target.value || null })}
        >
          {REFERRER_POLICIES.map((policy) => (
            <option key={policy.label} value={policy.value}>
              {policy.label}
            </option>
          ))}
        </select>
        <p className="form-hint">
          {REFERRER_POLICIES.find((policy) => policy.value === (value.referrer_policy || ''))
            ?.description || 'Unset.'}
        </p>
      </fieldset>

      <fieldset className="form-group">
        <legend>Permissions-Policy</legend>
        <FieldDocs href={DOC_LINKS.permissions}>
          Allows or blocks browser features (camera, microphone, geolocation, …). Default: unset
          (the browser default applies). Deny what the application does not use.
        </FieldDocs>
        <div id={`${idPrefix}-permissions`}>
          {permissionsRows.length === 0 ? (
            <p className="form-hint">No features configured.</p>
          ) : (
            permissionsRows.map((row, index) => (
              <div className="permissions-row" key={`${row.feature}-${index}`}>
                <select
                  aria-label={`Feature ${index + 1}`}
                  value={row.feature}
                  onChange={(event) => {
                    const next = [...permissionsRows];
                    next[index] = { ...row, feature: event.target.value };
                    updatePermissions(next);
                  }}
                >
                  <option value="">Select a feature…</option>
                  {PERMISSIONS_FEATURES.map((feature) => (
                    <option key={feature.name} value={feature.name}>
                      {feature.name} — {feature.description}
                    </option>
                  ))}
                </select>
                <input
                  aria-label={`Allowlist for feature ${index + 1}`}
                  placeholder="self, https://partner.example.com"
                  value={row.allowlist}
                  onChange={(event) => {
                    const next = [...permissionsRows];
                    next[index] = { ...row, allowlist: event.target.value };
                    updatePermissions(next);
                  }}
                />
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => updatePermissions(permissionsRows.filter((_, i) => i !== index))}
                >
                  Remove
                </button>
              </div>
            ))
          )}
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            id={`${idPrefix}-permissions-add`}
            onClick={() => updatePermissions([...permissionsRows, { feature: '', allowlist: '' }])}
          >
            Add feature
          </button>
        </div>
        <div className="preview-block">
          <span className="preview-label">Generated header</span>
          <code>
            {value.permissions_policy ? `Permissions-Policy: ${value.permissions_policy}` : '(no Permissions-Policy)'}
          </code>
        </div>
      </fieldset>

      <fieldset className="form-group">
        <legend>X-Content-Type-Options</legend>
        <FieldDocs href={DOC_LINKS.xcto}>
          Prevents browsers from MIME-sniffing a response away from its declared content type.
          Default: <code>nosniff</code>. Disabling it lets a mislabelled upload be interpreted as
          script.
        </FieldDocs>
        <select
          id={`${idPrefix}-xcto`}
          name="x_content_type_options"
          value={value.x_content_type_options || ''}
          onChange={(event) => update({ x_content_type_options: event.target.value || null })}
        >
          {X_CONTENT_TYPE_OPTIONS.map((option) => (
            <option key={option.label} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </fieldset>

      <div className="preview-block" id={`${idPrefix}-preview`}>
        <span className="preview-label">Effective headers</span>
        {preview.length === 0 ? (
          <code>(no security headers)</code>
        ) : (
          <ul className="header-preview-list">
            {preview.map((line) => (
              <li key={line.name}>
                <code>
                  {line.name}: {line.value}
                </code>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
