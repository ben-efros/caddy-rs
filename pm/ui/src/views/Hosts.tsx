// Hosts list and the create/edit form. The form stays uncontrolled on purpose: the smoke test (and
// a real browser) fills the DOM and submits; reading FormData on submit keeps that contract.

import { useEffect, useState, type FormEvent } from 'react';
import {
  ApiError,
  certificates,
  hosts,
  type CertificateItem,
  type HostDetail,
  type HostPayload,
  type HostSpec,
  type HostSummary,
  type Page,
  type ProxySpec,
  type RedirectSpec,
  type TlsSettings,
} from '../api';
import {
  Empty,
  EnabledBadge,
  ErrorBox,
  Loading,
  Modal,
  TlsBadge,
  confirmAction,
  formValues,
  numberOrNull,
  parseDomains,
  toast,
} from '../ui';

const PAGE_SIZE = 25;

interface Filters {
  domain: string;
  kind: string;
  enabled: string;
}

interface HostFormState {
  host: HostDetail | null;
  etag: string | null;
  intents: CertificateItem[];
  manual: CertificateItem[];
}

export function Hosts(): JSX.Element {
  const [filters, setFilters] = useState<Filters>({ domain: '', kind: '', enabled: '' });
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page<HostSummary> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [form, setForm] = useState<HostFormState | null>(null);

  const load = async (nextOffset: number, nextFilters: Filters): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await hosts.list({
        limit: PAGE_SIZE,
        offset: nextOffset,
        domain: nextFilters.domain,
        kind: nextFilters.kind,
        enabled: nextFilters.enabled,
      });
      setPage(data);
    } catch (failure) {
      setError(failure);
      setPage(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load(offset, filters);
  }, [offset, filters]);

  const onFilterSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const values = formValues(event.currentTarget);
    setOffset(0);
    setFilters({
      domain: String(values.domain ?? ''),
      kind: String(values.kind ?? ''),
      enabled: String(values.enabled ?? ''),
    });
  };

  const openHostForm = async (id: number | null): Promise<void> => {
    try {
      // The certificate list needs the caddy-rs data plane (it derives live status). A stopped data
      // plane must not block creating a plain HTTP host, so that call degrades to an empty list.
      const [detail, certList] = await Promise.all([
        id === null
          ? Promise.resolve({ data: null as HostDetail | null, etag: null as string | null })
          : hosts.get(id),
        certificates.list({ limit: 200 }).catch(() => ({
          data: { items: [] as CertificateItem[] },
          etag: null,
          status: 200,
        })),
      ]);
      const intents: CertificateItem[] = [];
      const manual: CertificateItem[] = [];
      for (const item of certList.data.items) {
        if (item.origin === 'manual') manual.push(item);
        else intents.push(item);
      }
      setForm({ host: detail.data, etag: detail.etag, intents, manual });
    } catch (failure) {
      toast(errorMessage(failure), 'danger');
    }
  };

  const toggleHost = async (id: number, enabled: boolean): Promise<void> => {
    try {
      // `If-Match: *` is deliberate: a toggle means "flip the current state", not "replace the
      // snapshot I loaded". The server re-reads the host and compare-and-swaps on that revision.
      await hosts.setEnabled(id, enabled, '*');
      toast(`Host ${id} ${enabled ? 'enabled' : 'disabled'}.`);
      await load(offset, filters);
    } catch (failure) {
      toast(errorMessage(failure), 'danger');
    }
  };

  const deleteHost = async (id: number): Promise<void> => {
    if (!(await confirmAction('Delete host', `Delete host ${id}? Its domains are released for reuse.`))) {
      return;
    }
    try {
      await hosts.remove(id, '*');
      toast(`Host ${id} deleted.`);
      await load(offset, filters);
    } catch (failure) {
      toast(errorMessage(failure), 'danger');
    }
  };

  const pages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1;
  const pageNumber = page ? Math.floor(page.offset / page.limit) + 1 : 1;
  const filtered = Boolean(filters.domain || filters.kind || filters.enabled);

  return (
    <main className="main-content">
      <div className="page-header">
        <div>
          <h1>Hosts</h1>
          <p className="page-subtitle">Proxy, redirect and dead hosts compiled into the caddy-rs config</p>
        </div>
        <button type="button" className="btn btn-primary" id="create-host" onClick={() => void openHostForm(null)}>
          New host
        </button>
      </div>

      <div className="card">
        <div className="card-header">
          <form className="filters" id="filters" onSubmit={onFilterSubmit}>
            <input name="domain" placeholder="Filter by domain" defaultValue={filters.domain} />
            <select name="kind" defaultValue={filters.kind}>
              <option value="">Any kind</option>
              <option value="proxy">Proxy</option>
              <option value="redirect">Redirect</option>
              <option value="dead">Dead</option>
            </select>
            <select name="enabled" defaultValue={filters.enabled}>
              <option value="">Any state</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
            <button type="submit" className="btn btn-ghost btn-sm">
              Apply
            </button>
          </form>
        </div>
        <div className="table-container" id="hosts-table">
          {loading ? (
            <Loading />
          ) : error ? (
            <ErrorBox error={error} />
          ) : page && page.items.length ? (
            <HostsTable items={page.items} onEdit={openHostForm} onToggle={toggleHost} onDelete={deleteHost} />
          ) : (
            <Empty
              text={
                filtered
                  ? 'No hosts match these filters.'
                  : 'No hosts yet. Create the first one.'
              }
            />
          )}
        </div>
        <div className={pages <= 1 ? 'pagination hidden' : 'pagination'} id="pagination">
          {pages > 1 && page ? (
            <>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={page.offset === 0}
                onClick={() => setOffset(Math.max(0, page.offset - page.limit))}
              >
                Previous
              </button>
              <span>
                Page {pageNumber} of {pages} · {page.total} hosts
              </span>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={page.offset + page.limit >= page.total}
                onClick={() => setOffset(page.offset + page.limit)}
              >
                Next
              </button>
            </>
          ) : null}
        </div>
      </div>

      {form ? (
        <HostForm
          state={form}
          onClose={() => setForm(null)}
          onSaved={(message) => {
            setForm(null);
            toast(message);
            void load(offset, filters);
          }}
        />
      ) : null}
    </main>
  );
}

function HostsTable({
  items,
  onEdit,
  onToggle,
  onDelete,
}: {
  items: HostSummary[];
  onEdit: (id: number) => void;
  onToggle: (id: number, enabled: boolean) => void;
  onDelete: (id: number) => void;
}): JSX.Element {
  return (
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Domains</th>
          <th>Kind</th>
          <th>TLS</th>
          <th>State</th>
          <th>Revision</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {items.map((host) => (
          <tr key={host.id}>
            <td>{host.id}</td>
            <td>
              {host.domains.map((domain) => (
                <span className="domain" key={domain}>
                  {domain}
                </span>
              ))}
            </td>
            <td>{host.kind}</td>
            <td>
              <TlsBadge mode={host.tlsMode} />
            </td>
            <td>
              <EnabledBadge enabled={host.enabled} />
            </td>
            <td>{host.revision}</td>
            <td className="actions">
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => onEdit(host.id)}>
                Edit
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => onToggle(host.id, !host.enabled)}
              >
                {host.enabled ? 'Disable' : 'Enable'}
              </button>
              <button type="button" className="btn btn-danger btn-sm" onClick={() => onDelete(host.id)}>
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function HostForm({
  state,
  onClose,
  onSaved,
}: {
  state: HostFormState;
  onClose: () => void;
  onSaved: (message: string) => void;
}): JSX.Element {
  const { host, etag, intents, manual } = state;
  const spec: HostSpec = host?.spec ?? { kind: 'proxy' };
  const proxy: Partial<ProxySpec> =
    spec.kind === 'proxy' ? ((spec.spec as ProxySpec | undefined) ?? {}) : {};
  const redirect: Partial<RedirectSpec> =
    spec.kind === 'redirect' ? ((spec.spec as RedirectSpec | undefined) ?? {}) : {};
  const tls: TlsSettings = host?.tls ?? {
    mode: 'disabled',
    sslForced: false,
    hstsEnabled: false,
    hstsSubdomains: false,
  };

  const [kind, setKind] = useState(spec.kind);
  const [tlsMode, setTlsMode] = useState(tls.mode);
  const [saving, setSaving] = useState(false);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const form = event.currentTarget;
    setSaving(true);
    try {
      const payload = buildPayload(form);
      if (host === null) await hosts.create(payload);
      else await hosts.replace(host.id, payload, etag);
      onSaved(host === null ? 'Host created.' : `Host ${host.id} updated.`);
    } catch (failure) {
      setSaving(false);
      toast(errorMessage(failure), 'danger');
    }
  };

  return (
    <Modal title={host === null ? 'New host' : `Edit host ${host.id}`} onClose={onClose}>
      <form id="host-form" onSubmit={(event) => void onSubmit(event)}>
        <div className="form-group">
          <label htmlFor="domains">Domains</label>
          <input
            id="domains"
            name="domains"
            required
            defaultValue={(host?.domains || []).join(', ')}
            placeholder="app.example.com, www.example.com"
          />
          <span className="form-hint">
            Comma or space separated. Every domain must be unique across hosts.
          </span>
        </div>

        <div className="form-grid">
          <div className="form-group">
            <label htmlFor="kind">Kind</label>
            <select id="kind" name="kind" value={kind} onChange={(event) => setKind(event.target.value)}>
              <option value="proxy">Proxy</option>
              <option value="redirect">Redirect</option>
              <option value="dead">Dead (404)</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="enabled">State</label>
            <select id="enabled" name="enabled" defaultValue={host?.enabled !== false ? 'true' : 'false'}>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </div>
        </div>

        <fieldset id="proxy-fields" className={kind === 'proxy' ? undefined : 'hidden'}>
          <legend>Proxy</legend>
          <div className="form-grid">
            <div className="form-group">
              <label htmlFor="scheme">Upstream scheme</label>
              <select id="scheme" name="scheme" defaultValue={proxy.upstream?.scheme !== 'https' ? 'http' : 'https'}>
                <option value="http">http</option>
                <option value="https">https</option>
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="upstream-host">Upstream host</label>
              <input
                id="upstream-host"
                name="upstreamHost"
                defaultValue={proxy.upstream?.host || ''}
                placeholder="10.0.0.5"
              />
            </div>
            <div className="form-group">
              <label htmlFor="upstream-port">Upstream port</label>
              <input
                id="upstream-port"
                name="upstreamPort"
                type="number"
                min="1"
                max="65535"
                defaultValue={proxy.upstream?.port ?? ''}
                placeholder="8080"
              />
            </div>
          </div>
          <label className="checkbox">
            <input type="checkbox" name="websocket" defaultChecked={Boolean(proxy.websocket)} /> WebSocket
            support
          </label>
          <label className="checkbox">
            <input type="checkbox" name="preserveHost" defaultChecked={proxy.preserveHost !== false} />{' '}
            Preserve the Host header
          </label>
        </fieldset>

        <fieldset id="redirect-fields" className={kind === 'redirect' ? undefined : 'hidden'}>
          <legend>Redirect</legend>
          <div className="form-grid">
            <div className="form-group">
              <label htmlFor="redirect-target">Target</label>
              <input
                id="redirect-target"
                name="redirectTarget"
                defaultValue={redirect.target || ''}
                placeholder="example.com"
              />
            </div>
            <div className="form-group">
              <label htmlFor="redirect-status">Status</label>
              <select id="redirect-status" name="redirectStatus" defaultValue={String(redirect.status ?? 301)}>
                {[301, 302, 307, 308].map((code) => (
                  <option value={code} key={code}>
                    {code}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="redirect-scheme">Scheme</label>
              <select id="redirect-scheme" name="redirectScheme" defaultValue={redirect.scheme ?? 'auto'}>
                <option value="auto">auto (keep request scheme)</option>
                <option value="http">http</option>
                <option value="https">https</option>
              </select>
            </div>
          </div>
          <label className="checkbox">
            <input type="checkbox" name="preservePath" defaultChecked={redirect.preservePath !== false} />{' '}
            Preserve the request path
          </label>
        </fieldset>

        <fieldset>
          <legend>TLS</legend>
          <div className="form-group">
            <label htmlFor="tls-mode">Mode</label>
            <select
              id="tls-mode"
              name="tlsMode"
              value={tlsMode}
              onChange={(event) => setTlsMode(event.target.value)}
            >
              <option value="disabled">Disabled (plain HTTP)</option>
              <option value="auto">Auto (managed certificate)</option>
              <option value="manual">Manual (uploaded certificate)</option>
            </select>
          </div>
          <div
            className={`form-group${tlsMode === 'auto' ? '' : ' hidden'}`}
            id="auto-policy-group"
          >
            <label htmlFor="auto-policy">Certificate intent</label>
            <select id="auto-policy" name="autoPolicyId" defaultValue={tls.autoPolicyId ?? ''}>
              <option value="">Choose an intent…</option>
              {intents.map((intent) => (
                <option value={intent.policyId ?? ''} key={intent.policyId}>
                  {intent.name} — {intent.domains.join(', ')}
                </option>
              ))}
            </select>
            <span className="form-hint">
              Create intents on the Certificates page. None are configured yet if this list is empty.
            </span>
          </div>
          <div
            className={`form-group${tlsMode === 'manual' ? '' : ' hidden'}`}
            id="manual-cert-group"
          >
            <label htmlFor="manual-cert">Certificate</label>
            <select id="manual-cert" name="certificateId" defaultValue={tls.certificateId ?? ''}>
              <option value="">Choose a certificate…</option>
              {manual.map((certificate) => (
                <option value={certificate.id ?? ''} key={certificate.id}>
                  {certificate.name} — {certificate.domains.join(', ')}
                </option>
              ))}
            </select>
            <span className="form-hint">Upload certificates on the Certificates page.</span>
          </div>
          <label className="checkbox">
            <input type="checkbox" name="sslForced" defaultChecked={Boolean(tls.sslForced)} /> Force HTTPS
          </label>
          <label className="checkbox">
            <input type="checkbox" name="hstsEnabled" defaultChecked={Boolean(tls.hstsEnabled)} /> Send HSTS
          </label>
          <label className="checkbox">
            <input type="checkbox" name="hstsSubdomains" defaultChecked={Boolean(tls.hstsSubdomains)} /> HSTS
            includes subdomains
          </label>
        </fieldset>

        <div className="modal-footer">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" id="save-host" disabled={saving}>
            {host === null ? 'Create' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function buildPayload(form: HTMLFormElement): HostPayload {
  const values = formValues(form);
  const kind = String(values.kind ?? '');
  const mode = String(values.tlsMode ?? 'disabled');

  const tls: TlsSettings = {
    mode,
    sslForced: Boolean(values.sslForced),
    hstsEnabled: Boolean(values.hstsEnabled),
    hstsSubdomains: Boolean(values.hstsSubdomains),
  };
  if (mode === 'auto') tls.autoPolicyId = numberOrNull(values.autoPolicyId);
  if (mode === 'manual') tls.certificateId = numberOrNull(values.certificateId);

  let spec: HostSpec;
  if (kind === 'proxy') {
    spec = {
      kind: 'proxy',
      spec: {
        upstream: {
          scheme: String(values.scheme || 'http'),
          host: String(values.upstreamHost ?? ''),
          port: Number(values.upstreamPort),
        },
        websocket: Boolean(values.websocket),
        preserveHost: Boolean(values.preserveHost),
      },
    };
  } else if (kind === 'redirect') {
    spec = {
      kind: 'redirect',
      spec: {
        scheme: String(values.redirectScheme || 'auto'),
        target: String(values.redirectTarget ?? ''),
        status: Number(values.redirectStatus) || 301,
        preservePath: Boolean(values.preservePath),
      },
    };
  } else {
    spec = { kind: 'dead' };
  }

  return {
    domains: parseDomains(values.domains),
    tls,
    spec,
    enabled: values.enabled !== 'false',
  };
}

function errorMessage(failure: unknown): string {
  if (failure instanceof ApiError && failure.location) return `${failure.message} (${failure.location})`;
  return failure instanceof Error ? failure.message : 'Request failed';
}
