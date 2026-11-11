import { ApiError, certificates, hosts } from '../api.js';
import {
  closeModal,
  confirmAction,
  empty,
  enabledBadge,
  errorBox,
  escapeHtml,
  formValues,
  header,
  loading,
  numberOrNull,
  openModal,
  parseDomains,
  tlsBadge,
  toast,
} from '../ui.js';

const PAGE_SIZE = 25;

const state = {
  offset: 0,
  domain: '',
  kind: '',
  enabled: '',
};

export async function renderHosts(container) {
  container.innerHTML = `
    <div class="page">
      ${header('/hosts')}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Hosts</h1>
            <p class="page-subtitle">Proxy, redirect and dead hosts compiled into the caddy-rs config</p>
          </div>
          <button type="button" class="btn btn-primary" id="create-host">New host</button>
        </div>

        <div class="card">
          <div class="card-header">
            <form class="filters" id="filters">
              <input name="domain" placeholder="Filter by domain" value="${escapeHtml(state.domain)}" />
              <select name="kind">
                <option value="">Any kind</option>
                <option value="proxy">Proxy</option>
                <option value="redirect">Redirect</option>
                <option value="dead">Dead</option>
              </select>
              <select name="enabled">
                <option value="">Any state</option>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
              <button type="submit" class="btn btn-ghost btn-sm">Apply</button>
            </form>
          </div>
          <div class="table-container" id="hosts-table">${loading()}</div>
          <div class="pagination hidden" id="pagination"></div>
        </div>
      </main>
    </div>`;

  const filters = container.querySelector('#filters');
  filters.querySelector('[name="kind"]').value = state.kind;
  filters.querySelector('[name="enabled"]').value = state.enabled;
  filters.addEventListener('submit', (event) => {
    event.preventDefault();
    const values = formValues(filters);
    state.domain = values.domain;
    state.kind = values.kind;
    state.enabled = values.enabled;
    state.offset = 0;
    void loadHosts(container);
  });

  container.querySelector('#create-host').addEventListener('click', () => void openHostForm(container, null));

  await loadHosts(container);
}

async function loadHosts(container) {
  const table = container.querySelector('#hosts-table');
  const pagination = container.querySelector('#pagination');
  table.innerHTML = loading();

  try {
    const { data } = await hosts.list({
      limit: PAGE_SIZE,
      offset: state.offset,
      domain: state.domain,
      kind: state.kind,
      enabled: state.enabled,
    });

    if (!data.items.length) {
      table.innerHTML = empty(
        state.domain || state.kind || state.enabled
          ? 'No hosts match these filters.'
          : 'No hosts yet. Create the first one.',
      );
      pagination.classList.add('hidden');
      return;
    }

    table.innerHTML = `
      <table>
        <thead>
          <tr><th>ID</th><th>Domains</th><th>Kind</th><th>TLS</th><th>State</th><th>Revision</th><th></th></tr>
        </thead>
        <tbody>
          ${data.items
            .map(
              (host) => `
            <tr>
              <td>${host.id}</td>
              <td>${host.domains.map((domain) => `<span class="domain">${escapeHtml(domain)}</span>`).join('')}</td>
              <td>${escapeHtml(host.kind)}</td>
              <td>${tlsBadge(host.tlsMode)}</td>
              <td>${enabledBadge(host.enabled)}</td>
              <td>${host.revision}</td>
              <td class="actions">
                <button type="button" class="btn btn-ghost btn-sm" data-edit="${host.id}">Edit</button>
                <button type="button" class="btn btn-ghost btn-sm" data-toggle="${host.id}" data-enabled="${host.enabled}">
                  ${host.enabled ? 'Disable' : 'Enable'}
                </button>
                <button type="button" class="btn btn-danger btn-sm" data-delete="${host.id}">Delete</button>
              </td>
            </tr>`,
            )
            .join('')}
        </tbody>
      </table>`;

    table.querySelectorAll('[data-edit]').forEach((button) => {
      button.addEventListener('click', () => void openHostForm(container, Number(button.dataset.edit)));
    });
    table.querySelectorAll('[data-toggle]').forEach((button) => {
      button.addEventListener('click', () =>
        void toggleHost(container, Number(button.dataset.toggle), button.dataset.enabled !== 'true'),
      );
    });
    table.querySelectorAll('[data-delete]').forEach((button) => {
      button.addEventListener('click', () => void deleteHost(container, Number(button.dataset.delete)));
    });

    renderPagination(pagination, data, container);
  } catch (error) {
    table.innerHTML = errorBox(error);
    pagination.classList.add('hidden');
  }
}

function renderPagination(pagination, data, container) {
  const pages = Math.max(1, Math.ceil(data.total / data.limit));
  const page = Math.floor(data.offset / data.limit) + 1;
  pagination.classList.toggle('hidden', pages <= 1);
  if (pages <= 1) return;
  pagination.innerHTML = `
    <button type="button" class="btn btn-ghost btn-sm" ${data.offset === 0 ? 'disabled' : ''} data-page="prev">Previous</button>
    <span>Page ${page} of ${pages} · ${data.total} hosts</span>
    <button type="button" class="btn btn-ghost btn-sm" ${
      data.offset + data.limit >= data.total ? 'disabled' : ''
    } data-page="next">Next</button>`;
  pagination.querySelector('[data-page="prev"]').addEventListener('click', () => {
    state.offset = Math.max(0, data.offset - data.limit);
    void loadHosts(container);
  });
  pagination.querySelector('[data-page="next"]').addEventListener('click', () => {
    state.offset = data.offset + data.limit;
    void loadHosts(container);
  });
}

async function toggleHost(container, id, enabled) {
  try {
    // `If-Match: *` is deliberate: a toggle means "flip the current state", not "replace the
    // snapshot I loaded". The server re-reads the host and compare-and-swaps on that revision.
    await hosts.setEnabled(id, enabled, '*');
    toast(`Host ${id} ${enabled ? 'enabled' : 'disabled'}.`);
    await loadHosts(container);
  } catch (error) {
    toast(error.message, 'danger');
  }
}

async function deleteHost(container, id) {
  if (!(await confirmAction('Delete host', `Delete host ${id}? Its domains are released for reuse.`))) {
    return;
  }
  try {
    await hosts.remove(id, '*');
    toast(`Host ${id} deleted.`);
    await loadHosts(container);
  } catch (error) {
    toast(error.message, 'danger');
  }
}

async function openHostForm(container, id) {
  let host = null;
  let etag = null;
  let intents = [];
  let manual = [];

  try {
    // The certificate list needs the caddy-rs data plane (it derives live status). A stopped data
    // plane must not block creating a plain HTTP host, so that call degrades to an empty list.
    const [detail, certList] = await Promise.all([
      id === null ? Promise.resolve({ data: null, etag: null }) : hosts.get(id),
      certificates.list({ limit: 200 }).catch(() => ({ data: { items: [] } })),
    ]);
    host = detail.data;
    etag = detail.etag;
    for (const item of certList.data.items) {
      if (item.origin === 'manual') manual.push(item);
      else intents.push(item);
    }
  } catch (error) {
    toast(error.message, 'danger');
    return;
  }

  const spec = host?.spec || { kind: 'proxy', spec: {} };
  const proxy = spec.kind === 'proxy' ? spec.spec : {};
  const redirect = spec.kind === 'redirect' ? spec.spec : {};
  const tls = host?.tls || { mode: 'disabled', sslForced: false, hstsEnabled: false, hstsSubdomains: false };

  const overlay = openModal(
    id === null ? 'New host' : `Edit host ${id}`,
    `<form id="host-form">
      <div class="form-group">
        <label for="domains">Domains</label>
        <input id="domains" name="domains" required value="${escapeHtml((host?.domains || []).join(', '))}"
               placeholder="app.example.com, www.example.com" />
        <span class="form-hint">Comma or space separated. Every domain must be unique across hosts.</span>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label for="kind">Kind</label>
          <select id="kind" name="kind">
            <option value="proxy" ${spec.kind === 'proxy' ? 'selected' : ''}>Proxy</option>
            <option value="redirect" ${spec.kind === 'redirect' ? 'selected' : ''}>Redirect</option>
            <option value="dead" ${spec.kind === 'dead' ? 'selected' : ''}>Dead (404)</option>
          </select>
        </div>
        <div class="form-group">
          <label for="enabled">State</label>
          <select id="enabled" name="enabled">
            <option value="true" ${host?.enabled !== false ? 'selected' : ''}>Enabled</option>
            <option value="false" ${host?.enabled === false ? 'selected' : ''}>Disabled</option>
          </select>
        </div>
      </div>

      <fieldset id="proxy-fields">
        <legend>Proxy</legend>
        <div class="form-grid">
          <div class="form-group">
            <label for="scheme">Upstream scheme</label>
            <select id="scheme" name="scheme">
              <option value="http" ${proxy.upstream?.scheme !== 'https' ? 'selected' : ''}>http</option>
              <option value="https" ${proxy.upstream?.scheme === 'https' ? 'selected' : ''}>https</option>
            </select>
          </div>
          <div class="form-group">
            <label for="upstream-host">Upstream host</label>
            <input id="upstream-host" name="upstreamHost" value="${escapeHtml(proxy.upstream?.host || '')}" placeholder="10.0.0.5" />
          </div>
          <div class="form-group">
            <label for="upstream-port">Upstream port</label>
            <input id="upstream-port" name="upstreamPort" type="number" min="1" max="65535"
                   value="${proxy.upstream?.port ?? ''}" placeholder="8080" />
          </div>
        </div>
        <label class="checkbox"><input type="checkbox" name="websocket" ${proxy.websocket ? 'checked' : ''} /> WebSocket support</label>
        <label class="checkbox"><input type="checkbox" name="preserveHost" ${proxy.preserveHost !== false ? 'checked' : ''} /> Preserve the Host header</label>
      </fieldset>

      <fieldset id="redirect-fields">
        <legend>Redirect</legend>
        <div class="form-grid">
          <div class="form-group">
            <label for="redirect-target">Target</label>
            <input id="redirect-target" name="redirectTarget" value="${escapeHtml(redirect.target || '')}" placeholder="example.com" />
          </div>
          <div class="form-group">
            <label for="redirect-status">Status</label>
            <select id="redirect-status" name="redirectStatus">
              ${[301, 302, 307, 308]
                .map(
                  (code) =>
                    `<option value="${code}" ${(redirect.status ?? 301) === code ? 'selected' : ''}>${code}</option>`,
                )
                .join('')}
            </select>
          </div>
          <div class="form-group">
            <label for="redirect-scheme">Scheme</label>
            <select id="redirect-scheme" name="redirectScheme">
              <option value="auto" ${(redirect.scheme ?? 'auto') === 'auto' ? 'selected' : ''}>auto (keep request scheme)</option>
              <option value="http" ${redirect.scheme === 'http' ? 'selected' : ''}>http</option>
              <option value="https" ${redirect.scheme === 'https' ? 'selected' : ''}>https</option>
            </select>
          </div>
        </div>
        <label class="checkbox"><input type="checkbox" name="preservePath" ${redirect.preservePath !== false ? 'checked' : ''} /> Preserve the request path</label>
      </fieldset>

      <fieldset>
        <legend>TLS</legend>
        <div class="form-group">
          <label for="tls-mode">Mode</label>
          <select id="tls-mode" name="tlsMode">
            <option value="disabled" ${tls.mode === 'disabled' ? 'selected' : ''}>Disabled (plain HTTP)</option>
            <option value="auto" ${tls.mode === 'auto' ? 'selected' : ''}>Auto (managed certificate)</option>
            <option value="manual" ${tls.mode === 'manual' ? 'selected' : ''}>Manual (uploaded certificate)</option>
          </select>
        </div>
        <div class="form-group" id="auto-policy-group">
          <label for="auto-policy">Certificate intent</label>
          <select id="auto-policy" name="autoPolicyId">
            <option value="">Choose an intent…</option>
            ${intents
              .map(
                (intent) =>
                  `<option value="${intent.policyId}" ${tls.autoPolicyId === intent.policyId ? 'selected' : ''}>${escapeHtml(
                    intent.name,
                  )} — ${escapeHtml(intent.domains.join(', '))}</option>`,
              )
              .join('')}
          </select>
          <span class="form-hint">Create intents on the Certificates page. None are configured yet if this list is empty.</span>
        </div>
        <div class="form-group" id="manual-cert-group">
          <label for="manual-cert">Certificate</label>
          <select id="manual-cert" name="certificateId">
            <option value="">Choose a certificate…</option>
            ${manual
              .map(
                (certificate) =>
                  `<option value="${certificate.id}" ${tls.certificateId === certificate.id ? 'selected' : ''}>${escapeHtml(
                    certificate.name,
                  )} — ${escapeHtml(certificate.domains.join(', '))}</option>`,
              )
              .join('')}
          </select>
          <span class="form-hint">Upload certificates on the Certificates page.</span>
        </div>
        <label class="checkbox"><input type="checkbox" name="sslForced" ${tls.sslForced ? 'checked' : ''} /> Force HTTPS</label>
        <label class="checkbox"><input type="checkbox" name="hstsEnabled" ${tls.hstsEnabled ? 'checked' : ''} /> Send HSTS</label>
        <label class="checkbox"><input type="checkbox" name="hstsSubdomains" ${tls.hstsSubdomains ? 'checked' : ''} /> HSTS includes subdomains</label>
      </fieldset>

      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary" id="save-host">${id === null ? 'Create' : 'Save'}</button>
      </div>
    </form>`,
  );

  const form = overlay.querySelector('#host-form');
  const syncFields = () => {
    const kind = form.querySelector('#kind').value;
    form.querySelector('#proxy-fields').classList.toggle('hidden', kind !== 'proxy');
    form.querySelector('#redirect-fields').classList.toggle('hidden', kind !== 'redirect');
    const mode = form.querySelector('#tls-mode').value;
    form.querySelector('#auto-policy-group').classList.toggle('hidden', mode !== 'auto');
    form.querySelector('#manual-cert-group').classList.toggle('hidden', mode !== 'manual');
  };
  form.querySelector('#kind').addEventListener('change', syncFields);
  form.querySelector('#tls-mode').addEventListener('change', syncFields);
  syncFields();

  form.querySelector('[data-close]').addEventListener('click', closeModal);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('#save-host');
    button.disabled = true;
    try {
      const payload = buildPayload(form);
      if (id === null) await hosts.create(payload);
      else await hosts.replace(id, payload, etag);
      closeModal();
      toast(id === null ? 'Host created.' : `Host ${id} updated.`);
      await loadHosts(container);
    } catch (error) {
      button.disabled = false;
      const message =
        error instanceof ApiError && error.location
          ? `${error.message} (${error.location})`
          : error.message;
      toast(message, 'danger');
    }
  });
}

function buildPayload(form) {
  const values = formValues(form);
  const kind = values.kind;
  const mode = values.tlsMode;

  const tls = {
    mode,
    sslForced: Boolean(values.sslForced),
    hstsEnabled: Boolean(values.hstsEnabled),
    hstsSubdomains: Boolean(values.hstsSubdomains),
  };
  if (mode === 'auto') tls.autoPolicyId = numberOrNull(values.autoPolicyId);
  if (mode === 'manual') tls.certificateId = numberOrNull(values.certificateId);

  let spec;
  if (kind === 'proxy') {
    spec = {
      kind: 'proxy',
      spec: {
        upstream: {
          scheme: values.scheme || 'http',
          host: values.upstreamHost,
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
        scheme: values.redirectScheme || 'auto',
        target: values.redirectTarget,
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
