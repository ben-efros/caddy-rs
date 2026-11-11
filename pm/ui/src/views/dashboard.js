import { auth, certificates, config, hosts, system } from '../api.js';
import {
  empty,
  errorBox,
  escapeHtml,
  formatUnix,
  header,
  loading,
  statusBadge,
  tlsBadge,
  enabledBadge,
} from '../ui.js';

export async function renderDashboard(container) {
  container.innerHTML = `
    <div class="page">
      ${header('/')}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Dashboard</h1>
            <p class="page-subtitle">Live view of hosts, certificates and the applied configuration</p>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><span class="stat-value" id="stat-hosts">—</span><span class="stat-label">Hosts</span></div>
          <div class="stat"><span class="stat-value" id="stat-enabled">—</span><span class="stat-label">Enabled</span></div>
          <div class="stat"><span class="stat-value" id="stat-certs">—</span><span class="stat-label">Certificates</span></div>
          <div class="stat"><span class="stat-value" id="stat-revision">—</span><span class="stat-label">Config revision</span></div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Hosts</h2><a class="btn btn-ghost btn-sm" href="/hosts" data-nav="/hosts">Manage</a></div>
          <div class="table-container" id="hosts-table">${loading()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Certificates</h2><a class="btn btn-ghost btn-sm" href="/certificates" data-nav="/certificates">Manage</a></div>
          <div class="table-container" id="certs-table">${loading()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Recent applies</h2><a class="btn btn-ghost btn-sm" href="/config" data-nav="/config">Configuration</a></div>
          <div class="table-container" id="revisions-table">${loading()}</div>
        </div>
      </main>
    </div>`;

  try {
    const { data: me } = await auth.me();
    const who = container.querySelector('#whoami');
    if (who) who.textContent = `${me.username} · ${me.role?.name || 'user'}`;
  } catch {
    /* the header simply stays anonymous; the API guard already proved the session */
  }

  const [hostsResult, certsResult, revisionsResult, versionResult] = await Promise.allSettled([
    hosts.list({ limit: 5 }),
    certificates.list({ limit: 5 }),
    config.revisions({ limit: 5 }),
    system.version(),
  ]);

  if (versionResult.status === 'fulfilled') {
    const title = container.querySelector('.app-title');
    if (title) title.textContent = `caddy-rs proxy manager ${versionResult.value.data.version}`;
  }

  if (hostsResult.status === 'fulfilled') {
    const { items, total } = hostsResult.value.data;
    container.querySelector('#stat-hosts').textContent = String(total);
    container.querySelector('#stat-enabled').textContent = String(items.filter((item) => item.enabled).length);
    container.querySelector('#hosts-table').innerHTML = items.length
      ? hostsTable(items)
      : empty('No hosts yet. Create one from the Hosts page.');
  } else {
    container.querySelector('#stat-hosts').textContent = '—';
    container.querySelector('#hosts-table').innerHTML = errorBox(hostsResult.reason);
  }

  if (certsResult.status === 'fulfilled') {
    const { items, total } = certsResult.value.data;
    container.querySelector('#stat-certs').textContent = String(total);
    container.querySelector('#certs-table').innerHTML = items.length
      ? certsTable(items)
      : empty('No certificates or intents yet.');
  } else {
    container.querySelector('#stat-certs').textContent = '—';
    container.querySelector('#certs-table').innerHTML = errorBox(certsResult.reason);
  }

  if (revisionsResult.status === 'fulfilled') {
    const { items } = revisionsResult.value.data;
    const latest = items[0];
    container.querySelector('#stat-revision').textContent = latest ? String(latest.revision) : '0';
    container.querySelector('#revisions-table').innerHTML = items.length
      ? revisionsTable(items)
      : empty('Nothing applied yet.');
  } else {
    container.querySelector('#stat-revision').textContent = '—';
    container.querySelector('#revisions-table').innerHTML = errorBox(revisionsResult.reason);
  }
}

function hostsTable(items) {
  return `
    <table>
      <thead><tr><th>ID</th><th>Domains</th><th>Kind</th><th>TLS</th><th>State</th></tr></thead>
      <tbody>
        ${items
          .map(
            (host) => `
          <tr>
            <td>${host.id}</td>
            <td>${host.domains.map((domain) => `<span class="domain">${escapeHtml(domain)}</span>`).join('')}</td>
            <td>${escapeHtml(host.kind)}</td>
            <td>${tlsBadge(host.tlsMode)}</td>
            <td>${enabledBadge(host.enabled)}</td>
          </tr>`,
          )
          .join('')}
      </tbody>
    </table>`;
}

function certsTable(items) {
  return `
    <table>
      <thead><tr><th>Domains</th><th>Origin</th><th>Status</th><th>Expires</th></tr></thead>
      <tbody>
        ${items
          .map(
            (item) => `
          <tr>
            <td>${(item.domains || []).map((domain) => `<span class="domain">${escapeHtml(domain)}</span>`).join('')}</td>
            <td>${escapeHtml(item.origin)}</td>
            <td>${statusBadge(item.status)}</td>
            <td>${formatUnix(item.expiresAtUnix)}</td>
          </tr>`,
          )
          .join('')}
      </tbody>
    </table>`;
}

function revisionsTable(items) {
  return `
    <table>
      <thead><tr><th>Revision</th><th>Status</th><th>Changed</th><th>Recorded</th><th>Error</th></tr></thead>
      <tbody>
        ${items
          .map(
            (revision) => `
          <tr>
            <td>${revision.revision}</td>
            <td>${statusBadge(revision.status)}</td>
            <td>${revision.changed ? 'yes' : 'no'}</td>
            <td>${formatUnix(revision.recordedAtUnix)}</td>
            <td>${revision.error ? escapeHtml(revision.error) : '—'}</td>
          </tr>`,
          )
          .join('')}
      </tbody>
    </table>`;
}
