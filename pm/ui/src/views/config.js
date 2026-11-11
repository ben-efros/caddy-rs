import { config } from '../api.js';
import {
  empty,
  errorBox,
  escapeHtml,
  formatUnix,
  header,
  loading,
  statusBadge,
  toast,
} from '../ui.js';

const state = { tab: 'config' };

export async function renderConfig(container) {
  container.innerHTML = `
    <div class="page">
      ${header('/config')}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Configuration</h1>
            <p class="page-subtitle">The assembled Caddy JSON and the durable apply history</p>
          </div>
          <button type="button" class="btn btn-primary" id="apply">Apply to caddy-rs</button>
        </div>

        <div id="apply-result"></div>

        <div class="tabs">
          <button type="button" class="tab" data-tab="config">Assembled config</button>
          <button type="button" class="tab" data-tab="revisions">Apply history</button>
        </div>

        <div class="card" id="panel">${loading()}</div>
      </main>
    </div>`;

  const tabs = container.querySelectorAll('[data-tab]');
  tabs.forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.tab === state.tab);
    tab.addEventListener('click', () => {
      state.tab = tab.dataset.tab;
      tabs.forEach((other) => other.classList.toggle('active', other === tab));
      void loadPanel(container);
    });
  });

  container.querySelector('#apply').addEventListener('click', () => void apply(container));

  await loadPanel(container);
}

async function loadPanel(container) {
  const panel = container.querySelector('#panel');
  panel.innerHTML = loading();
  if (state.tab === 'config') await showConfig(panel);
  else await showRevisions(panel);
}

async function showConfig(panel) {
  try {
    const { data, etag } = await config.get();
    panel.innerHTML = `
      <div class="card-header">
        <h2>Assembled Caddy JSON</h2>
        <span class="chip" title="Weak ETag for this representation">${escapeHtml(etag || 'no etag')}</span>
      </div>
      <div class="code-block"><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre></div>
      <div class="meta-row">
        <span>Hosts and certificate policies are compiled on read, so this view is always current.</span>
      </div>`;
  } catch (error) {
    panel.innerHTML = `<div class="card-body">${errorBox(error)}</div>`;
  }
}

async function showRevisions(panel) {
  try {
    const { data } = await config.revisions({ limit: 50 });
    if (!data.items.length) {
      panel.innerHTML = empty('Nothing has been applied yet. Create a host, then apply.');
      return;
    }
    panel.innerHTML = `
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Revision</th><th>Status</th><th>Changed</th><th>Hash</th><th>Recorded</th><th>Error</th></tr>
          </thead>
          <tbody>
            ${data.items
              .map(
                (revision) => `
              <tr>
                <td>${revision.revision}</td>
                <td>${statusBadge(revision.status)}</td>
                <td>${revision.changed ? 'yes' : 'no'}</td>
                <td><span class="chip" title="${escapeHtml(revision.hash)}">${escapeHtml(
                  revision.hash.slice(0, 12),
                )}…</span></td>
                <td>${formatUnix(revision.recordedAtUnix)}</td>
                <td>${revision.error ? escapeHtml(revision.error) : '—'}</td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>
      </div>`;
  } catch (error) {
    panel.innerHTML = `<div class="card-body">${errorBox(error)}</div>`;
  }
}

async function apply(container) {
  const button = container.querySelector('#apply');
  const result = container.querySelector('#apply-result');
  button.disabled = true;
  button.textContent = 'Applying…';
  result.innerHTML = '';
  try {
    const { data } = await config.apply();
    result.innerHTML = `<div class="success-message">Revision ${data.revision} ${
      data.changed ? 'applied' : 'already up to date'
    } · hash <span class="chip">${escapeHtml(data.hash.slice(0, 16))}…</span></div>`;
    await loadPanel(container);
  } catch (error) {
    result.innerHTML = errorBox(error);
    toast(error.message, 'danger');
  } finally {
    button.disabled = false;
    button.textContent = 'Apply to caddy-rs';
  }
}
