import { ApiError, certificates } from '../api.js';
import {
  closeModal,
  confirmAction,
  empty,
  errorBox,
  escapeHtml,
  formatUnix,
  formatUnixDate,
  header,
  loading,
  openModal,
  parseDomains,
  statusBadge,
  toast,
} from '../ui.js';

const PAGE_SIZE = 50;

const state = { tab: 'intents', offset: 0 };

export async function renderCertificates(container) {
  container.innerHTML = `
    <div class="page">
      ${header('/certificates')}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Certificates</h1>
            <p class="page-subtitle">Managed certificate intents and uploaded certificates</p>
          </div>
          <div class="btn-group">
            <button type="button" class="btn btn-primary" id="new-intent">New intent</button>
            <button type="button" class="btn btn-ghost" id="upload-certificate">Upload certificate</button>
          </div>
        </div>

        <div class="tabs">
          <button type="button" class="tab" data-tab="intents">Intents</button>
          <button type="button" class="tab" data-tab="manual">Uploaded</button>
        </div>

        <div class="card">
          <div class="table-container" id="cert-table">${loading()}</div>
          <div class="pagination hidden" id="pagination"></div>
        </div>
      </main>
    </div>`;

  const tabs = container.querySelectorAll('[data-tab]');
  tabs.forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.tab === state.tab);
    tab.addEventListener('click', () => {
      state.tab = tab.dataset.tab;
      state.offset = 0;
      tabs.forEach((other) => other.classList.toggle('active', other === tab));
      void load(container);
    });
  });

  container.querySelector('#new-intent').addEventListener('click', () => void openIntentForm(container));
  container
    .querySelector('#upload-certificate')
    .addEventListener('click', () => void openUploadForm(container));

  await load(container);
}

async function load(container) {
  const table = container.querySelector('#cert-table');
  const pagination = container.querySelector('#pagination');
  table.innerHTML = loading();

  try {
    const { data } = await certificates.list({ limit: PAGE_SIZE, offset: state.offset });
    const items = data.items.filter((item) =>
      state.tab === 'manual' ? item.origin === 'manual' : item.origin !== 'manual',
    );

    if (!items.length) {
      table.innerHTML = empty(
        state.tab === 'manual'
          ? 'No uploaded certificates. Upload a PEM chain and key to reference it from a host.'
          : 'No certificate intents. An intent lets caddy-rs obtain and renew a certificate.',
      );
      pagination.classList.add('hidden');
      return;
    }

    table.innerHTML =
      state.tab === 'manual' ? manualTable(items) : intentTable(items);
    wireRowActions(container, table);
    renderPagination(pagination, data, container);
  } catch (error) {
    // `503` means the caddy-rs data plane is unreachable: status cannot be derived from the live
    // inventory. Creating an intent does not need it, so the page keeps working and says so.
    table.innerHTML =
      error.status === 503
        ? `${errorBox(error)}<div class="card-body muted">Certificate status is read from caddy-rs. Start the data plane and reload; creating an intent still works.</div>`
        : errorBox(error);
    pagination.classList.add('hidden');
  }
}

function intentTable(items) {
  return `
    <table>
      <thead>
        <tr><th>Domains</th><th>Issuer</th><th>Challenge</th><th>Status</th><th>Expires</th><th>Revision</th><th></th></tr>
      </thead>
      <tbody>
        ${items
          .map(
            (item) => `
          <tr>
            <td>${item.domains.map((domain) => `<span class="domain">${escapeHtml(domain)}</span>`).join('')}</td>
            <td>${escapeHtml(item.issuer)}</td>
            <td>${escapeHtml(item.challenge)}</td>
            <td>${statusBadge(item.status)}${
              item.renewalError
                ? `<div class="form-hint">${escapeHtml(item.renewalError)}</div>`
                : ''
            }</td>
            <td>${formatUnix(item.expiresAtUnix)}</td>
            <td>${item.revision}</td>
            <td class="actions"></td>
          </tr>`,
          )
          .join('')}
      </tbody>
    </table>`;
}

function manualTable(items) {
  return `
    <table>
      <thead>
        <tr><th>Domains</th><th>Key</th><th>Status</th><th>Expires</th><th>Fingerprint</th><th>Revision</th><th></th></tr>
      </thead>
      <tbody>
        ${items
          .map(
            (item) => `
          <tr>
            <td>${item.domains.map((domain) => `<span class="domain">${escapeHtml(domain)}</span>`).join('')}</td>
            <td>${escapeHtml(item.keyType)}</td>
            <td>${statusBadge(item.status)}</td>
            <td>${formatUnixDate(item.expiresAtUnix)}</td>
            <td><span class="chip" title="${escapeHtml(item.fingerprintSha256)}">${escapeHtml(
              item.fingerprintSha256.slice(0, 16),
            )}…</span></td>
            <td>${item.revision}</td>
            <td class="actions">
              <button type="button" class="btn btn-danger btn-sm" data-delete-cert="${item.id}">Delete</button>
            </td>
          </tr>`,
          )
          .join('')}
      </tbody>
    </table>`;
}

function wireRowActions(container, table) {
  table.querySelectorAll('[data-delete-cert]').forEach((button) => {
    button.addEventListener('click', () => void deleteCertificate(container, Number(button.dataset.deleteCert)));
  });
}

function renderPagination(pagination, data, container) {
  const pages = Math.max(1, Math.ceil(data.total / data.limit));
  pagination.classList.toggle('hidden', pages <= 1);
  if (pages <= 1) return;
  pagination.innerHTML = `
    <button type="button" class="btn btn-ghost btn-sm" ${data.offset === 0 ? 'disabled' : ''} data-page="prev">Previous</button>
    <span>Page ${Math.floor(data.offset / data.limit) + 1} of ${pages}</span>
    <button type="button" class="btn btn-ghost btn-sm" ${
      data.offset + data.limit >= data.total ? 'disabled' : ''
    } data-page="next">Next</button>`;
  pagination.querySelector('[data-page="prev"]').addEventListener('click', () => {
    state.offset = Math.max(0, data.offset - data.limit);
    void load(container);
  });
  pagination.querySelector('[data-page="next"]').addEventListener('click', () => {
    state.offset = data.offset + data.limit;
    void load(container);
  });
}

async function deleteCertificate(container, id) {
  if (
    !(await confirmAction(
      'Delete certificate',
      `Delete uploaded certificate ${id}? Hosts referencing it must be changed first.`,
    ))
  ) {
    return;
  }
  try {
    const { etag } = await certificates.custom(id);
    await certificates.removeCustom(id, etag);
    toast(`Certificate ${id} deleted.`);
    await load(container);
  } catch (error) {
    toast(error.message, 'danger');
  }
}

function openIntentForm(container) {
  const overlay = openModal(
    'New certificate intent',
    `<form id="intent-form">
      <div class="form-group">
        <label for="intent-domains">Domains</label>
        <input id="intent-domains" name="domains" required placeholder="app.example.com, *.example.com" />
        <span class="form-hint">Up to 100 names. Wildcards need a DNS-01 challenge, which this build does not support.</span>
      </div>
      <div class="form-grid">
        <div class="form-group">
          <label for="intent-issuer">Issuer</label>
          <select id="intent-issuer" name="issuer">
            <option value="letsencrypt">Let's Encrypt</option>
            <option value="zerossl">ZeroSSL</option>
            <option value="internal">Internal CA</option>
          </select>
        </div>
        <div class="form-group">
          <label for="intent-challenge">Challenge</label>
          <select id="intent-challenge" name="challenge">
            <option value="http01">HTTP-01</option>
            <option value="tls-alpn01">TLS-ALPN-01</option>
          </select>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary" id="save-intent">Create</button>
      </div>
    </form>`,
  );

  const form = overlay.querySelector('#intent-form');
  form.querySelector('[data-close]').addEventListener('click', closeModal);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('#save-intent');
    button.disabled = true;
    const values = Object.fromEntries(new FormData(form).entries());
    try {
      await certificates.createIntent({
        domains: parseDomains(values.domains),
        issuer: values.issuer,
        challenge: values.challenge,
      });
      closeModal();
      toast('Certificate intent created.');
      await load(container);
    } catch (error) {
      button.disabled = false;
      toast(withLocation(error), 'danger');
    }
  });
}

function openUploadForm(container) {
  const overlay = openModal(
    'Upload certificate',
    `<form id="upload-form">
      <div class="form-group">
        <label for="upload-domains">Domains</label>
        <input id="upload-domains" name="domains" required placeholder="app.example.com, www.example.com" />
      </div>
      <div class="form-group">
        <label for="upload-chain">Certificate chain (PEM)</label>
        <textarea id="upload-chain" name="certificate" rows="7" required
                  placeholder="-----BEGIN CERTIFICATE-----"></textarea>
      </div>
      <div class="form-group">
        <label for="upload-key">Private key (PEM)</label>
        <textarea id="upload-key" name="privateKey" rows="7" required
                  placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
        <span class="form-hint">The key is stored in the PM data directory and never returned by the API.</span>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary" id="save-certificate">Upload</button>
      </div>
    </form>`,
  );

  const form = overlay.querySelector('#upload-form');
  form.querySelector('[data-close]').addEventListener('click', closeModal);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('#save-certificate');
    button.disabled = true;
    const values = Object.fromEntries(new FormData(form).entries());
    try {
      await certificates.createCustom({
        domains: parseDomains(values.domains),
        certificate: values.certificate,
        privateKey: values.privateKey,
      });
      closeModal();
      toast('Certificate uploaded.');
      await load(container);
    } catch (error) {
      button.disabled = false;
      toast(withLocation(error), 'danger');
    }
  });
}

function withLocation(error) {
  if (error instanceof ApiError && error.location) return `${error.message} (${error.location})`;
  return error.message;
}
