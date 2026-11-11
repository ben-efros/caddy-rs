// Shared rendering helpers. Plain DOM, no framework: the whole UI is a handful of tables and forms,
// and a build that only needs Vite keeps the embedded bundle small.

export function escapeHtml(value) {
  return String(value ?? '').replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char],
  );
}

export function badge(text, tone = 'neutral') {
  return `<span class="badge badge-${escapeHtml(tone)}">${escapeHtml(text)}</span>`;
}

const TLS_TONES = {
  disabled: 'neutral',
  auto: 'ok',
  manual: 'info',
  acme_configured: 'ok',
  internal_ca: 'info',
};

export function tlsBadge(mode) {
  return badge(mode.replace(/_/g, ' '), TLS_TONES[mode] || 'neutral');
}

const STATUS_TONES = {
  applied: 'ok',
  failed: 'danger',
  pending: 'warn',
  issued: 'ok',
  expiring_soon: 'warn',
  expired: 'danger',
  renewal_error: 'danger',
};

export function statusBadge(status) {
  return badge(status.replace(/_/g, ' '), STATUS_TONES[status] || 'neutral');
}

export function enabledBadge(enabled) {
  return enabled ? badge('enabled', 'ok') : badge('disabled', 'neutral');
}

export function formatUnix(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  return new Date(seconds * 1000).toLocaleString();
}

export function formatUnixDate(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  return new Date(seconds * 1000).toLocaleDateString();
}

export function header(active) {
  const links = [
    ['/', 'Dashboard'],
    ['/hosts', 'Hosts'],
    ['/certificates', 'Certificates'],
    ['/config', 'Config'],
    ['/settings', 'Settings'],
  ];
  return `
    <header class="header">
      <div class="header-left">
        <svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
          <rect width="32" height="32" rx="7" fill="var(--accent)"/>
          <path d="M8 11h16M8 16h12M8 21h8" stroke="#0d1117" stroke-width="2.5" stroke-linecap="round"/>
        </svg>
        <span class="app-title">caddy-rs proxy manager</span>
      </div>
      <nav class="header-nav">
        ${links
          .map(
            ([href, label]) =>
              `<a href="${href}" class="nav-link${href === active ? ' active' : ''}" data-nav="${href}">${label}</a>`,
          )
          .join('')}
      </nav>
      <div class="header-right">
        <span class="who" id="whoami"></span>
        <button type="button" class="btn btn-ghost" id="logout-btn">Sign out</button>
      </div>
    </header>`;
}

export function loading(text = 'Loading…') {
  return `<div class="loading">${escapeHtml(text)}</div>`;
}

export function empty(text) {
  return `<div class="empty">${escapeHtml(text)}</div>`;
}

export function errorBox(error) {
  const location = error.location ? ` <code>${escapeHtml(error.location)}</code>` : '';
  return `<div class="error-message">${escapeHtml(error.message)}${location}</div>`;
}

export function toast(message, tone = 'ok') {
  const host = document.getElementById('toasts') || (() => {
    const element = document.createElement('div');
    element.id = 'toasts';
    document.body.appendChild(element);
    return element;
  })();
  const item = document.createElement('div');
  item.className = `toast toast-${tone}`;
  item.textContent = message;
  host.appendChild(item);
  setTimeout(() => item.remove(), 4000);
}

/** Open a modal with `bodyHtml` and return the element so callers can wire it up. */
export function openModal(title, bodyHtml) {
  closeModal();
  const overlay = document.createElement('div');
  overlay.className = 'modal';
  overlay.id = 'modal';
  overlay.innerHTML = `
    <div class="modal-overlay" data-close></div>
    <div class="modal-content" role="dialog" aria-modal="true" aria-label="${escapeHtml(title)}">
      <div class="modal-header">
        <h2>${escapeHtml(title)}</h2>
        <button type="button" class="modal-close" data-close aria-label="Close">&times;</button>
      </div>
      <div class="modal-body">${bodyHtml}</div>
    </div>`;
  overlay.addEventListener('click', (event) => {
    if (event.target.hasAttribute('data-close')) closeModal();
  });
  document.body.appendChild(overlay);
  const focusable = overlay.querySelector('input, select, textarea, button:not(.modal-close)');
  if (focusable) focusable.focus();
  return overlay;
}

export function closeModal() {
  document.getElementById('modal')?.remove();
}

/** Promise-based confirm dialog; resolves `false` on Escape or overlay click. */
export function confirmAction(title, message, confirmLabel = 'Delete') {
  return new Promise((resolve) => {
    const overlay = openModal(
      title,
      `<p class="modal-text">${escapeHtml(message)}</p>
       <div class="modal-footer">
         <button type="button" class="btn btn-ghost" data-cancel>Cancel</button>
         <button type="button" class="btn btn-danger" data-confirm>${escapeHtml(confirmLabel)}</button>
       </div>`,
    );
    const finish = (value) => {
      closeModal();
      resolve(value);
    };
    overlay.querySelector('[data-cancel]').addEventListener('click', () => finish(false));
    overlay.querySelector('[data-confirm]').addEventListener('click', () => finish(true));
    overlay.querySelector('.modal-overlay').addEventListener('click', () => finish(false));
    document.addEventListener(
      'keydown',
      (event) => {
        if (event.key === 'Escape') finish(false);
      },
      { once: true },
    );
  });
}

/** Read a form into a plain object, trimming strings and coercing numbers. */
export function formValues(form) {
  const values = {};
  for (const [key, raw] of new FormData(form).entries()) {
    if (raw instanceof File) continue;
    const value = typeof raw === 'string' ? raw.trim() : raw;
    values[key] = value;
  }
  for (const input of form.querySelectorAll('input[type="checkbox"]')) {
    values[input.name] = input.checked;
  }
  return values;
}

export function numberOrNull(value) {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/** Split a comma/newline separated domain list. */
export function parseDomains(value) {
  return String(value || '')
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}
