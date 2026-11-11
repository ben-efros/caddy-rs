import { auth, ApiError } from '../api.js';
import { startSession } from '../main.js';
import { escapeHtml } from '../ui.js';

// The login page doubles as the first-run setup page. `GET /setup` reports whether a user store
// exists, so a fresh deployment gets "create the administrator" instead of a dead end.
export async function renderLogin(container, notice = null) {
  let configured = true;
  let setupError = null;
  try {
    const { data } = await auth.setupStatus();
    configured = Boolean(data.configured);
  } catch (error) {
    setupError = error;
  }

  container.innerHTML = `
    <div class="login-page">
      <div class="login-card">
        <div class="login-header">
          <svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="var(--accent)"/>
            <path d="M8 11h16M8 16h12M8 21h8" stroke="#0d1117" stroke-width="2.5" stroke-linecap="round"/>
          </svg>
          <h1>caddy-rs proxy manager</h1>
          <p>${configured ? 'Sign in to manage hosts and certificates' : 'Create the first administrator account'}</p>
        </div>
        ${
          setupError || notice
            ? `<div class="error-message">${escapeHtml((setupError || { message: notice }).message)}</div>`
            : ''
        }
        <div id="login-error"></div>
        <form id="auth-form" autocomplete="on">
          <div class="form-group">
            <label for="username">Username</label>
            <input id="username" name="username" autocomplete="username" required autofocus />
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="${
              configured ? 'current-password' : 'new-password'
            }" required />
            ${
              configured
                ? ''
                : '<span class="form-hint">At least 8 characters. This account is created once.</span>'
            }
          </div>
          ${
            configured
              ? `<div class="form-group">
                   <label for="totp">Two-factor code <span class="muted">(if enabled)</span></label>
                   <input id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" />
                 </div>`
              : ''
          }
          <button type="submit" class="btn btn-primary btn-block" id="submit">
            ${configured ? 'Sign in' : 'Create administrator'}
          </button>
        </form>
        <p class="login-footer">
          ${
            configured
              ? 'Sessions are issued by <code>caddy-rs-pm</code> on this host.'
              : 'Setup is available only until the first account exists.'
          }
        </p>
      </div>
    </div>`;

  const form = container.querySelector('#auth-form');
  const errorHost = container.querySelector('#login-error');
  const submit = container.querySelector('#submit');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorHost.innerHTML = '';
    submit.disabled = true;
    submit.textContent = configured ? 'Signing in…' : 'Creating…';

    const data = new FormData(form);
    const username = String(data.get('username') || '').trim();
    const password = String(data.get('password') || '');
    const totp = String(data.get('totp') || '').trim();

    try {
      const response = configured
        ? await auth.login(username, password, totp || null)
        : await auth.setup(username, password, totp || null);
      startSession(response.data);
    } catch (error) {
      // A `409` on setup means another operator claimed the install while this form was open.
      // Re-render as the login form so the page stops offering an action that can never succeed.
      if (!configured && error instanceof ApiError && error.status === 409) {
        await renderLogin(container, error.message);
        return;
      }
      const message =
        error instanceof ApiError && error.location
          ? `${error.message} (${error.location})`
          : error.message || 'Authentication failed';
      errorHost.innerHTML = `<div class="error-message">${escapeHtml(message)}</div>`;
      submit.disabled = false;
      submit.textContent = configured ? 'Sign in' : 'Create administrator';
    }
  });
}
