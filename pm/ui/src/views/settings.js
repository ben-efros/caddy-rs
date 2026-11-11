import { auth, system } from '../api.js';
import { signOut } from '../main.js';
import { errorBox, escapeHtml, header, loading } from '../ui.js';

export async function renderSettings(container) {
  container.innerHTML = `
    <div class="page">
      ${header('/settings')}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Settings</h1>
            <p class="page-subtitle">Session and server facts reported by this daemon</p>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Session</h2></div>
          <div id="session">${loading()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Server</h2></div>
          <div id="server">${loading()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Sign out</h2></div>
          <div class="setting">
            <div>
              <h3>End this session</h3>
              <p>Revokes the refresh token used by this browser. Other devices stay signed in.</p>
            </div>
            <button type="button" class="btn btn-danger" id="sign-out">Sign out</button>
          </div>
        </div>
      </main>
    </div>`;

  container.querySelector('#sign-out').addEventListener('click', () => {
    void signOut();
  });

  const sessionHost = container.querySelector('#session');
  const serverHost = container.querySelector('#server');

  try {
    const { data } = await auth.me();
    sessionHost.innerHTML = `
      <div class="setting"><div><h3>Username</h3><p>${escapeHtml(data.username)}</p></div></div>
      <div class="setting"><div><h3>User ID</h3><p>${escapeHtml(data.id)}</p></div></div>
      <div class="setting"><div><h3>Role</h3><p>${escapeHtml(data.role?.name || 'unknown')}</p></div></div>
      <div class="setting"><div><h3>Two-factor</h3><p>${data.totp_enabled ? 'enabled' : 'not enabled'}</p></div></div>
      <div class="setting"><div><h3>Auth epoch</h3><p>${escapeHtml(data.auth_epoch)}</p></div></div>`;
  } catch (error) {
    sessionHost.innerHTML = `<div class="card-body">${errorBox(error)}</div>`;
  }

  try {
    const [{ data: version }, { data: health }] = await Promise.all([system.version(), system.health()]);
    serverHost.innerHTML = `
      <div class="setting"><div><h3>Proxy manager</h3><p>${escapeHtml(version.version)}</p></div></div>
      <div class="setting"><div><h3>caddy-rs core</h3><p>${escapeHtml(version.caddyRs)}</p></div></div>
      <div class="setting"><div><h3>Health</h3><p>${escapeHtml(health.status)}</p></div></div>
      <div class="setting"><div><h3>Setup complete</h3><p>${health.setup ? 'yes' : 'no'}</p></div></div>`;
  } catch (error) {
    serverHost.innerHTML = `<div class="card-body">${errorBox(error)}</div>`;
  }
}
