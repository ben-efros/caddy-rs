import './styles.css';
import { auth, clearSession, isAuthenticated, onSessionChange, setSession } from './api.js';
import { renderLogin } from './views/login.js';
import { renderDashboard } from './views/dashboard.js';
import { renderHosts } from './views/hosts.js';
import { renderCertificates } from './views/certificates.js';
import { renderConfig } from './views/config.js';
import { renderSettings } from './views/settings.js';

const routes = [
  { pattern: /^\/login$/, render: renderLogin, requiresAuth: false },
  { pattern: /^\/$/, render: renderDashboard, requiresAuth: true },
  { pattern: /^\/hosts$/, render: renderHosts, requiresAuth: true },
  { pattern: /^\/certificates$/, render: renderCertificates, requiresAuth: true },
  { pattern: /^\/config$/, render: renderConfig, requiresAuth: true },
  { pattern: /^\/settings$/, render: renderSettings, requiresAuth: true },
];

let currentPath = null;

export function navigate(path, { replace = false } = {}) {
  if (replace) window.history.replaceState({}, '', path);
  else window.history.pushState({}, '', path);
  void render();
}

export function currentRoute() {
  return currentPath;
}

async function render() {
  const path = window.location.pathname;
  const route = routes.find((candidate) => candidate.pattern.test(path)) ?? routes[1];

  if (route.requiresAuth && !isAuthenticated()) {
    navigate('/login', { replace: true });
    return;
  }
  if (!route.requiresAuth && isAuthenticated() && path === '/login') {
    navigate('/', { replace: true });
    return;
  }

  currentPath = path;
  const app = document.getElementById('app');
  app.replaceChildren();
  try {
    await route.render(app);
  } catch (error) {
    console.error('render failed', error);
    app.innerHTML = `<div class="main-content"><div class="error-message">${
      error && error.message ? error.message : 'Failed to render page'
    }</div></div>`;
  }
}

/** Sign out: revoke the session server-side, then drop local tokens even if that call fails. */
export async function signOut() {
  try {
    await auth.logout();
  } catch (error) {
    console.warn('logout failed; clearing local session anyway', error);
  }
  clearSession();
  navigate('/login', { replace: true });
}

export function startSession(session) {
  setSession(session);
  navigate('/', { replace: true });
}

// Navigation is delegated once: views replace the whole document body, so per-view listeners would
// pile up with every render.
document.addEventListener('click', (event) => {
  const link = event.target.closest('[data-nav]');
  if (link) {
    event.preventDefault();
    navigate(link.getAttribute('data-nav'));
  }
  if (event.target.closest('#logout-btn')) {
    event.preventDefault();
    void signOut();
  }
});

window.addEventListener('popstate', () => void render());

onSessionChange((authenticated) => {
  if (!authenticated && !window.location.pathname.startsWith('/login')) {
    navigate('/login', { replace: true });
  }
});

void render();
