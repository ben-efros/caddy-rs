// Application entry point and router.
//
// Routes and guards mirror the vanilla shell: `/login` is public and doubles as first-run setup,
// every other route requires a session, authenticated users never see `/login`, and unknown paths
// fall back to the dashboard (which in turn sends anonymous visitors to `/login`).

import { useEffect, useState, type ReactElement } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import './styles.css';
import { isAuthenticated, onSessionChange } from './api';
import { SessionContext, useAuthenticated } from './auth';
import { Layout } from './Layout';
import { Login } from './views/Login';
import { Dashboard } from './views/Dashboard';
import { Hosts } from './views/Hosts';
import { Certificates } from './views/Certificates';
import { Config } from './views/Config';
import { Settings } from './views/Settings';

function RequireAuth({ children }: { children: ReactElement }): JSX.Element {
  const authenticated = useAuthenticated();
  if (!authenticated) return <Navigate to="/login" replace />;
  return children;
}

export function App(): JSX.Element {
  const [authenticated, setAuthenticated] = useState(isAuthenticated());
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => onSessionChange(setAuthenticated), []);

  // A session that expires while a protected page is open must not leave the page rendered.
  useEffect(() => {
    if (!authenticated && !location.pathname.startsWith('/login')) {
      navigate('/login', { replace: true });
    }
  }, [authenticated, location.pathname, navigate]);

  return (
    <SessionContext.Provider value={authenticated}>
      <Routes>
        <Route path="/login" element={authenticated ? <Navigate to="/" replace /> : <Login />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Dashboard />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/certificates" element={<Certificates />} />
          <Route path="/config" element={<Config />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </SessionContext.Provider>
  );
}

const container = document.getElementById('app');
if (!container) throw new Error('missing #app mount point');
createRoot(container).render(
  <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
    <App />
  </BrowserRouter>,
);
