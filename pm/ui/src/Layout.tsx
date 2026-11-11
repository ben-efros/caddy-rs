// Application shell: the persistent header, navigation and the routed page area.
//
// The vanilla UI rendered the header from every view; in React it lives once in the layout so the
// session facts and the app title survive client-side navigation.

import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { auth, system } from './api';
import { useAuthenticated, useSignOut } from './auth';

const LINKS: ReadonlyArray<readonly [string, string]> = [
  ['/', 'Dashboard'],
  ['/hosts', 'Hosts'],
  ['/certificates', 'Certificates'],
  ['/config', 'Config'],
  ['/settings', 'Settings'],
];

export function Layout(): JSX.Element {
  const authenticated = useAuthenticated();
  const signOut = useSignOut();
  const [who, setWho] = useState('');
  const [title, setTitle] = useState('caddy-rs proxy manager');

  useEffect(() => {
    if (!authenticated) return undefined;
    let active = true;
    auth
      .me()
      .then(({ data }) => {
        if (active) setWho(`${data.username} · ${data.role?.name || 'user'}`);
      })
      .catch(() => {
        /* the header simply stays anonymous; the API guard already proved the session */
      });
    system
      .version()
      .then(({ data }) => {
        if (active) setTitle(`caddy-rs proxy manager ${data.version}`);
      })
      .catch(() => {
        /* keep the unversioned title */
      });
    return () => {
      active = false;
    };
  }, [authenticated]);

  return (
    <div className="page">
      <header className="header">
        <div className="header-left">
          <svg className="logo" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="var(--accent)" />
            <path
              d="M8 11h16M8 16h12M8 21h8"
              stroke="#0d1117"
              strokeWidth="2.5"
              strokeLinecap="round"
            />
          </svg>
          <span className="app-title">{title}</span>
        </div>
        <nav className="header-nav">
          {LINKS.map(([href, label]) => (
            <NavLink
              key={href}
              to={href}
              end={href === '/'}
              data-nav={href}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="header-right">
          <span className="who" id="whoami">
            {who}
          </span>
          <button type="button" className="btn btn-ghost" id="logout-btn" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </header>
      <Outlet />
    </div>
  );
}
