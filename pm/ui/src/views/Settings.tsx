// Settings: the session facts and the server facts this daemon reports, plus sign-out.
//
// The two cards load independently: an unreachable data plane breaks the server card only, while
// the session card keeps rendering the authenticated user.

import { useEffect, useState } from 'react';
import { auth, system, type CurrentUser, type HealthInfo, type VersionInfo } from '../api';
import { ErrorBox, Loading } from '../ui';
import { useSignOut } from '../auth';

export function Settings(): JSX.Element {
  const signOut = useSignOut();
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [userError, setUserError] = useState<unknown>(null);
  const [server, setServer] = useState<{ version: VersionInfo; health: HealthInfo } | null>(null);
  const [serverError, setServerError] = useState<unknown>(null);

  useEffect(() => {
    let active = true;
    auth
      .me()
      .then(({ data }) => {
        if (active) setUser(data);
      })
      .catch((failure: unknown) => {
        if (active) setUserError(failure);
      });
    void Promise.all([system.version(), system.health()])
      .then(([{ data: version }, { data: health }]) => {
        if (active) setServer({ version, health });
      })
      .catch((failure: unknown) => {
        if (active) setServerError(failure);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <main className="main-content">
      <div className="page-header">
        <div>
          <h1>Settings</h1>
          <p className="page-subtitle">Session and server facts reported by this daemon</p>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Session</h2>
        </div>
        <div id="session">
          {userError !== null ? (
            <div className="card-body">
              <ErrorBox error={userError} />
            </div>
          ) : user === null ? (
            <Loading />
          ) : (
            <>
              <div className="setting">
                <div>
                  <h3>Username</h3>
                  <p>{user.username}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>User ID</h3>
                  <p>{user.id}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>Role</h3>
                  <p>{user.role?.name || 'unknown'}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>Two-factor</h3>
                  <p>{user.totp_enabled ? 'enabled' : 'not enabled'}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>Auth epoch</h3>
                  <p>{String(user.auth_epoch ?? '')}</p>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Server</h2>
        </div>
        <div id="server">
          {serverError !== null ? (
            <div className="card-body">
              <ErrorBox error={serverError} />
            </div>
          ) : server === null ? (
            <Loading />
          ) : (
            <>
              <div className="setting">
                <div>
                  <h3>Proxy manager</h3>
                  <p>{server.version.version}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>caddy-rs core</h3>
                  <p>{server.version.caddyRs}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>Health</h3>
                  <p>{server.health.status}</p>
                </div>
              </div>
              <div className="setting">
                <div>
                  <h3>Setup complete</h3>
                  <p>{server.health.setup ? 'yes' : 'no'}</p>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Sign out</h2>
        </div>
        <div className="setting">
          <div>
            <h3>End this session</h3>
            <p>Revokes the refresh token used by this browser. Other devices stay signed in.</p>
          </div>
          <button type="button" className="btn btn-danger" id="sign-out" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </div>
    </main>
  );
}
