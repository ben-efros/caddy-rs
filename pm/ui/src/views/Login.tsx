// The login page doubles as the first-run setup page. `GET /setup` reports whether a user store
// exists, so a fresh deployment gets "create the administrator" instead of a dead end.

import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiError, auth, setSession } from '../api';

export function Login(): JSX.Element {
  const navigate = useNavigate();
  const [configured, setConfigured] = useState(true);
  const [setupError, setSetupError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let active = true;
    auth
      .setupStatus()
      .then(({ data }) => {
        if (active) setConfigured(Boolean(data.configured));
      })
      .catch((failure: unknown) => {
        if (active) setSetupError(failure);
      });
    return () => {
      active = false;
    };
  }, []);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const data = new FormData(event.currentTarget);
    const username = String(data.get('username') || '').trim();
    const password = String(data.get('password') || '');
    const totp = String(data.get('totp') || '').trim();

    try {
      const response = configured
        ? await auth.login(username, password, totp || null)
        : await auth.setup(username, password, totp || null);
      setSession(response.data);
      navigate('/', { replace: true });
    } catch (failure) {
      // A `409` on setup means another operator claimed the install while this form was open.
      // Re-render as the login form so the page stops offering an action that can never succeed.
      if (!configured && failure instanceof ApiError && failure.status === 409) {
        setNotice(failure.message);
        try {
          const { data: status } = await auth.setupStatus();
          setConfigured(Boolean(status.configured));
        } catch {
          setConfigured(true);
        }
        setSubmitting(false);
        return;
      }
      const message =
        failure instanceof ApiError && failure.location
          ? `${failure.message} (${failure.location})`
          : failure instanceof Error
            ? failure.message || 'Authentication failed'
            : 'Authentication failed';
      setError(message);
      setSubmitting(false);
    }
  };

  const noticeMessage = setupError instanceof Error ? setupError.message : notice;

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <svg className="logo" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="var(--accent)" />
            <path
              d="M8 11h16M8 16h12M8 21h8"
              stroke="#0d1117"
              strokeWidth="2.5"
              strokeLinecap="round"
            />
          </svg>
          <h1>caddy-rs proxy manager</h1>
          <p>
            {configured
              ? 'Sign in to manage hosts and certificates'
              : 'Create the first administrator account'}
          </p>
        </div>
        {noticeMessage ? <div className="error-message">{noticeMessage}</div> : null}
        <div id="login-error">{error ? <div className="error-message">{error}</div> : null}</div>
        <form id="auth-form" autoComplete="on" onSubmit={(event) => void onSubmit(event)}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input id="username" name="username" autoComplete="username" required autoFocus />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete={configured ? 'current-password' : 'new-password'}
              required
            />
            {configured ? null : (
              <span className="form-hint">At least 8 characters. This account is created once.</span>
            )}
          </div>
          {configured ? (
            <div className="form-group">
              <label htmlFor="totp">
                Two-factor code <span className="muted">(if enabled)</span>
              </label>
              <input
                id="totp"
                name="totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
              />
            </div>
          ) : null}
          <button type="submit" className="btn btn-primary btn-block" id="submit" disabled={submitting}>
            {configured
              ? submitting
                ? 'Signing in…'
                : 'Sign in'
              : submitting
                ? 'Creating…'
                : 'Create administrator'}
          </button>
        </form>
        <p className="login-footer">
          {configured ? (
            <>
              Sessions are issued by <code>caddy-rs-pm</code> on this host.
            </>
          ) : (
            'Setup is available only until the first account exists.'
          )}
        </p>
      </div>
    </div>
  );
}
