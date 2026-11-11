// Shared rendering helpers for the React UI: badges, formatters, the modal shell, toasts and the
// promise-based confirm dialog. Keeping them here means the views stay declarative while the few
// genuinely imperative pieces (toast lifetime, confirm promise) have one implementation.

import { createRoot } from 'react-dom/client';
import type { ReactNode } from 'react';
import { ApiError } from './api';

export type Tone = 'neutral' | 'ok' | 'info' | 'danger' | 'warn';

export function Badge({ text, tone = 'neutral' }: { text: string; tone?: Tone }): JSX.Element {
  return <span className={`badge badge-${tone}`}>{text}</span>;
}

const TLS_TONES: Record<string, Tone> = {
  disabled: 'neutral',
  auto: 'ok',
  manual: 'info',
  acme_configured: 'ok',
  internal_ca: 'info',
};

export function TlsBadge({ mode }: { mode: string }): JSX.Element {
  return <Badge text={mode.replace(/_/g, ' ')} tone={TLS_TONES[mode] || 'neutral'} />;
}

const STATUS_TONES: Record<string, Tone> = {
  applied: 'ok',
  failed: 'danger',
  pending: 'warn',
  issued: 'ok',
  expiring_soon: 'warn',
  expired: 'danger',
  renewal_error: 'danger',
};

export function StatusBadge({ status }: { status: string }): JSX.Element {
  return <Badge text={status.replace(/_/g, ' ')} tone={STATUS_TONES[status] || 'neutral'} />;
}

export function EnabledBadge({ enabled }: { enabled: boolean }): JSX.Element {
  return enabled ? <Badge text="enabled" tone="ok" /> : <Badge text="disabled" tone="neutral" />;
}

export function formatUnix(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return '—';
  return new Date(seconds * 1000).toLocaleString();
}

export function formatUnixDate(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return '—';
  return new Date(seconds * 1000).toLocaleDateString();
}

export function Loading({ text = 'Loading…' }: { text?: string }): JSX.Element {
  return <div className="loading">{text}</div>;
}

export function Empty({ text }: { text: string }): JSX.Element {
  return <div className="empty">{text}</div>;
}

export function ErrorBox({ error }: { error: unknown }): JSX.Element {
  const message = error instanceof Error ? error.message : String(error);
  const location = error instanceof ApiError ? error.location : null;
  return (
    <div className="error-message">
      {message}
      {location ? (
        <>
          {' '}
          <code>{location}</code>
        </>
      ) : null}
    </div>
  );
}

export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}): JSX.Element {
  return (
    <div className="modal" id="modal">
      <div className="modal-overlay" onClick={onClose} />
      <div className="modal-content" role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="modal-close" aria-label="Close" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

/** Append a transient toast; returns nothing and cleans itself up after four seconds. */
export function toast(message: string, tone: 'ok' | 'danger' = 'ok'): void {
  const host =
    document.getElementById('toasts') ??
    (() => {
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

/** Promise-based confirm dialog; resolves `false` on Escape or overlay click. */
export function confirmAction(
  title: string,
  message: string,
  confirmLabel = 'Delete',
): Promise<boolean> {
  return new Promise((resolve) => {
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    let done = false;
    const finish = (value: boolean): void => {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKey);
      resolve(value);
      // Unmounting from inside a React event handler of this same root is not allowed; defer it.
      setTimeout(() => {
        root.unmount();
        container.remove();
      }, 0);
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') finish(false);
    };
    document.addEventListener('keydown', onKey);
    root.render(
      <div className="modal" id="modal">
        <div className="modal-overlay" onClick={() => finish(false)} />
        <div className="modal-content" role="dialog" aria-modal="true" aria-label={title}>
          <div className="modal-header">
            <h2>{title}</h2>
            <button type="button" className="modal-close" aria-label="Close" onClick={() => finish(false)}>
              &times;
            </button>
          </div>
          <div className="modal-body">
            <p className="modal-text">{message}</p>
            <div className="modal-footer">
              <button type="button" className="btn btn-ghost" onClick={() => finish(false)}>
                Cancel
              </button>
              <button type="button" className="btn btn-danger" onClick={() => finish(true)}>
                {confirmLabel}
              </button>
            </div>
          </div>
        </div>
      </div>,
    );
  });
}

/** Read a form into a plain object, trimming strings and keeping checkbox booleans. */
export function formValues(form: HTMLFormElement): Record<string, string | boolean> {
  const values: Record<string, string | boolean> = {};
  for (const [key, raw] of new FormData(form).entries()) {
    // File inputs are not part of this UI's forms; every value that matters is a string.
    if (typeof raw !== 'string') continue;
    values[key] = raw.trim();
  }
  for (const input of form.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')) {
    values[input.name] = input.checked;
  }
  return values;
}

export function numberOrNull(value: unknown): number | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/** Split a comma/newline separated domain list. */
export function parseDomains(value: unknown): string[] {
  return String(value || '')
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}
