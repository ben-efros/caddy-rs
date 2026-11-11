// Configuration: the assembled Caddy JSON, the durable apply history and the apply action.
//
// The JSON is rendered as text, not escaped HTML, so it is always safe and always shows exactly
// what the server assembled.

import { useEffect, useState } from 'react';
import {
  config,
  type ApplyResult,
  type ConfigDocument,
  type ConfigRevision,
} from '../api';
import {
  Empty,
  ErrorBox,
  Loading,
  StatusBadge,
  formatUnix,
  toast,
} from '../ui';

type Tab = 'config' | 'revisions';

type Panel =
  | { kind: 'config'; data: ConfigDocument; etag: string | null }
  | { kind: 'revisions'; items: ConfigRevision[] };

type ApplyOutcome = { ok: true; result: ApplyResult } | { ok: false; error: unknown };

export function Config(): JSX.Element {
  const [tab, setTab] = useState<Tab>('config');
  const [panel, setPanel] = useState<Panel | null>(null);
  const [panelError, setPanelError] = useState<unknown>(null);
  const [applying, setApplying] = useState(false);
  const [applyOutcome, setApplyOutcome] = useState<ApplyOutcome | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setPanel(null);
    setPanelError(null);
    const request: Promise<Panel> =
      tab === 'config'
        ? config.get().then(({ data, etag }) => ({ kind: 'config' as const, data, etag }))
        : config
            .revisions({ limit: 50 })
            .then(({ data }) => ({ kind: 'revisions' as const, items: data.items }));
    void request
      .then((next) => {
        if (active) setPanel(next);
      })
      .catch((failure: unknown) => {
        if (active) setPanelError(failure);
      });
    return () => {
      active = false;
    };
  }, [tab, reloadKey]);

  const apply = async (): Promise<void> => {
    setApplying(true);
    setApplyOutcome(null);
    try {
      const { data } = await config.apply();
      setApplyOutcome({ ok: true, result: data });
      setReloadKey((value) => value + 1);
    } catch (failure) {
      setApplyOutcome({ ok: false, error: failure });
      toast(errorMessage(failure), 'danger');
    } finally {
      setApplying(false);
    }
  };

  return (
    <main className="main-content">
      <div className="page-header">
        <div>
          <h1>Configuration</h1>
          <p className="page-subtitle">The assembled Caddy JSON and the durable apply history</p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          id="apply"
          disabled={applying}
          onClick={() => void apply()}
        >
          {applying ? 'Applying…' : 'Apply to caddy-rs'}
        </button>
      </div>

      <div id="apply-result">
        {applyOutcome === null ? null : applyOutcome.ok ? (
          <div className="success-message">
            Revision {applyOutcome.result.revision}{' '}
            {applyOutcome.result.changed ? 'applied' : 'already up to date'} · hash{' '}
            <span className="chip">{applyOutcome.result.hash.slice(0, 16)}…</span>
          </div>
        ) : (
          <ErrorBox error={applyOutcome.error} />
        )}
      </div>

      <div className="tabs">
        <button
          type="button"
          className={`tab${tab === 'config' ? ' active' : ''}`}
          data-tab="config"
          onClick={() => setTab('config')}
        >
          Assembled config
        </button>
        <button
          type="button"
          className={`tab${tab === 'revisions' ? ' active' : ''}`}
          data-tab="revisions"
          onClick={() => setTab('revisions')}
        >
          Apply history
        </button>
      </div>

      <div className="card" id="panel">
        {panelError !== null ? (
          <div className="card-body">
            <ErrorBox error={panelError} />
          </div>
        ) : panel === null ? (
          <Loading />
        ) : panel.kind === 'config' ? (
          <>
            <div className="card-header">
              <h2>Assembled Caddy JSON</h2>
              <span className="chip" title="Weak ETag for this representation">
                {panel.etag || 'no etag'}
              </span>
            </div>
            <div className="code-block">
              <pre>{JSON.stringify(panel.data, null, 2)}</pre>
            </div>
            <div className="meta-row">
              <span>Hosts and certificate policies are compiled on read, so this view is always current.</span>
            </div>
          </>
        ) : panel.items.length === 0 ? (
          <Empty text="Nothing has been applied yet. Create a host, then apply." />
        ) : (
          <RevisionsTable items={panel.items} />
        )}
      </div>
    </main>
  );
}

function RevisionsTable({ items }: { items: ConfigRevision[] }): JSX.Element {
  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Revision</th>
            <th>Status</th>
            <th>Changed</th>
            <th>Hash</th>
            <th>Recorded</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {items.map((revision) => (
            <tr key={revision.revision}>
              <td>{revision.revision}</td>
              <td>
                <StatusBadge status={revision.status} />
              </td>
              <td>{revision.changed ? 'yes' : 'no'}</td>
              <td>
                <span className="chip" title={revision.hash}>
                  {revision.hash.slice(0, 12)}…
                </span>
              </td>
              <td>{formatUnix(revision.recordedAtUnix)}</td>
              <td>{revision.error ? revision.error : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function errorMessage(failure: unknown): string {
  if (failure instanceof Error) return failure.message;
  return 'Request failed';
}
