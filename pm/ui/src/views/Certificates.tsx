// Certificates: managed certificate intents, uploaded certificates and their create/upload forms.
//
// The two modal forms stay uncontrolled on purpose: the smoke test (and a real browser) fills the
// DOM directly and submits, so every value is read from FormData rather than from React state.

import { useEffect, useState, type FormEvent } from 'react';
import { ApiError, certificates, type CertificateItem, type Page } from '../api';
import {
  Empty,
  ErrorBox,
  Loading,
  Modal,
  StatusBadge,
  confirmAction,
  formValues,
  formatUnix,
  formatUnixDate,
  parseDomains,
  toast,
} from '../ui';

const PAGE_SIZE = 50;

type Tab = 'intents' | 'manual';
type Dialog = 'intent' | 'upload' | null;

export function Certificates(): JSX.Element {
  const [tab, setTab] = useState<Tab>('intents');
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page<CertificateItem> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [saving, setSaving] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const reload = (): void => {
    setReloadKey((value) => value + 1);
  };

  useEffect(() => {
    let active = true;
    setPage(null);
    setError(null);
    certificates
      .list({ limit: PAGE_SIZE, offset })
      .then(({ data }) => {
        if (active) setPage(data);
      })
      .catch((failure: unknown) => {
        if (active) setError(failure);
      });
    return () => {
      active = false;
    };
  }, [offset, reloadKey]);

  const selectTab = (next: Tab): void => {
    setTab(next);
    setOffset(0);
  };

  const items =
    page === null
      ? []
      : page.items.filter((item) =>
          tab === 'manual' ? item.origin === 'manual' : item.origin !== 'manual',
        );

  const pages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1;

  const deleteCertificate = async (id: number): Promise<void> => {
    if (
      !(await confirmAction(
        'Delete certificate',
        `Delete uploaded certificate ${id}? Hosts referencing it must be changed first.`,
      ))
    ) {
      return;
    }
    try {
      const { etag } = await certificates.custom(id);
      await certificates.removeCustom(id, etag);
      toast(`Certificate ${id} deleted.`);
      reload();
    } catch (failure) {
      toast(errorMessage(failure), 'danger');
    }
  };

  const submitIntent = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const values = formValues(event.currentTarget);
    setSaving(true);
    try {
      await certificates.createIntent({
        domains: parseDomains(values.domains),
        issuer: String(values.issuer ?? 'letsencrypt'),
        challenge: String(values.challenge ?? 'http01'),
      });
      setDialog(null);
      toast('Certificate intent created.');
      reload();
    } catch (failure) {
      toast(errorMessage(failure), 'danger');
    } finally {
      setSaving(false);
    }
  };

  const submitUpload = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const values = formValues(event.currentTarget);
    setSaving(true);
    try {
      await certificates.createCustom({
        domains: parseDomains(values.domains),
        certificate: String(values.certificate ?? ''),
        privateKey: String(values.privateKey ?? ''),
      });
      setDialog(null);
      toast('Certificate uploaded.');
      reload();
    } catch (failure) {
      toast(errorMessage(failure), 'danger');
    } finally {
      setSaving(false);
    }
  };

  return (
    <main className="main-content">
      <div className="page-header">
        <div>
          <h1>Certificates</h1>
          <p className="page-subtitle">Managed certificate intents and uploaded certificates</p>
        </div>
        <div className="btn-group">
          <button type="button" className="btn btn-primary" id="new-intent" onClick={() => setDialog('intent')}>
            New intent
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            id="upload-certificate"
            onClick={() => setDialog('upload')}
          >
            Upload certificate
          </button>
        </div>
      </div>

      <div className="tabs">
        <button
          type="button"
          className={`tab${tab === 'intents' ? ' active' : ''}`}
          data-tab="intents"
          onClick={() => selectTab('intents')}
        >
          Intents
        </button>
        <button
          type="button"
          className={`tab${tab === 'manual' ? ' active' : ''}`}
          data-tab="manual"
          onClick={() => selectTab('manual')}
        >
          Uploaded
        </button>
      </div>

      <div className="card">
        <div className="table-container" id="cert-table">
          {error !== null ? (
            <>
              <ErrorBox error={error} />
              {error instanceof ApiError && error.status === 503 ? (
                // `503` means the caddy-rs data plane is unreachable: status cannot be derived from
                // the live inventory. Creating an intent does not need it, so the page keeps
                // working and says so.
                <div className="card-body muted">
                  Certificate status is read from caddy-rs. Start the data plane and reload; creating
                  an intent still works.
                </div>
              ) : null}
            </>
          ) : page === null ? (
            <Loading />
          ) : items.length === 0 ? (
            <Empty
              text={
                tab === 'manual'
                  ? 'No uploaded certificates. Upload a PEM chain and key to reference it from a host.'
                  : 'No certificate intents. An intent lets caddy-rs obtain and renew a certificate.'
              }
            />
          ) : tab === 'manual' ? (
            <ManualTable items={items} onDelete={(id) => void deleteCertificate(id)} />
          ) : (
            <IntentTable items={items} />
          )}
        </div>
        <div
          className={`pagination${page !== null && items.length > 0 && pages > 1 ? '' : ' hidden'}`}
          id="pagination"
        >
          {page !== null && items.length > 0 && pages > 1 ? (
            <>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={page.offset === 0}
                data-page="prev"
                onClick={() => setOffset(Math.max(0, page.offset - page.limit))}
              >
                Previous
              </button>
              <span>
                Page {Math.floor(page.offset / page.limit) + 1} of {pages}
              </span>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={page.offset + page.limit >= page.total}
                data-page="next"
                onClick={() => setOffset(page.offset + page.limit)}
              >
                Next
              </button>
            </>
          ) : null}
        </div>
      </div>

      {dialog === 'intent' ? (
        <Modal title="New certificate intent" onClose={() => setDialog(null)}>
          <form id="intent-form" onSubmit={(event) => void submitIntent(event)}>
            <div className="form-group">
              <label htmlFor="intent-domains">Domains</label>
              <input
                id="intent-domains"
                name="domains"
                required
                placeholder="app.example.com, *.example.com"
              />
              <span className="form-hint">
                Up to 100 names. Wildcards need a DNS-01 challenge, which this build does not support.
              </span>
            </div>
            <div className="form-grid">
              <div className="form-group">
                <label htmlFor="intent-issuer">Issuer</label>
                <select id="intent-issuer" name="issuer" defaultValue="letsencrypt">
                  <option value="letsencrypt">Let&apos;s Encrypt</option>
                  <option value="zerossl">ZeroSSL</option>
                  <option value="internal">Internal CA</option>
                </select>
              </div>
              <div className="form-group">
                <label htmlFor="intent-challenge">Challenge</label>
                <select id="intent-challenge" name="challenge" defaultValue="http01">
                  <option value="http01">HTTP-01</option>
                  <option value="tls-alpn01">TLS-ALPN-01</option>
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-ghost" data-close onClick={() => setDialog(null)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" id="save-intent" disabled={saving}>
                Create
              </button>
            </div>
          </form>
        </Modal>
      ) : null}

      {dialog === 'upload' ? (
        <Modal title="Upload certificate" onClose={() => setDialog(null)}>
          <form id="upload-form" onSubmit={(event) => void submitUpload(event)}>
            <div className="form-group">
              <label htmlFor="upload-domains">Domains</label>
              <input
                id="upload-domains"
                name="domains"
                required
                placeholder="app.example.com, www.example.com"
              />
            </div>
            <div className="form-group">
              <label htmlFor="upload-chain">Certificate chain (PEM)</label>
              <textarea
                id="upload-chain"
                name="certificate"
                rows={7}
                required
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
            <div className="form-group">
              <label htmlFor="upload-key">Private key (PEM)</label>
              <textarea
                id="upload-key"
                name="privateKey"
                rows={7}
                required
                placeholder="-----BEGIN PRIVATE KEY-----"
              />
              <span className="form-hint">
                The key is stored in the PM data directory and never returned by the API.
              </span>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-ghost" data-close onClick={() => setDialog(null)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" id="save-certificate" disabled={saving}>
                Upload
              </button>
            </div>
          </form>
        </Modal>
      ) : null}
    </main>
  );
}

function IntentTable({ items }: { items: CertificateItem[] }): JSX.Element {
  return (
    <table>
      <thead>
        <tr>
          <th>Domains</th>
          <th>Issuer</th>
          <th>Challenge</th>
          <th>Status</th>
          <th>Expires</th>
          <th>Revision</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, index) => (
          <tr key={item.policyId ?? item.id ?? index}>
            <td>
              {item.domains.map((domain) => (
                <span key={domain} className="domain">
                  {domain}
                </span>
              ))}
            </td>
            <td>{item.issuer}</td>
            <td>{item.challenge}</td>
            <td>
              <StatusBadge status={item.status} />
              {item.renewalError ? <div className="form-hint">{item.renewalError}</div> : null}
            </td>
            <td>{formatUnix(item.expiresAtUnix)}</td>
            <td>{item.revision}</td>
            <td className="actions"></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ManualTable({
  items,
  onDelete,
}: {
  items: CertificateItem[];
  onDelete: (id: number) => void;
}): JSX.Element {
  return (
    <table>
      <thead>
        <tr>
          <th>Domains</th>
          <th>Key</th>
          <th>Status</th>
          <th>Expires</th>
          <th>Fingerprint</th>
          <th>Revision</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, index) => (
          <tr key={item.id ?? index}>
            <td>
              {item.domains.map((domain) => (
                <span key={domain} className="domain">
                  {domain}
                </span>
              ))}
            </td>
            <td>{item.keyType}</td>
            <td>
              <StatusBadge status={item.status} />
            </td>
            <td>{formatUnixDate(item.expiresAtUnix)}</td>
            <td>
              <span className="chip" title={item.fingerprintSha256}>
                {(item.fingerprintSha256 ?? '').slice(0, 16)}…
              </span>
            </td>
            <td>{item.revision}</td>
            <td className="actions">
              <button
                type="button"
                className="btn btn-danger btn-sm"
                data-delete-cert={item.id}
                onClick={() => {
                  if (item.id !== undefined) onDelete(item.id);
                }}
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function errorMessage(failure: unknown): string {
  if (failure instanceof ApiError && failure.location) return `${failure.message} (${failure.location})`;
  return failure instanceof Error ? failure.message : 'Request failed';
}
