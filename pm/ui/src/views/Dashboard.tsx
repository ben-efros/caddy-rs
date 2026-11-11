// Dashboard: counts and preview tables for hosts, certificates and the apply history.

import { useEffect, useState } from 'react';
import {
  certificates,
  config,
  hosts,
  type CertificateItem,
  type ConfigRevision,
  type HostSummary,
  type Page,
} from '../api';
import {
  Empty,
  EnabledBadge,
  ErrorBox,
  Loading,
  StatusBadge,
  TlsBadge,
  formatUnix,
} from '../ui';

export function Dashboard(): JSX.Element {
  const [hostsPage, setHostsPage] = useState<Page<HostSummary> | null>(null);
  const [certsPage, setCertsPage] = useState<Page<CertificateItem> | null>(null);
  const [revisions, setRevisions] = useState<ConfigRevision[] | null>(null);
  const [hostsError, setHostsError] = useState<unknown>(null);
  const [certsError, setCertsError] = useState<unknown>(null);
  const [revisionsError, setRevisionsError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const load = async (): Promise<void> => {
      const [hostsResult, certsResult, revisionsResult] = await Promise.allSettled([
        hosts.list({ limit: 5 }),
        certificates.list({ limit: 5 }),
        config.revisions({ limit: 5 }),
      ]);
      if (!active) return;
      if (hostsResult.status === 'fulfilled') setHostsPage(hostsResult.value.data);
      else setHostsError(hostsResult.reason);
      if (certsResult.status === 'fulfilled') setCertsPage(certsResult.value.data);
      else setCertsError(certsResult.reason);
      if (revisionsResult.status === 'fulfilled') setRevisions(revisionsResult.value.data.items);
      else setRevisionsError(revisionsResult.reason);
      setLoading(false);
    };
    void load();
    return () => {
      active = false;
    };
  }, []);

  const latest = revisions && revisions.length > 0 ? revisions[0] : null;

  return (
    <main className="main-content">
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p className="page-subtitle">Live view of hosts, certificates and the applied configuration</p>
        </div>
      </div>
      <div className="stats">
        <div className="stat">
          <span className="stat-value" id="stat-hosts">
            {hostsError ? '—' : hostsPage ? String(hostsPage.total) : '—'}
          </span>
          <span className="stat-label">Hosts</span>
        </div>
        <div className="stat">
          <span className="stat-value" id="stat-enabled">
            {hostsError || !hostsPage ? '—' : String(hostsPage.items.filter((item) => item.enabled).length)}
          </span>
          <span className="stat-label">Enabled</span>
        </div>
        <div className="stat">
          <span className="stat-value" id="stat-certs">
            {certsError ? '—' : certsPage ? String(certsPage.total) : '—'}
          </span>
          <span className="stat-label">Certificates</span>
        </div>
        <div className="stat">
          <span className="stat-value" id="stat-revision">
            {revisionsError ? '—' : latest ? String(latest.revision) : '0'}
          </span>
          <span className="stat-label">Config revision</span>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Hosts</h2>
          <a className="btn btn-ghost btn-sm" href="/hosts" data-nav="/hosts">
            Manage
          </a>
        </div>
        <div className="table-container" id="hosts-table">
          {loading ? (
            <Loading />
          ) : hostsError ? (
            <ErrorBox error={hostsError} />
          ) : hostsPage && hostsPage.items.length ? (
            <HostsTable items={hostsPage.items} />
          ) : (
            <Empty text="No hosts yet. Create one from the Hosts page." />
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Certificates</h2>
          <a className="btn btn-ghost btn-sm" href="/certificates" data-nav="/certificates">
            Manage
          </a>
        </div>
        <div className="table-container" id="certs-table">
          {loading ? (
            <Loading />
          ) : certsError ? (
            <ErrorBox error={certsError} />
          ) : certsPage && certsPage.items.length ? (
            <CertsTable items={certsPage.items} />
          ) : (
            <Empty text="No certificates or intents yet." />
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Recent applies</h2>
          <a className="btn btn-ghost btn-sm" href="/config" data-nav="/config">
            Configuration
          </a>
        </div>
        <div className="table-container" id="revisions-table">
          {loading ? (
            <Loading />
          ) : revisionsError ? (
            <ErrorBox error={revisionsError} />
          ) : revisions && revisions.length ? (
            <RevisionsTable items={revisions} />
          ) : (
            <Empty text="Nothing applied yet." />
          )}
        </div>
      </div>
    </main>
  );
}

function HostsTable({ items }: { items: HostSummary[] }): JSX.Element {
  return (
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Domains</th>
          <th>Kind</th>
          <th>TLS</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        {items.map((host) => (
          <tr key={host.id}>
            <td>{host.id}</td>
            <td>
              {host.domains.map((domain) => (
                <span className="domain" key={domain}>
                  {domain}
                </span>
              ))}
            </td>
            <td>{host.kind}</td>
            <td>
              <TlsBadge mode={host.tlsMode} />
            </td>
            <td>
              <EnabledBadge enabled={host.enabled} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CertsTable({ items }: { items: CertificateItem[] }): JSX.Element {
  return (
    <table>
      <thead>
        <tr>
          <th>Domains</th>
          <th>Origin</th>
          <th>Status</th>
          <th>Expires</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, index) => (
          <tr key={item.policyId ?? item.id ?? index}>
            <td>
              {(item.domains || []).map((domain) => (
                <span className="domain" key={domain}>
                  {domain}
                </span>
              ))}
            </td>
            <td>{item.origin}</td>
            <td>
              <StatusBadge status={item.status} />
            </td>
            <td>{formatUnix(item.expiresAtUnix)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RevisionsTable({ items }: { items: ConfigRevision[] }): JSX.Element {
  return (
    <table>
      <thead>
        <tr>
          <th>Revision</th>
          <th>Status</th>
          <th>Changed</th>
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
            <td>{formatUnix(revision.recordedAtUnix)}</td>
            <td>{revision.error ? revision.error : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
