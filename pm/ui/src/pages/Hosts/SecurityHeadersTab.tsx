// Security Headers tab for the Hosts page.
//
// Two panels share one editor: the global configuration that every host inherits, and the selected
// host's override. The API returns the *effective* per-host config (inherited when the host stores
// none), so the host detail's `securityHeaders` field is what distinguishes "inherited" from
// "explicit override"; inherited values are rendered dimmed and only become an override once the
// operator edits them.
//
// Saving validates locally with the same rules as the server and then validates through the API, so
// an invalid HSTS preload combination is reported inline before any request is made.

import { useEffect, useState } from 'react';
import {
  ApiError,
  hosts,
  securityHeaders,
  type HostDetail,
  type HostSummary,
  type SecurityHeadersConfig,
} from '../../api';
import { ErrorBox, Loading, toast } from '../../ui';
import {
  SecurityHeadersEditor,
  defaultSecurityHeaders,
  validateSecurityHeaders,
} from '../../components/SecurityHeaders';

interface HostOption {
  id: number;
  label: string;
  inherited: boolean;
}

export function SecurityHeadersTab(): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(null);

  const [globalDraft, setGlobalDraft] = useState<SecurityHeadersConfig>(defaultSecurityHeaders());
  const [globalSaving, setGlobalSaving] = useState(false);
  const [globalError, setGlobalError] = useState<unknown>(null);
  const [globalSaved, setGlobalSaved] = useState(false);

  const [hostOptions, setHostOptions] = useState<HostOption[]>([]);
  const [selectedHost, setSelectedHost] = useState<number | null>(null);
  const [hostValue, setHostValue] = useState<SecurityHeadersConfig | null>(null);
  const [hostDraft, setHostDraft] = useState<SecurityHeadersConfig>(defaultSecurityHeaders());
  const [hostEtag, setHostEtag] = useState<string | null>(null);
  const [hostInherited, setHostInherited] = useState(false);
  const [hostSaving, setHostSaving] = useState(false);
  const [hostError, setHostError] = useState<unknown>(null);
  const [hostSaved, setHostSaved] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      try {
        const [global, hostPage] = await Promise.all([
          securityHeaders.getGlobal(),
          hosts.list({ limit: 100 }),
        ]);
        if (cancelled) return;
        setGlobalDraft(global.data);
        const options = hostPage.data.items.map((host: HostSummary) => ({
          id: host.id,
          label: `${host.domains.join(', ') || `host ${host.id}`} (#${host.id})`,
          inherited: false,
        }));
        setHostOptions(options);
        setSelectedHost((current) => current ?? options[0]?.id ?? null);
      } catch (error) {
        if (!cancelled) setLoadError(error);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Load the selected host: the detail tells us whether the host stores an override, and the
  // per-host endpoint returns the effective (inherited) config.
  useEffect(() => {
    if (selectedHost === null) return;
    let cancelled = false;
    (async () => {
      setHostError(null);
      setHostSaved(false);
      try {
        const [detail, config] = await Promise.all([
          hosts.get(selectedHost),
          securityHeaders.getHost(selectedHost),
        ]);
        if (cancelled) return;
        const detailBody = detail.data as HostDetail;
        const inherited = !detailBody.securityHeaders;
        setHostInherited(inherited);
        setHostEtag(detail.etag);
        setHostValue(config.data);
        setHostDraft(config.data);
      } catch (error) {
        if (!cancelled) setHostError(error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedHost]);

  const saveGlobal = async (): Promise<void> => {
    const errors = validateSecurityHeaders(globalDraft);
    if (Object.keys(errors).length > 0) {
      setGlobalError(new Error(Object.values(errors)[0]));
      return;
    }
    setGlobalSaving(true);
    setGlobalError(null);
    setGlobalSaved(false);
    try {
      const { data } = await securityHeaders.putGlobal(globalDraft);
      setGlobalDraft(data);
      setGlobalSaved(true);
      toast('Global security headers saved');
      // Inherited host values are now stale; reload the selected host.
      if (selectedHost !== null) {
        const config = await securityHeaders.getHost(selectedHost);
        setHostValue(config.data);
        if (hostInherited) setHostDraft(config.data);
      }
    } catch (error) {
      setGlobalError(error);
    } finally {
      setGlobalSaving(false);
    }
  };

  const saveHost = async (): Promise<void> => {
    if (selectedHost === null) return;
    const errors = validateSecurityHeaders(hostDraft);
    if (Object.keys(errors).length > 0) {
      setHostError(new Error(Object.values(errors)[0]));
      return;
    }
    setHostSaving(true);
    setHostError(null);
    setHostSaved(false);
    try {
      const { data } = await securityHeaders.putHost(selectedHost, hostDraft, hostEtag);
      setHostValue(data);
      setHostDraft(data);
      setHostInherited(false);
      setHostSaved(true);
      toast('Host security headers saved');
      // The host revision advanced, so refresh the If-Match token.
      const detail = await hosts.get(selectedHost);
      setHostEtag(detail.etag);
    } catch (error) {
      setHostError(error);
    } finally {
      setHostSaving(false);
    }
  };

  if (loading) return <Loading text="Loading security headers…" />;
  if (loadError !== null) return <ErrorBox error={loadError} />;

  return (
    <div id="security-headers-tab">
      <div className="card" id="global-security-headers">
        <div className="card-header">
          <h2>Global security headers</h2>
        </div>
        <div className="card-body">
          <p className="page-subtitle">
            Every host inherits these values unless it stores its own override. Unset fields emit no
            header; the proxy-manager API applies the secure baseline when no configuration has been
            saved yet.
          </p>
          <SecurityHeadersEditor
            idPrefix="global"
            value={globalDraft}
            onChange={(next) => {
              setGlobalDraft(next);
              setGlobalSaved(false);
            }}
          />
          {globalError !== null ? <ErrorBox error={globalError} /> : null}
          {globalSaved ? (
            <div className="success-message" id="global-security-headers-saved">
              Global security headers saved.
            </div>
          ) : null}
          <button
            type="button"
            className="btn btn-primary"
            id="save-global-security-headers"
            disabled={globalSaving}
            onClick={() => void saveGlobal()}
          >
            {globalSaving ? 'Saving…' : 'Save global headers'}
          </button>
        </div>
      </div>

      <div className="card" id="host-security-headers">
        <div className="card-header">
          <h2>Per-host override</h2>
        </div>
        <div className="card-body">
          <div className="form-group">
            <label htmlFor="security-headers-host">Host</label>
            <select
              id="security-headers-host"
              value={selectedHost ?? ''}
              onChange={(event) => setSelectedHost(Number(event.target.value))}
            >
              {hostOptions.length === 0 ? <option value="">No hosts yet</option> : null}
              {hostOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          {selectedHost === null ? (
            <p className="form-hint">Create a host first; security headers are configured per host.</p>
          ) : (
            <>
              {hostInherited ? (
                <div className="inherited-note" id="host-security-headers-inherited">
                  This host inherits the global configuration. Edit any field to store an override.
                </div>
              ) : (
                <div className="inherited-note" id="host-security-headers-override">
                  This host stores its own override, which wins over the global configuration.
                </div>
              )}
              {hostValue === null ? (
                <Loading text="Loading host headers…" />
              ) : (
                <SecurityHeadersEditor
                  idPrefix="host"
                  value={hostDraft}
                  inherited={hostInherited}
                  onChange={(next) => {
                    setHostDraft(next);
                    setHostInherited(false);
                    setHostSaved(false);
                  }}
                />
              )}
              {hostError !== null ? <ErrorBox error={hostError} /> : null}
              {hostSaved ? (
                <div className="success-message" id="host-security-headers-saved">
                  Host security headers saved.
                </div>
              ) : null}
              <button
                type="button"
                className="btn btn-primary"
                id="save-host-security-headers"
                disabled={hostSaving || hostValue === null}
                onClick={() => void saveHost()}
              >
                {hostSaving ? 'Saving…' : 'Save host headers'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/** Small helper used by the tab and tests: the inherited-vs-explicit marker for a host detail. */
export function hostInheritsGlobal(detail: HostDetail): boolean {
  return !detail.securityHeaders;
}

/** Re-exported so callers can tell a validation error from a transport error. */
export function isValidationError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 422;
}
