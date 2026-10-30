// HTTP client for the vault service. The token is a closure variable only:
// never put in storage, a URL or a log. Writes are sent exactly once; nothing
// here retries.

export class ApiError extends Error {
  constructor({ code, message, action, status = 0, uncertain = false }) {
    super(message);
    this.code = code; this.action = action; this.status = status; this.uncertain = uncertain;
  }
}

const TIMEOUT_MS = 60000;

export function createApi({ base = '', token, fetchImpl = (...a) => fetch(...a) }) {
  async function call(method, path, body) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    const write = method !== 'GET';
    let res;
    try {
      res = await fetchImpl(base + path, {
        method, signal: ctl.signal, cache: 'no-store', redirect: 'error', credentials: 'omit',
        headers: { Authorization: `Bearer ${token}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new ApiError({
        code: 'unreachable', uncertain: write,
        message: 'The vault service did not answer.',
        action: write
          ? 'The request may or may not have been applied. Reload this page and check the proposal before doing anything else. Do not repeat the action.'
          : 'Check that mpc-vault is running on this machine and that this page was opened from it, then reload.',
      });
    } finally { clearTimeout(timer); }
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON body */ }
    if (!res.ok) {
      const e = data?.error;
      throw new ApiError({
        code: e?.code ?? 'http_error', status: res.status,
        message: e?.message ?? `The service answered HTTP ${res.status}.`,
        action: e?.action ?? 'Check the service log on the machine it runs on.',
        uncertain: write && res.status >= 500,
      });
    }
    return data;
  }
  const q = (o) => { const s = new URLSearchParams(Object.entries(o).filter(([, v]) => v != null)).toString(); return s ? `?${s}` : ''; };
  return {
    mode: 'live',
    vaults: () => call('GET', '/vaults').then((d) => d.vaults),
    proposals: (f = {}) => call('GET', `/proposals${q(f)}`).then((d) => d.proposals),
    proposal: (id) => call('GET', `/proposals/${encodeURIComponent(id)}`),
    plan: (id) => call('GET', `/proposals/${encodeURIComponent(id)}/plan`),
    preview: (b) => call('POST', '/proposals/preview', b),
    create: (b) => call('POST', '/proposals', b),
    importPlan: (b) => call('POST', '/proposals/import', b),
    approve: (id, message_sha256) => call('POST', `/proposals/${encodeURIComponent(id)}/approve`, { confirm: true, message_sha256 }),
    reject: (id, reason) => call('POST', `/proposals/${encodeURIComponent(id)}/reject`, reason ? { reason } : {}),
    refresh: (id) => call('POST', `/proposals/${encodeURIComponent(id)}/refresh`),
    events: (after = 0) => call('GET', `/events${q({ after, limit: 200 })}`).then((d) => d.events),
  };
}
