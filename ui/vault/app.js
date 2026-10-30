// Browser wiring: routing, polling and event handling. All markup comes from
// render.js. The bearer token lives in `api` (a closure) and nowhere else.

import { createApi } from './api.js';
import { createMockApi } from './mock.js';
import * as R from './render.js';

const $ = (id) => document.getElementById(id);
const view = $('view');
const POLL_MS = 3000;

let api = null;
let timer = null;
let tick = null;
let gen = 0; // bumped on every route change so late responses are dropped
let data = { vaults: [], proposals: [], events: [], proposal: null };
let ctx = { panel: null, ack: false, reason: '', busy: false, error: null, plan: null };
let nf = { form: { vault_id: '', recipient: '', amount: '', memo: '' }, errors: {}, preview: null, stale: false, error: null, importPlan: '', importError: null, busy: false };
let connectError = null;
let lastHtml = '';

function say(msg) { $('live').textContent = msg; }

function setTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
}
try { setTheme(localStorage.getItem('vault-ui-theme')); } catch { /* storage unavailable */ }
$('theme').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme === 'dark'
    || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
  const next = dark ? 'light' : 'dark';
  setTheme(next);
  try { localStorage.setItem('vault-ui-theme', next); } catch { /* ignore */ }
});

function route() {
  const [path, query = ''] = location.hash.replace(/^#/, '').split('?');
  const parts = path.split('/').filter(Boolean);
  return { name: parts[0] ?? 'vaults', id: parts[1] ? decodeURIComponent(parts[1]) : null, query: new URLSearchParams(query) };
}

function draw(html, { focusTitle = false } = {}) {
  if (html === lastHtml && !focusTitle) return;
  const a = document.activeElement;
  const keep = view.contains(a) && a.id ? { id: a.id, s: a.selectionStart, e: a.selectionEnd } : null;
  view.innerHTML = html;
  lastHtml = html;
  if (focusTitle) { $('page-title')?.focus(); say($('page-title')?.textContent ?? ''); }
  else if (keep) {
    const el = $(keep.id);
    if (el) { el.focus(); try { if (keep.s != null) el.setSelectionRange(keep.s, keep.e); } catch { /* not a text input */ } }
  }
}

function stopPolling() { clearInterval(timer); clearInterval(tick); timer = tick = null; }
function poll(fn) { stopPolling(); timer = setInterval(fn, POLL_MS); tick = setInterval(paint, 30000); }

async function guard(fn, setErr) {
  try { return await fn(); } catch (e) {
    if (e.code === 'unauthorized' || e.status === 401) { disconnect('The token was refused. Enter it again.'); return null; }
    setErr(e); return undefined;
  }
}

// ----- screens

function paint() {
  const r = route();
  const now = Date.now();
  if (!api) { draw(R.renderConnect({ error: connectError })); return; }
  if (r.name === 'vaults') draw(R.renderVaults(data.vaults));
  else if (r.name === 'proposals' && r.id) draw(data.proposal ? R.renderDetail(data.proposal, { ...ctx, now }) : R.renderError(ctx.error) || '<p>Loading…</p>');
  else if (r.name === 'proposals') draw(R.renderProposals(data.proposals, { now, vaultId: r.query.get('vault'), vaults: data.vaults }) + (data.error ? R.renderError(data.error) : ''));
  else if (r.name === 'new') draw(R.renderNew({ vaults: data.vaults, form: nf.form, errors: nf.errors, preview: nf.preview, previewStale: nf.stale, error: nf.error, importForm: { plan: nf.importPlan }, importError: nf.importError, busy: nf.busy }));
  else if (r.name === 'activity') draw(R.renderEvents(data.events, { error: data.error, now }));
  else draw('<h1 id="page-title" tabindex="-1">Not found</h1><p><a href="#/vaults">Go to vaults</a></p>');
}

async function load(first) {
  const r = route();
  const my = gen;
  data.error = null;
  const fail = (e) => { if (my === gen) { data.error = e; ctx.error = ctx.error ?? e; } };
  if (r.name === 'vaults' || r.name === 'new' || r.name === 'proposals') {
    const v = await guard(() => api.vaults(), fail);
    if (v && my === gen) {
      data.vaults = v;
      if (!nf.form.vault_id) nf.form.vault_id = r.query.get('vault') ?? v[0]?.id ?? '';
    }
  }
  if (r.name === 'proposals' && !r.id) {
    const p = await guard(() => api.proposals(), fail);
    if (p && my === gen) data.proposals = p;
  } else if (r.name === 'proposals' && r.id) {
    const p = await guard(() => api.proposal(r.id), (e) => { if (my === gen) { ctx.error = e; } });
    if (p && my === gen) { data.proposal = p; if (!ctx.busy) ctx.error = null; }
  } else if (r.name === 'activity') {
    const e = await guard(() => api.events(0), fail);
    if (e && my === gen) data.events = e;
  }
  if (my !== gen) return;
  if (api?.mode === 'mock') api.autoStep?.();
  paint();
  if (first) { draw(lastHtml.length ? lastHtml : '', { focusTitle: true }); }
}

async function navigate() {
  gen += 1;
  stopPolling();
  ctx = { panel: null, ack: false, reason: '', busy: false, error: null, plan: null };
  data.proposal = null; data.error = null;
  lastHtml = '';
  document.querySelectorAll('[data-nav]').forEach((a) => {
    if (a.dataset.nav === route().name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  if (api && route().name === 'new') { nf.preview = null; nf.stale = false; nf.error = null; nf.errors = {}; }
  if (!api) { paint(); draw(lastHtml, { focusTitle: true }); return; }
  view.innerHTML = '<p>Loading…</p>';
  await load(false);
  lastHtml = '';
  paint();
  $('page-title')?.focus();
  say($('page-title')?.textContent ?? '');
  const r = route();
  if (r.name === 'proposals' || r.name === 'activity') poll(() => { if (!ctx.busy) load(false); });
}

function connected(a) {
  api = a;
  connectError = null;
  $('nav').hidden = false;
  $('disconnect').hidden = false;
  $('mock-banner').hidden = a.mode !== 'mock';
  if (!location.hash || location.hash === '#/connect') location.hash = '#/vaults';
  navigate();
}

function disconnect(msg) {
  api = null; // drops the token
  stopPolling();
  gen += 1;
  data = { vaults: [], proposals: [], events: [], proposal: null };
  nf = { form: { vault_id: '', recipient: '', amount: '', memo: '' }, errors: {}, preview: null, stale: false, error: null, importPlan: '', importError: null, busy: false };
  connectError = msg ? { code: 'unauthorized', message: msg, action: 'Paste the token from the service’s token file.' } : null;
  $('nav').hidden = true; $('disconnect').hidden = true; $('mock-banner').hidden = true;
  lastHtml = '';
  paint(); draw(lastHtml, { focusTitle: true });
}

// ----- actions

async function doApprove() {
  const p = data.proposal;
  if (!p || R.approvalBlocker(p) || !ctx.ack || ctx.busy) return;
  ctx.busy = true; ctx.error = null; paint();
  const res = await guard(() => api.approve(p.id, p.message_sha256), (e) => { ctx.error = e; });
  ctx.busy = false;
  if (res) { data.proposal = res; ctx.panel = null; ctx.ack = false; say('Approval accepted. Waiting for signing.'); }
  paint();
  if (res) $('page-title')?.focus();
}

async function doReject() {
  const p = data.proposal;
  if (!p || R.rejectBlocker(p) || ctx.busy) return;
  ctx.busy = true; ctx.error = null; paint();
  const res = await guard(() => api.reject(p.id, ctx.reason.trim()), (e) => { ctx.error = e; });
  ctx.busy = false;
  if (res) { data.proposal = res; ctx.panel = null; say('Proposal rejected on this node.'); }
  paint();
  if (res) $('page-title')?.focus();
}

async function doPreview() {
  nf.errors = R.validateNew(nf.form);
  nf.error = null; nf.preview = null;
  if (Object.keys(nf.errors).length) { paint(); $(`f-${Object.keys(nf.errors)[0].replace('vault_id', 'vault')}`)?.focus(); return; }
  nf.busy = true; paint();
  const f = nf.form;
  const res = await guard(() => api.preview({ vault_id: f.vault_id, recipient: f.recipient.trim(), amount: f.amount.trim(), ...(f.memo ? { memo: f.memo } : {}) }), (e) => { nf.error = e; });
  nf.busy = false;
  if (res) { nf.preview = res; nf.stale = false; }
  paint();
  if (res) $('pv-h')?.scrollIntoView?.({ block: 'nearest' });
}

async function doSubmit() {
  if (!nf.preview || nf.stale || nf.busy) return;
  nf.busy = true; nf.error = null; paint();
  const f = nf.form;
  const res = await guard(() => api.create({ vault_id: f.vault_id, recipient: f.recipient.trim(), amount: f.amount.trim(), ...(f.memo ? { memo: f.memo } : {}) }), (e) => { nf.error = e; });
  nf.busy = false;
  if (res) {
    nf.form = { vault_id: f.vault_id, recipient: '', amount: '', memo: '' }; nf.preview = null;
    location.hash = `#/proposals/${encodeURIComponent(res.id)}`;
  } else paint();
}

async function doImport() {
  let plan;
  try { plan = JSON.parse(nf.importPlan); } catch {
    nf.importError = { code: 'bad_request', message: 'The pasted text is not valid JSON.', action: 'Paste the plan exactly as the other operator’s service returned it.' };
    paint(); return;
  }
  nf.busy = true; nf.importError = null; paint();
  const res = await guard(() => api.importPlan({ vault_id: nf.form.vault_id, plan }), (e) => { nf.importError = e; });
  nf.busy = false;
  if (res) { nf.importPlan = ''; location.hash = `#/proposals/${encodeURIComponent(res.id)}`; } else paint();
}

async function doRefresh() {
  const p = data.proposal;
  if (!p || ctx.busy) return;
  ctx.busy = true; ctx.error = null; paint();
  const res = await guard(() => api.refresh(p.id), (e) => { ctx.error = e; });
  ctx.busy = false;
  if (res) data.proposal = res;
  paint();
}

// ----- events

view.addEventListener('click', async (ev) => {
  const t = ev.target.closest('[data-action]');
  if (!t || t.disabled) return;
  switch (t.dataset.action) {
    case 'use-mock': connected(createMockApi()); break;
    case 'open-approve': ctx.panel = 'approve'; ctx.ack = false; paint(); $('ack')?.focus(); break;
    case 'open-reject': ctx.panel = 'reject'; paint(); $('reason')?.focus(); break;
    case 'close-panel': ctx.panel = null; ctx.ack = false; paint(); break;
    case 'refresh': await doRefresh(); break;
    case 'submit-proposal': await doSubmit(); break;
    case 'show-plan': {
      const p = data.proposal;
      const plan = await guard(() => api.plan(p.id), (e) => { ctx.error = e; });
      if (plan) ctx.plan = JSON.stringify(plan, null, 2);
      paint(); break;
    }
    default: break;
  }
});

view.addEventListener('input', (ev) => {
  const k = ev.target.dataset?.input;
  if (!k) return;
  const v = ev.target.type === 'checkbox' ? ev.target.checked : ev.target.value;
  if (k === 'ack') { ctx.ack = v; paint(); }
  else if (k === 'reason') ctx.reason = v;
  else if (k === 'import_plan') nf.importPlan = v;
  else if (k in nf.form) {
    nf.form[k] = v;
    if (nf.preview) { nf.stale = true; paint(); }
  }
});

view.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = ev.target.dataset.form;
  if (f === 'connect') {
    const input = $('token');
    const a = createApi({ base: '', token: input.value });
    input.value = '';
    const v = await guard(() => a.vaults(), (e) => { connectError = e; });
    if (v) connected(a); else if (v === undefined) paint();
  } else if (f === 'approve') await doApprove();
  else if (f === 'reject') await doReject();
  else if (f === 'new') await doPreview();
  else if (f === 'import') await doImport();
});

$('disconnect').addEventListener('click', () => disconnect());
window.addEventListener('hashchange', navigate);

if (new URLSearchParams(location.search).has('mock')) connected(createMockApi());
else { paint(); }
