// Run: node --test ui/vault/test   (no dependencies, no DOM)
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import * as R from '../render.js';
import { createMockApi } from '../mock.js';
import { createApi, ApiError } from '../api.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const NOW = Date.now();
const mockApi = () => createMockApi({ now: () => NOW });
const ctx = (o = {}) => ({ now: NOW, panel: null, ack: false, reason: '', busy: false, error: null, plan: null, ...o });
const byState = async (state, api = createMockApi({ now: () => NOW })) => (await api.proposals()).find((p) => p.state === state && p.integrity.status === 'verified');

// Required fields copied from crates/mpc-vault/openapi.yaml (Proposal, Vault, Summary, Event).
const REQ = {
  proposal: ['id', 'vault_id', 'state', 'origin', 'created_at', 'updated_at', 'expires_at', 'operation_id', 'message_sha256', 'message_len', 'signers', 'confirmations', 'summary', 'integrity', 'timeline'],
  vault: ['id', 'name', 'chain', 'address', 'group_public_key', 'members', 'threshold', 'group_status', 'created_at'],
  summary: ['network', 'from', 'recipient', 'amount', 'fee'],
  event: ['seq', 'at', 'kind', 'message'],
};

test('mock fixtures carry every field the contract requires', async () => {
  const api = createMockApi({ now: () => NOW });
  for (const p of await api.proposals()) {
    for (const k of REQ.proposal) assert.ok(k in p, `proposal.${k}`);
    for (const k of REQ.summary) assert.ok(k in p.summary, `summary.${k}`);
    assert.match(p.message_sha256, /^[0-9a-f]{64}$/);
  }
  for (const v of await api.vaults()) for (const k of REQ.vault) assert.ok(k in v, `vault.${k}`);
  for (const e of await api.events()) for (const k of REQ.event) assert.ok(k in e, `event.${k}`);
  assert.ok((await api.proposals()).every((p) => /EXAMPLE/.test(JSON.stringify(p))), 'example data is marked');
});

test('proposal list: every state gets its own group with row details', async () => {
  const list = await createMockApi({ now: () => NOW }).proposals();
  const html = R.renderProposals(list, { now: NOW, vaults: await createMockApi({ now: () => NOW }).vaults() });
  for (const s of R.STATES) {
    assert.ok(list.some((p) => p.state === s), `fixture for ${s}`);
    assert.match(html, new RegExp(`id="g-${s}"`), `group ${s}`);
  }
  const order = R.STATES.map((s) => html.indexOf(`id="g-${s}"`));
  assert.deepEqual(order, [...order].sort((a, b) => a - b), 'groups in lifecycle order');
  assert.match(html, /1 of 2 confirmations/);
  assert.match(html, /0 of 2 confirmations/);
  assert.match(html, /2 of 2 confirmations/);
  assert.match(html, /expires in 22 h/);
  assert.match(html, /created 2 h ago/);
  assert.match(html, /fee 0\.000005 SOL/);
  assert.match(html, /bytes\/summary mismatch/);
});

test('proposal detail renders for every state', async () => {
  const api = createMockApi({ now: () => NOW });
  for (const p of await api.proposals()) {
    const html = R.renderDetail(p, ctx());
    assert.ok(html.includes(p.summary.recipient), `${p.state} shows full recipient`);
    assert.ok(html.includes(p.message_sha256), `${p.state} shows hash`);
    assert.match(html, new RegExp(`badge s-${p.state}`));
    assert.match(html, /Signers and timeline/);
    for (const s of p.signers) assert.ok(html.includes(s.agent));
    if (!R.STATES.slice(0, 5).includes(p.state)) assert.match(html, /Ended as/, `${p.state} rail end`);
  }
});

test('approve is offered only where the contract allows it', async () => {
  const api = createMockApi({ now: () => NOW });
  const open = (h) => !/data-action="open-approve"[^>]*disabled/.test(h);
  for (const p of await api.proposals()) {
    const h = R.renderDetail(p, ctx());
    const expectOpen = p.integrity.status === 'verified' && ['proposed', 'approved'].includes(p.state) && p.signers[0].approved !== true && !p.local_task;
    assert.equal(open(h), expectOpen, `${p.id} (${p.state}) approve enabled`);
    assert.equal(R.approvalBlocker(p) === null, expectOpen);
  }
});

test('approval needs the on-page confirmation step', async () => {
  const p = await byState('proposed');
  const without = R.renderDetail(p, ctx({ panel: null }));
  assert.doesNotMatch(without, /data-form="approve"/);
  const panel = R.renderDetail(p, ctx({ panel: 'approve', ack: false }));
  assert.match(panel, /data-form="approve"/);
  assert.match(panel, /id="confirm-approve" disabled/);
  assert.ok(panel.includes(p.summary.recipient) && panel.includes(p.message_sha256));
  assert.doesNotMatch(R.renderDetail(p, ctx({ panel: 'approve', ack: true })), /id="confirm-approve" disabled/);
});

test('mismatch path: banner, disabled approval, no panel, flagged list row', async () => {
  const api = createMockApi({ now: () => NOW });
  const bad = (await api.proposals()).find((p) => p.integrity.status === 'mismatch');
  const html = R.renderDetail(bad, ctx({ panel: 'approve', ack: true }));
  assert.match(html, /role="alert"[^]*Bytes and summary mismatch\. Do not approve\./);
  assert.ok(html.includes(bad.integrity.detail));
  assert.match(html, /Unverified summary\. Do not trust\./);
  assert.match(html, /data-action="open-approve"[^>]*disabled/);
  assert.doesNotMatch(html, /data-form="approve"/, 'panel is not rendered even if requested');
  assert.match(html, /What to do/);
  assert.match(R.renderProposals([bad], { now: NOW }), /bytes\/summary mismatch/);
  // The service refuses too; the UI is not the only guard.
  await assert.rejects(api.approve(bad.id, bad.message_sha256), (e) => e.code === 'bytes_summary_mismatch');
  // A verified proposal never shows the banner.
  assert.doesNotMatch(R.renderDetail(await byState('proposed'), ctx()), /Bytes and summary mismatch/);
});

test('reject is blocked once this node approved, and for terminal states', async () => {
  const api = createMockApi({ now: () => NOW });
  const signed = await byState('signed');
  assert.ok(R.rejectBlocker(signed));
  const proposed = await byState('proposed');
  assert.equal(R.rejectBlocker(proposed), null);
  assert.match(R.renderDetail(proposed, ctx({ panel: 'reject' })), /data-form="reject"[^]*this node only/);
  await assert.rejects(api.reject(signed.id), (e) => e.code === 'already_approved' || e.code === 'bad_state');
});

test('no retry controls for signing or broadcast', async () => {
  for (const p of await createMockApi({ now: () => NOW }).proposals()) {
    const h = R.renderDetail(p, ctx({ error: { code: 'node_failed', message: 'x', action: 'y' } }));
    const controls = [...h.matchAll(/<(?:button|a)\b[^>]*>([^<]*)</g)].map((m) => m[1]).join('|') + (h.match(/data-action="[^"]*"/g) ?? []).join('|');
    assert.doesNotMatch(controls, /retry|resend|try again|broadcast/i);
  }
});

test('uncertain broadcast and failure are explained', async () => {
  const api = createMockApi({ now: () => NOW });
  const unc = (await api.proposals()).find((p) => p.broadcast?.uncertain);
  assert.match(R.renderDetail(unc, ctx()), /Broadcast outcome unknown[^]*never by sending again/);
  const failed = await byState('failed');
  assert.match(R.renderDetail(failed, ctx()), /Failed at step “sign”[^]*What to do/);
});

test('errors show what failed and what to do', () => {
  const html = R.renderError(new ApiError({ code: 'busy', message: 'This node is busy.', action: 'Wait.', status: 409 }));
  assert.match(html, /role="alert"/);
  assert.match(html, /Failed: This node is busy\./);
  assert.match(html, /What to do:<\/strong> Wait\./);
  assert.match(R.renderError({ code: 'unreachable', message: 'm', action: 'a', uncertain: true }), /outcome is unknown/);
});

test('untrusted strings are escaped everywhere', async () => {
  const evil = '<img src=x onerror=alert(1)>"\'';
  const p = await byState('proposed');
  p.summary.memo = evil; p.summary.recipient = evil; p.timeline[0].event = evil; p.integrity = { status: 'mismatch', detail: evil };
  p.signers[1].agent = evil; p.failure = { step: evil, reason: evil, action: evil };
  const outs = [R.renderDetail(p, ctx()), R.renderProposals([p], { now: NOW }), R.renderEvents([{ seq: 1, at: evil, kind: evil, message: evil, proposal_id: evil }], { now: NOW }),
    R.renderVaults([{ id: evil, name: evil, chain: evil, address: evil, members: [{ agent: evil, local: true }], threshold: 2, group_status: 'descriptor_present', balance: null, balance_error: evil, created_at: evil, notes: [evil] }])];
  for (const h of outs) assert.doesNotMatch(h, /<img|onerror=alert\(1\)>/);
});

test('vaults, new proposal and activity screens', async () => {
  const api = createMockApi({ now: () => NOW });
  const v = R.renderVaults(await api.vaults());
  assert.match(v, /2 of 3/); assert.match(v, /Balance unavailable/); assert.match(v, /2\.5 SOL/); assert.match(v, /EXAMPLEvaultAddr/);
  assert.match(R.renderVaults([]), /No vault exists/);
  const vaults = await api.vaults();
  const form = { vault_id: vaults[0].id, recipient: 'r', amount: '5', memo: '' };
  const pv = await api.preview(form);
  const fresh = R.renderNew({ vaults, form, preview: pv, previewStale: false, importForm: { plan: '' } });
  assert.doesNotMatch(fresh, /data-action="submit-proposal" disabled/);
  assert.ok(fresh.includes(pv.message_sha256));
  assert.match(R.renderNew({ vaults, form, preview: pv, previewStale: true, importForm: { plan: '' } }), /data-action="submit-proposal" disabled/);
  assert.match(R.renderNew({ vaults, form, preview: null, importForm: { plan: '' } }), /data-action="submit-proposal" disabled/);
  assert.deepEqual(Object.keys(R.validateNew({ vault_id: '', recipient: ' ', amount: '1.5', memo: 'x'.repeat(141) })).sort(), ['amount', 'memo', 'recipient', 'vault_id']);
  assert.deepEqual(R.validateNew(form), {});
  const ev = R.renderEvents(await api.events(), { now: NOW });
  assert.match(ev, /proposal\.confirmed/);
});

test('mock runs a full approval to confirmed with the displayed hash', async () => {
  const api = createMockApi({ now: () => NOW });
  const p = await byState('proposed');
  await assert.rejects(api.approve(p.id, 'f'.repeat(64)), (e) => e.code === 'hash_mismatch');
  const r = await api.approve(p.id, p.message_sha256);
  assert.equal(r.local_task, 'approving');
  await assert.rejects(api.approve(p.id, p.message_sha256), (e) => e.code === 'busy');
  for (let i = 0; i < 4; i++) api.step(p.id);
  assert.equal((await api.proposal(p.id)).state, 'confirmed');
});

test('api client: bearer header, single attempt, uncertain writes, error bodies', async () => {
  const calls = [];
  const mk = (impl) => createApi({ token: 'secret-token', fetchImpl: async (u, o) => { calls.push([u, o]); return impl(u, o); } });
  const ok = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
  await mk(() => ok({ vaults: [] })).vaults();
  assert.equal(calls[0][1].headers.Authorization, 'Bearer secret-token');
  assert.equal(calls[0][0], '/vaults');
  calls.length = 0;
  await assert.rejects(mk(() => { throw new TypeError('network'); }).approve('p1', 'h'), (e) => e.code === 'unreachable' && e.uncertain === true && /Do not repeat/.test(e.action));
  assert.equal(calls.length, 1, 'a failed write is not retried');
  await assert.rejects(mk(() => { throw new TypeError('network'); }).vaults(), (e) => e.uncertain === false);
  await assert.rejects(mk(() => ok({ error: { code: 'expired', message: 'm', action: 'a' } }, 409)).approve('p', 'h'), (e) => e.code === 'expired' && e.status === 409 && e.action === 'a');
  await assert.rejects(mk(() => ({ ok: false, status: 502, json: async () => { throw new Error('x'); } })).refresh('p'), (e) => e.code === 'http_error');
  assert.deepEqual(JSON.parse(calls.at(-1)[1].body ?? 'null'), null);
});

test('static rules: no external requests, no dialogs, token never stored', () => {
  const files = readdirSync(dir).filter((f) => /\.(js|html|css)$/.test(f));
  assert.ok(files.length >= 6);
  for (const f of files) {
    const src = readFileSync(path.join(dir, f), 'utf8');
    assert.doesNotMatch(src.replace(/\/\/.*$/gm, ''), /https?:\/\/(?!127\.0\.0\.1|localhost)/, `${f}: external URL`);
    assert.doesNotMatch(src, /\b(confirm|alert|prompt)\s*\(/, `${f}: browser dialog`);
    assert.doesNotMatch(src, /\bstyle="|<script(?![^>]*src=)/, `${f}: inline style/script (CSP default-src 'self')`);
    assert.doesNotMatch(src, /@import|url\(\s*['"]?https?:/, `${f}: remote css`);
    assert.doesNotMatch(src, /(localStorage|sessionStorage|indexedDB|document\.cookie)[^;\n]*token/i, `${f}: token storage`);
  }
  const app = readFileSync(path.join(dir, 'app.js'), 'utf8');
  assert.deepEqual([...app.matchAll(/localStorage\.\w+\(([^)]*)\)/g)].map((m) => m[1]), ["'vault-ui-theme'", "'vault-ui-theme', next"]);
});
