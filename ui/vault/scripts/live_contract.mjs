// Optional: drives the real service (use `mpc-vault demo`, mock chain) with the UI's own
// client and renderer. Run: VAULT_URL=http://127.0.0.1:8787 VAULT_TOKEN_FILE=/abs/token node ui/vault/scripts/live_contract.mjs
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createApi } from '../api.js';
import * as R from '../render.js';

const api = createApi({ base: process.env.VAULT_URL, token: readFileSync(process.env.VAULT_TOKEN_FILE, 'utf8').trim() });
const need = (o, keys, what) => { for (const k of keys) assert.ok(k in o, `${what}.${k} missing from the service response`); };
const vaults = await api.vaults();
assert.ok(vaults.length, 'service has a vault');
need(vaults[0], ['id', 'name', 'chain', 'address', 'group_public_key', 'members', 'threshold', 'group_status', 'created_at'], 'vault');
R.renderVaults(vaults);
const v = vaults[0];
const body = { vault_id: v.id, recipient: process.env.VAULT_RECIPIENT ?? v.address, amount: '1000', memo: `ui live check ${Date.now()}` };
let pv;
try { pv = await api.preview(body); } catch (e) { console.log('preview refused:', e.code, e.message); throw e; }
need(pv, ['summary', 'message_sha256', 'message_len'], 'preview');
const p = await api.create(body);
need(p, ['id', 'state', 'integrity', 'confirmations', 'summary', 'signers', 'timeline', 'message_sha256'], 'proposal');
assert.equal(p.message_sha256, pv.message_sha256, 'preview hash equals created hash');
const now = Date.now();
R.renderDetail(p, { now, panel: 'approve', ack: true });
console.log('created', p.id, p.state, R.approvalBlocker(p) ?? 'approve allowed');
await assert.rejects(api.approve(p.id, 'f'.repeat(64)), (e) => e.code === 'hash_mismatch');
const a = await api.approve(p.id, p.message_sha256);
console.log('approve ->', a.state, a.local_task);
let cur = a;
for (let i = 0; i < 40 && !['confirmed', 'failed', 'rejected', 'expired'].includes(cur.state); i++) {
  await new Promise((r) => setTimeout(r, 1000));
  cur = await api.proposal(p.id);
  R.renderDetail(cur, { now: Date.now(), panel: null });
  process.stdout.write(`${cur.state}${cur.local_task ? '/' + cur.local_task : ''} `);
}
console.log('\nfinal', cur.state, JSON.stringify(cur.confirmations));
const events = await api.events(0);
need(events[0], ['seq', 'at', 'kind', 'message'], 'event');
console.log('events', events.length);
const plan = await api.plan(p.id);
console.log('plan keys', Object.keys(plan).slice(0, 6).join(','));
console.log('proposals', (await api.proposals()).length, (await api.plan(p.id)) ? 'plan ok' : '');
