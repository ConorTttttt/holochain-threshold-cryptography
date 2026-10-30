// In-page mock of the vault API, shaped like crates/mpc-vault/openapi.yaml.
// EVERYTHING here is example data. Addresses and hashes are fake on purpose.
// Same method names and error bodies as api.js. `step(id)` advances a proposal
// one stage so the UI (and tests) can watch a full run without timers.

import { ApiError } from './api.js';

const LOCAL = 'uhCAkEXAMPLE-this-node-AAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PEER_B = 'uhCAkEXAMPLE-peer-b-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const PEER_C = 'uhCAkEXAMPLE-peer-c-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';
const VAULT_ADDR = 'EXAMPLEvaultAddr1111111111111111111111111111';
const RECIPIENT = 'EXAMPLErecipient22222222222222222222222222';
const hex = (c) => c.repeat(64);
const hexDigit = (i) => '0123456789abcdef'[i % 16];

const sol = (raw) => ({ raw: String(raw), decimals: 9, symbol: 'SOL', display: `${(Number(raw) / 1e9).toFixed(Number(raw) % 1e6 ? 9 : 3).replace(/\.?0+$/, '')} SOL` });

export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function err(status, code, message, action) {
  return new ApiError({ code, message, action, status });
}

export function createMockApi({ now = () => Date.now() } = {}) {
  const iso = (offsetMs = 0) => new Date(now() + offsetMs).toISOString();
  const H = 3600000;
  const members = [
    { index: 0, agent: LOCAL, local: true },
    { index: 1, agent: PEER_B, local: false },
    { index: 2, agent: PEER_C, local: false },
  ];
  const vaults = [
    {
      id: 'vault-example-1', name: 'EXAMPLE Treasury (devnet)', chain: 'solana-devnet', address: VAULT_ADDR,
      group_public_key: hex('a'), members, threshold: 2, group_status: 'descriptor_present',
      balance: sol(2500000000), balance_error: null, created_at: iso(-72 * H),
      notes: ['EXAMPLE DATA. Spending limits and allowlists are not implemented.', 'Owners and threshold cannot change without a new DKG (a new vault).'],
    },
    {
      id: 'vault-example-2', name: 'EXAMPLE Offline chain vault', chain: 'mock', address: 'ee'.repeat(32),
      group_public_key: hex('e'), members, threshold: 2, group_status: 'descriptor_present',
      balance: null, balance_error: 'EXAMPLE: the chain could not be reached. Check the RPC URL in the service config.',
      created_at: iso(-24 * H), notes: ['EXAMPLE DATA. Mock chain.'],
    },
  ];

  const timelineFor = (state, count) => {
    const t = [{ at: iso(-2 * H), node: null, event: 'Proposal created; signing plan written' }];
    if (count >= 1) t.push({ at: iso(-90 * 60000), node: LOCAL, event: 'Approved with this node' });
    if (count >= 2) t.push({ at: iso(-80 * 60000), node: PEER_B, event: 'Approved (observed)' });
    if (['signed', 'broadcast', 'confirmed'].includes(state)) t.push({ at: iso(-75 * 60000), node: null, event: 'Group signature verified under the vault key' });
    if (['broadcast', 'confirmed'].includes(state)) t.push({ at: iso(-70 * 60000), node: null, event: 'Broadcast once' });
    if (state === 'confirmed') t.push({ at: iso(-60 * 60000), node: null, event: 'Chain reports the transaction confirmed' });
    if (state === 'rejected') t.push({ at: iso(-30 * 60000), node: LOCAL, event: 'Rejected on this node' });
    if (state === 'expired') t.push({ at: iso(-10 * 60000), node: null, event: 'Expired before signing started' });
    return t;
  };

  function make(i, state, o = {}) {
    const count = o.count ?? ({ proposed: 0, approved: 1, signed: 2, broadcast: 2, confirmed: 2 }[state] ?? 0);
    const amount = o.amount ?? 1000000 * (i + 1);
    const approvedLocal = count >= 1 && !o.localNotApproved;
    return {
      id: `prop-example-${i}`, vault_id: 'vault-example-1', state, local_task: o.local_task ?? null, origin: o.origin ?? 'created',
      created_at: iso(-2 * H), updated_at: iso(-60000), expires_at: iso(state === 'expired' ? -10 * 60000 : 22 * H),
      operation_id: hex(String(i % 10)), message_sha256: hex(hexDigit(i + 1)), message_len: 220 + i,
      signers: [
        { agent: LOCAL, local: true, approved: approvedLocal ? true : state === 'proposed' ? false : null },
        { agent: PEER_B, local: false, approved: count >= 2 ? true : null },
      ],
      confirmations: { count, required: 2, approvers: [...(approvedLocal ? [LOCAL] : []), ...(count >= 2 ? [PEER_B] : [])], observed_at: iso(-5 * 60000) },
      summary: {
        network: 'solana-devnet', from: VAULT_ADDR, recipient: RECIPIENT, amount: sol(amount), fee: sol(5000),
        memo: o.memo === undefined ? `EXAMPLE memo ${i}` : o.memo, notes: ['EXAMPLE: uses a durable nonce'],
      },
      integrity: o.integrity ?? { status: 'verified', detail: null },
      signature: ['signed', 'broadcast', 'confirmed'].includes(state) ? 'ab'.repeat(64) : null,
      broadcast: ['broadcast', 'confirmed'].includes(state)
        ? { attempted_at: iso(-70 * 60000), uncertain: !!o.uncertain, txid: o.uncertain ? null : 'EXAMPLEtxid'.padEnd(40, 'x'), url: null } : null,
      failure: o.failure ?? null,
      timeline: timelineFor(state, count),
    };
  }

  const props = [
    make(0, 'proposed'),
    make(1, 'approved', { origin: 'imported', count: 1, localNotApproved: true }),
    make(2, 'signed'),
    make(3, 'broadcast', { uncertain: true }),
    make(4, 'confirmed'),
    make(5, 'rejected'),
    make(6, 'expired'),
    make(7, 'failed', { count: 1, failure: { step: 'sign', reason: 'EXAMPLE: the other signer never answered', action: 'Check the other operator’s service. Create a new proposal; signing is not retried.' } }),
    make(8, 'proposed', { integrity: { status: 'mismatch', detail: 'EXAMPLE: summary amount differs from the amount encoded in the stored bytes' }, memo: null }),
  ];
  props[1].created_at = iso(-3 * H);
  const events = [];
  const ev = (kind, message, proposal_id = null) => events.push({ seq: events.length + 1, at: iso(), kind, proposal_id, message });
  ev('vault.loaded', 'EXAMPLE: vault loaded from group descriptor');
  for (const p of props) ev(`proposal.${p.state}`, `EXAMPLE: proposal is ${p.state}`, p.id);

  const find = (id) => {
    const p = props.find((x) => x.id === id);
    if (!p) throw err(404, 'not_found', 'No such proposal.', 'Reload the proposal list.');
    return p;
  };
  const clone = (x) => structuredClone(x);
  const guardMismatch = (p) => {
    if (p.integrity.status === 'mismatch') {
      throw err(409, 'bytes_summary_mismatch', 'The stored bytes and the summary disagree.', 'Do not approve. Tell the proposing operator and create a new proposal.');
    }
  };

  async function decode(b) {
    if (!vaults.some((v) => v.id === b.vault_id)) throw err(404, 'not_found', 'No such vault.', 'Pick a vault from the list.');
    if (typeof b.recipient !== 'string' || !b.recipient.trim()) throw err(400, 'bad_request', 'The recipient is empty.', 'Enter a chain address.');
    if (!/^[1-9][0-9]*$/.test(String(b.amount))) throw err(400, 'bad_request', 'The amount is not a positive whole number of base units.', 'Enter digits only, for example 1000000.');
    if ((b.memo ?? '').length > 140) throw err(400, 'bad_request', 'The memo is longer than 140 characters.', 'Shorten the memo.');
    const summary = { network: 'solana-devnet', from: VAULT_ADDR, recipient: b.recipient.trim(), amount: sol(b.amount), fee: sol(5000), memo: b.memo || null, notes: ['EXAMPLE: uses a durable nonce'] };
    const text = JSON.stringify(['mock-tx', summary.from, summary.recipient, summary.amount.raw, summary.memo]);
    return { summary, message_sha256: await sha256Hex(text), message_len: text.length };
  }

  const driven = new Set();
  function add(p, event, node = null) { p.timeline.push({ at: iso(), node, event }); p.updated_at = iso(); }

  return {
    mode: 'mock',
    step(id) {
      const p = find(id);
      if (p.state === 'proposed' || p.state === 'approved') {
        if (p.local_task === 'approving') { p.local_task = 'signing'; p.state = 'approved'; p.confirmations.count = 1; p.confirmations.approvers = [LOCAL]; p.signers[0].approved = true; add(p, 'Approved with this node', LOCAL); ev('proposal.approved', 'EXAMPLE: approved by this node', id); }
        else if (p.local_task === 'signing') { p.confirmations.count = 2; p.confirmations.approvers = [LOCAL, PEER_B]; p.signers[1].approved = true; p.state = 'signed'; p.local_task = null; p.signature = 'cd'.repeat(64); add(p, 'Other signer approved (observed)', PEER_B); add(p, 'Group signature verified under the vault key'); ev('proposal.signed', 'EXAMPLE: signed', id); }
      } else if (p.state === 'signed') {
        p.state = 'broadcast'; p.broadcast = { attempted_at: iso(), uncertain: false, txid: 'EXAMPLEtxid'.padEnd(40, 'y'), url: null }; add(p, 'Broadcast once'); ev('proposal.broadcast', 'EXAMPLE: broadcast', id);
      } else if (p.state === 'broadcast') {
        p.state = 'confirmed'; add(p, 'Chain reports the transaction confirmed'); ev('proposal.confirmed', 'EXAMPLE: confirmed', id);
      }
    },
    // Only proposals this session approved move on their own; fixtures stay put.
    autoStep() { for (const id of driven) if (!['confirmed', 'rejected', 'failed'].includes(find(id).state)) this.step(id); },
    async vaults() { return clone(vaults); },
    async proposals(f = {}) { return clone(props.filter((p) => (!f.vault_id || p.vault_id === f.vault_id) && (!f.state || p.state === f.state))); },
    async proposal(id) { return clone(find(id)); },
    async plan(id) { find(id); return { example: true, note: 'EXAMPLE signing plan', operation_id: find(id).operation_id }; },
    async preview(b) { return decode(b); },
    async create(b) {
      const d = await decode(b);
      const p = make(props.length, 'proposed', { amount: Number(b.amount), memo: b.memo || null });
      p.id = `prop-example-new-${props.length}`; p.summary = d.summary; p.message_sha256 = d.message_sha256; p.message_len = d.message_len;
      p.created_at = iso(); p.timeline = [{ at: iso(), node: null, event: 'Proposal created; signing plan written' }];
      props.push(p); ev('proposal.proposed', 'EXAMPLE: proposal created', p.id);
      return clone(p);
    },
    async importPlan(b) {
      if (!b.plan || typeof b.plan !== 'object') throw err(400, 'bad_request', 'The plan is not a JSON object.', 'Paste the plan exactly as the other operator’s service returned it.');
      throw err(403, 'not_selected', 'EXAMPLE: the mock cannot import real plans.', 'Use the real service to import.');
    },
    async approve(id, hash) {
      const p = find(id);
      guardMismatch(p);
      if (hash !== p.message_sha256) throw err(409, 'hash_mismatch', 'The hash you confirmed is not the hash of the stored bytes.', 'Reload the proposal and review it again.');
      if (p.state !== 'proposed' && p.state !== 'approved') throw err(409, 'bad_state', `The proposal is ${p.state}.`, 'Nothing to approve.');
      if (p.signers[0].approved === true) throw err(409, 'already_approved', 'This node already approved.', 'Nothing to do.');
      if (p.local_task) throw err(409, 'busy', 'This node is busy with this proposal.', 'Wait for it to finish.');
      driven.add(id); p.local_task = 'approving'; add(p, 'Approval started on this node', LOCAL);
      return clone(p);
    },
    async reject(id, reason) {
      const p = find(id);
      if (p.signers[0].approved === true) throw err(409, 'already_approved', 'This node already approved; an approval cannot be retracted.', 'Nothing to do.');
      if (p.state !== 'proposed' && p.state !== 'approved') throw err(409, 'bad_state', `The proposal is ${p.state}.`, 'Nothing to reject.');
      p.state = 'rejected'; add(p, `Rejected on this node${reason ? `: ${reason}` : ''}`, LOCAL); ev('proposal.rejected', 'EXAMPLE: rejected', id);
      return clone(p);
    },
    async refresh(id) { const p = find(id); p.confirmations.observed_at = iso(); return clone(p); },
    async events(after = 0) { return clone(events.filter((e) => e.seq > after)); },
  };
}
