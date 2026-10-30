// Pure rendering: data in, escaped HTML string out. No DOM access, so the same
// code runs in the browser and in `node --test`. Every dynamic value goes
// through esc(); nothing here builds markup from raw API strings.

export const BANNER = 'Development build. Devnet only. Not production custody.';

export const STATES = ['proposed', 'approved', 'signed', 'broadcast', 'confirmed', 'rejected', 'expired', 'failed'];
const RAIL = ['proposed', 'approved', 'signed', 'broadcast', 'confirmed'];
const TERMINAL = ['confirmed', 'rejected', 'expired', 'failed'];
const STATE_TEXT = {
  proposed: 'Proposed', approved: 'Approved', signed: 'Signed', broadcast: 'Broadcast',
  confirmed: 'Confirmed', rejected: 'Rejected', expired: 'Expired', failed: 'Failed',
};
const STATE_HELP = {
  proposed: 'No approval yet.',
  approved: 'At least one signer has approved.',
  signed: 'The group signature exists. Waiting for broadcast.',
  broadcast: 'Submitted to the chain once. Waiting for confirmation.',
  confirmed: 'The chain reports the transaction final enough.',
  rejected: 'Rejected on this node. Final.',
  expired: 'Not signed before it expired. Final.',
  failed: 'Failed. Final. See the failure below.',
};

export function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function shortId(id) {
  const s = String(id ?? '');
  return s.length > 12 ? `${s.slice(0, 8)}…` : s;
}

// Middle-shortened for list rows only. Detail and preview always show the full value.
export function shortAddr(a) {
  const s = String(a ?? '');
  return s.length > 16 ? `${s.slice(0, 6)}…${s.slice(-6)}` : s;
}

function span(ms) {
  const m = Math.floor(ms / 60000);
  if (m < 1) return 'under a minute';
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${m % 60} min`.replace(/ 0 min$/, '');
  return `${Math.floor(h / 24)} d`;
}

export function age(iso, now) {
  const ms = now - Date.parse(iso);
  if (!Number.isFinite(ms)) return 'unknown';
  return ms < 60000 ? 'just now' : `${span(ms)} ago`;
}

export function expiry(p, now) {
  const ms = Date.parse(p.expires_at) - now;
  if (!Number.isFinite(ms)) return 'unknown';
  if (p.state === 'expired') return 'expired';
  if (TERMINAL.includes(p.state) || p.state === 'signed' || p.state === 'broadcast') return 'expiry no longer applies';
  return ms <= 0 ? 'expired, awaiting service update' : `expires in ${span(ms)}`;
}

function badge(state) {
  return `<span class="badge s-${esc(state)}">${esc(STATE_TEXT[state] ?? state)}</span>`;
}

export function pageHead(title, lead) {
  return `<h1 id="page-title" tabindex="-1">${esc(title)}</h1>${lead ? `<p class="lead">${esc(lead)}</p>` : ''}`;
}

export function renderError(err) {
  if (!err) return '';
  const uncertain = err.uncertain
    ? '<p class="err-uncertain"><strong>The outcome is unknown.</strong> Do not repeat the action. Reload and check the proposal first.</p>'
    : '';
  return `<div class="alert error" role="alert">
    <p class="alert-title">Failed: ${esc(err.message)}</p>
    <p><strong>What to do:</strong> ${esc(err.action)}</p>${uncertain}
    <p class="muted">Code <code>${esc(err.code)}</code>${err.status ? `, HTTP ${esc(err.status)}` : ''}</p>
  </div>`;
}

export function renderConnect({ error }) {
  return `${pageHead('Connect', 'This page talks to the vault service on this machine. The token is kept in memory for this tab only and is gone when you close or reload it.')}
  ${renderError(error)}
  <form class="card" data-form="connect" autocomplete="off">
    <label for="token">Bearer token</label>
    <p class="hint" id="token-hint">The contents of the 0600 token file given to the service. It is never written to disk by this page.</p>
    <input id="token" name="token" type="password" autocomplete="off" spellcheck="false" aria-describedby="token-hint" required>
    <div class="row">
      <button type="submit" class="primary">Connect</button>
      <button type="button" data-action="use-mock">Explore with example data</button>
    </div>
  </form>`;
}

// ----- vaults

function money(m) {
  return m ? esc(m.display) : '';
}

export function renderVaults(vaults) {
  if (!vaults.length) {
    return `${pageHead('Vaults')}<div class="card"><p>No vault exists on this node yet.</p>
      <p><strong>What to do:</strong> create one from the completed group with <code>POST /vaults</code> (see docs/V040_VAULT_APP.md). The UI does not create vaults.</p></div>`;
  }
  const cards = vaults.map((v) => {
    const bal = v.balance
      ? `<span class="big">${money(v.balance)}</span>`
      : `<span class="muted">Balance unavailable</span>${v.balance_error ? `<p class="hint">${esc(v.balance_error)}</p>` : ''}`;
    const members = v.members.map((m) =>
      `<li><code class="wrap">${esc(m.agent)}</code>${m.local ? ' <span class="tag">this node</span>' : ''}</li>`).join('');
    const notes = (v.notes ?? []).map((n) => `<li>${esc(n)}</li>`).join('');
    return `<article class="card node-card" aria-labelledby="v-${esc(v.id)}">
      <header class="card-head"><h2 id="v-${esc(v.id)}">${esc(v.name)}</h2>
        <span class="tag">${esc(v.chain)}</span></header>
      <dl class="facts">
        <dt>Address (group public key)</dt><dd><code class="wrap">${esc(v.address)}</code></dd>
        <dt>Balance</dt><dd>${bal}</dd>
        <dt>Threshold</dt><dd>${esc(v.threshold)} of ${esc(v.members.length)}</dd>
        <dt>Group status</dt><dd><span class="badge s-approved">${esc(v.group_status.replace('_', ' '))}</span>
          <p class="hint">This node holds a completed group descriptor. Activation by every member is checked when a proposal is approved.</p></dd>
        <dt>Members</dt><dd><ul class="plain">${members}</ul></dd>
        <dt>Created</dt><dd>${esc(v.created_at)}</dd>
      </dl>
      ${notes ? `<details><summary>Limits of this vault</summary><ul>${notes}</ul></details>` : ''}
      <p class="row"><a class="button" href="#/proposals?vault=${encodeURIComponent(v.id)}">Proposals</a>
        <a class="button primary" href="#/new?vault=${encodeURIComponent(v.id)}">New proposal</a></p>
    </article>`;
  }).join('');
  return `${pageHead('Vaults')}<div class="grid">${cards}</div>`;
}

// ----- proposals

function confirmText(c) {
  return `${c.count} of ${c.required}`;
}

function meter(c) {
  const slots = Array.from({ length: c.required }, (_, i) => `<span class="slot${i < c.count ? ' on' : ''}"></span>`).join('');
  return `<span class="meter" role="img" aria-label="${esc(confirmText(c))} confirmations">${slots}</span>`;
}

export function renderProposals(list, { now, vaultId, vaults = [] }) {
  const filtered = vaultId ? list.filter((p) => p.vault_id === vaultId) : list;
  const vname = new Map(vaults.map((v) => [v.id, v.name]));
  const groups = STATES.map((s) => [s, filtered.filter((p) => p.state === s)]).filter(([, a]) => a.length);
  const head = pageHead('Proposals', vaultId ? `Filtered to vault ${vname.get(vaultId) ?? vaultId}.` : null);
  if (!groups.length) {
    return `${head}<div class="card"><p>No proposals.</p><p><a class="button primary" href="#/new">New proposal</a></p></div>`;
  }
  const sections = groups.map(([s, items]) => {
    const rows = items.map((p) => {
      const warn = p.integrity.status === 'mismatch' ? ' <span class="tag danger">bytes/summary mismatch</span>' : '';
      return `<li class="prop-row"><a class="row-link" href="#/proposals/${encodeURIComponent(p.id)}">
        <span class="r-main"><strong>${esc(p.summary.amount.display)}</strong> to <code title="${esc(p.summary.recipient)}">${esc(shortAddr(p.summary.recipient))}</code>${warn}</span>
        <span class="r-sub">fee ${esc(p.summary.fee.display)} · ${meter(p.confirmations)} ${esc(confirmText(p.confirmations))} confirmations</span>
        <span class="r-sub">created ${esc(age(p.created_at, now))} · ${esc(expiry(p, now))}${p.local_task ? ` · this node is ${esc(p.local_task)}` : ''}</span>
        <span class="visually-hidden">Proposal ${esc(shortId(p.id))}${vname.get(p.vault_id) ? ` in ${esc(vname.get(p.vault_id))}` : ''}</span>
      </a></li>`;
    }).join('');
    return `<section aria-labelledby="g-${s}"><h2 id="g-${s}">${badge(s)} <span class="count">${items.length}</span></h2>
      <p class="hint">${esc(STATE_HELP[s])}</p><ul class="plain list">${rows}</ul></section>`;
  }).join('');
  return `${head}<p><a class="button primary" href="#/new">New proposal</a></p>${sections}`;
}

// ----- proposal detail

export function approvalBlocker(p) {
  if (p.integrity.status === 'mismatch') return 'The stored bytes and their summary disagree. Approval is disabled.';
  if (p.state !== 'proposed' && p.state !== 'approved') return `The proposal is ${p.state}; approval is closed.`;
  const me = p.signers.find((s) => s.local);
  if (!me) return 'This node is not a selected signer for this proposal.';
  if (me.approved === true) return 'This node has already approved. An approval cannot be retracted.';
  if (p.local_task) return `This node is busy: ${p.local_task}.`;
  return null;
}

export function rejectBlocker(p) {
  if (p.state !== 'proposed' && p.state !== 'approved') return `The proposal is ${p.state}; rejecting is closed.`;
  const me = p.signers.find((s) => s.local);
  if (me && me.approved === true) return 'This node has already approved, and an approval cannot be retracted.';
  if (p.local_task) return `This node is busy: ${p.local_task}.`;
  return null;
}

export function stageRail(p) {
  const at = RAIL.indexOf(p.state);
  const items = RAIL.map((s, i) => {
    let cls = 'todo';
    if (at >= 0) cls = i < at ? 'done' : i === at ? 'now' : 'todo';
    else if (i === 0) cls = 'done';
    return `<li class="${cls}"${cls === 'now' ? ' aria-current="step"' : ''}><span class="dot"></span>${esc(STATE_TEXT[s])}<span class="visually-hidden">${cls === 'done' ? ' (done)' : cls === 'now' ? ' (current)' : ' (not yet)'}</span></li>`;
  }).join('');
  const end = at < 0 ? `<p class="rail-end">Ended as ${badge(p.state)}</p>` : '';
  return `<ol class="rail" aria-label="Progress">${items}</ol>${end}`;
}

function summaryCard(p) {
  const s = p.summary;
  const bad = p.integrity.status === 'mismatch';
  const notes = (s.notes ?? []).map((n) => `<li>${esc(n)}</li>`).join('');
  return `<section class="card${bad ? ' unverified' : ''}" aria-labelledby="what">
    <h2 id="what">${bad ? 'Unverified summary. Do not trust.' : 'What is being signed'}</h2>
    <p class="hint">${bad
      ? 'This summary does not match the stored bytes. It is shown only so you can report it.'
      : `Decoded by the service from the exact ${esc(p.message_len)} bytes that will be signed. Compare the hash below with <code>sha256sum</code> of your own copy of the message.`}</p>
    <dl class="facts">
      <dt>Network</dt><dd>${esc(s.network)}</dd>
      <dt>From (the vault)</dt><dd><code class="wrap">${esc(s.from)}</code></dd>
      <dt>Recipient</dt><dd><code class="wrap strong">${esc(s.recipient)}</code></dd>
      <dt>Amount</dt><dd><strong class="big">${esc(s.amount.display)}</strong> <span class="muted">(${esc(s.amount.raw)} base units)</span></dd>
      <dt>Network fee</dt><dd>${esc(s.fee.display)} <span class="muted">(${esc(s.fee.raw)} base units)</span></dd>
      <dt>Memo</dt><dd>${s.memo ? esc(s.memo) : '<span class="muted">none</span>'}</dd>
      ${notes ? `<dt>Notes</dt><dd><ul>${notes}</ul></dd>` : ''}
      <dt>Message SHA-256</dt><dd><code class="wrap">${esc(p.message_sha256)}</code></dd>
      <dt>Message length</dt><dd>${esc(p.message_len)} bytes</dd>
      <dt>Operation id</dt><dd><code class="wrap">${esc(p.operation_id)}</code></dd>
    </dl></section>`;
}

function nodeCards(p) {
  const byNode = new Map();
  for (const e of p.timeline) {
    const k = e.node ?? '';
    if (!byNode.has(k)) byNode.set(k, []);
    byNode.get(k).push(e);
  }
  const card = (title, tagHtml, status, entries) => `<article class="card node-card">
    <header class="card-head"><h3>${title}</h3>${tagHtml}</header>
    ${status ? `<p>${status}</p>` : ''}
    ${entries.length
    ? `<ol class="timeline">${entries.map((e) => `<li><time datetime="${esc(e.at)}">${esc(e.at)}</time> ${esc(e.event)}</li>`).join('')}</ol>`
    : '<p class="muted">No events recorded for this node.</p>'}</article>`;
  const cards = p.signers.map((s) => {
    const status = s.approved === true ? '<span class="badge s-approved">Approved</span>'
      : s.approved === false ? '<span class="badge s-proposed">Not approved</span>'
        : '<span class="badge s-unknown">Not yet observed on this node</span>';
    return card(`<code class="wrap">${esc(s.agent)}</code>`, s.local ? '<span class="tag">this node</span>' : '', status, byNode.get(s.agent) ?? []);
  });
  const svc = byNode.get('');
  if (svc) cards.push(card('Service', '', '', svc));
  const others = [...byNode.keys()].filter((k) => k && !p.signers.some((s) => s.agent === k));
  for (const k of others) cards.push(card(`<code class="wrap">${esc(k)}</code>`, '', '', byNode.get(k)));
  return `<section aria-labelledby="nodes"><h2 id="nodes">Signers and timeline</h2><div class="grid">${cards.join('')}</div></section>`;
}

function approvePanel(p, ctx) {
  const s = p.summary;
  return `<form class="card confirm" data-form="approve" aria-labelledby="ap-h">
    <h3 id="ap-h">Confirm approval</h3>
    <p>You are about to approve signing this exact transaction with this node. This cannot be undone or retried from this page.</p>
    <dl class="facts">
      <dt>Recipient</dt><dd><code class="wrap strong">${esc(s.recipient)}</code></dd>
      <dt>Amount</dt><dd><strong>${esc(s.amount.display)}</strong></dd>
      <dt>Fee</dt><dd>${esc(s.fee.display)}</dd>
      <dt>Message SHA-256</dt><dd><code class="wrap">${esc(p.message_sha256)}</code></dd>
    </dl>
    <p class="hint">After you confirm, the passphrase for this node is typed on the terminal where the service runs. It is never entered here.</p>
    <label class="check"><input type="checkbox" id="ack" data-input="ack"${ctx.ack ? ' checked' : ''}>
      I have read the recipient, amount and hash above and they are what I intend to sign.</label>
    <div class="row">
      <button type="submit" class="primary" id="confirm-approve"${ctx.ack && !ctx.busy ? '' : ' disabled'}>Confirm approval</button>
      <button type="button" data-action="close-panel"${ctx.busy ? ' disabled' : ''}>Cancel</button>
    </div></form>`;
}

function rejectPanel(p, ctx) {
  return `<form class="card confirm" data-form="reject" aria-labelledby="rj-h">
    <h3 id="rj-h">Confirm rejection</h3>
    <p>This rejects the proposal on <strong>this node only</strong> and is final. Other nodes are not told. If two other members approve, it can still be signed.</p>
    <label for="reason">Reason (optional, at most 200 characters)</label>
    <input id="reason" data-input="reason" maxlength="200" value="${esc(ctx.reason ?? '')}">
    <div class="row">
      <button type="submit" class="danger" id="confirm-reject"${ctx.busy ? ' disabled' : ''}>Confirm rejection</button>
      <button type="button" data-action="close-panel"${ctx.busy ? ' disabled' : ''}>Cancel</button>
    </div></form>`;
}

function outcomeCard(p) {
  const parts = [];
  if (p.signature) parts.push(`<dt>Group signature</dt><dd><code class="wrap">${esc(p.signature)}</code></dd>`);
  if (p.broadcast) {
    const b = p.broadcast;
    parts.push(`<dt>Broadcast attempted</dt><dd>${esc(b.attempted_at)}</dd>`);
    if (b.txid) parts.push(`<dt>Transaction id</dt><dd><code class="wrap">${esc(b.txid)}</code></dd>`);
    if (b.url) parts.push(`<dt>Explorer</dt><dd><code class="wrap">${esc(b.url)}</code> <span class="hint">(not a link: this page makes no external requests)</span></dd>`);
  }
  if (!parts.length) return '';
  const unc = p.broadcast?.uncertain
    ? '<div class="alert warn" role="alert"><p class="alert-title">Broadcast outcome unknown</p><p>The service could not tell whether the network accepted it. It will be resolved by reading the chain for the signature above, never by sending again. <strong>What to do:</strong> wait, or use “Check chain once”.</p></div>'
    : '';
  return `<section class="card" aria-labelledby="out"><h2 id="out">Signature and broadcast</h2>${unc}<dl class="facts">${parts.join('')}</dl></section>`;
}

export function renderDetail(p, ctx) {
  const mismatch = p.integrity.status === 'mismatch';
  const blocker = approvalBlocker(p);
  const rBlock = rejectBlocker(p);
  const banner = mismatch
    ? `<div class="alert error" role="alert"><p class="alert-title">Bytes and summary mismatch. Do not approve.</p>
        <p>The service reports that the stored bytes and the decoded summary disagree${p.integrity.detail ? `: ${esc(p.integrity.detail)}` : ''}. Every write on this proposal is refused.</p>
        <p><strong>What to do:</strong> do not approve it on any node. Tell the proposing operator and the other signers, and create a new proposal if the transfer is still wanted.</p></div>`
    : '';
  const fail = p.failure
    ? `<div class="alert error" role="alert"><p class="alert-title">Failed at step “${esc(p.failure.step)}”: ${esc(p.failure.reason)}</p>
        <p><strong>What to do:</strong> ${esc(p.failure.action)}</p><p class="hint">Signing and broadcast are never retried automatically, and this page has no retry for them.</p></div>`
    : '';
  const busy = p.local_task ? `<p class="status" role="status">This node is ${esc(p.local_task)}…</p>` : '';
  let refresh = '';
  if (p.state === 'proposed' || p.state === 'approved') {
    refresh = `<button type="button" data-action="refresh"${ctx.busy ? ' disabled' : ''}>Re-read approvals from Holochain</button>
      <span class="hint">Read-only. With an interactive passphrase the service may ask for it on its terminal.</span>`;
  } else if (p.state === 'signed' || p.state === 'broadcast') {
    refresh = `<button type="button" data-action="refresh"${ctx.busy ? ' disabled' : ''}>Check chain once</button>
      <span class="hint">Read-only. Looks the signature up on the chain; it never sends anything.</span>`;
  }
  const signedNote = p.state === 'signed' && !p.broadcast
    ? '<p class="hint">Signed, not yet broadcast. The proposing node broadcasts automatically unless its auto-broadcast is off; this page does not broadcast.</p>' : '';
  const actions = `<section class="card" aria-labelledby="act"><h2 id="act">Decision</h2>
    ${blocker ? `<p class="blocker" id="blocker">${esc(blocker)}</p>` : ''}
    <div class="row">
      <button type="button" class="primary" data-action="open-approve"${blocker || ctx.panel === 'approve' ? ' disabled' : ''}${blocker ? ' aria-describedby="blocker"' : ''}>Approve…</button>
      <button type="button" class="danger" data-action="open-reject"${rBlock || ctx.panel === 'reject' ? ' disabled' : ''}>Reject…</button>
    </div>
    ${rBlock && !blocker ? `<p class="hint">${esc(rBlock)}</p>` : ''}
    ${refresh ? `<div class="row">${refresh}</div>` : ''}${signedNote}${busy}</section>`;
  const panel = ctx.panel === 'approve' && !blocker ? approvePanel(p, ctx)
    : ctx.panel === 'reject' && !rBlock ? rejectPanel(p, ctx) : '';
  const c = p.confirmations;
  const confirmations = `<section class="card" aria-labelledby="conf"><h2 id="conf">Confirmations</h2>
    <p><span class="big">${esc(confirmText(c))}</span> ${meter(c)}</p>
    <p class="hint">Last read ${esc(age(c.observed_at, ctx.now))}. Remote approvals are only known after a re-read or a completed signature.</p>
    ${c.approvers.length ? `<ul class="plain">${c.approvers.map((a) => `<li><code class="wrap">${esc(a)}</code></li>`).join('')}</ul>` : '<p class="muted">No approvers observed.</p>'}</section>`;
  const plan = p.origin === 'created'
    ? `<section class="card" aria-labelledby="plan"><h2 id="plan">Hand over to the other operator</h2>
        <p class="hint">The other selected signer imports this plan on their own service.</p>
        <button type="button" data-action="show-plan">${ctx.plan ? 'Reload plan' : 'Show signing plan'}</button>
        ${ctx.plan ? `<textarea readonly rows="8" class="mono" aria-label="Signing plan JSON">${esc(ctx.plan)}</textarea>` : ''}</section>` : '';
  return `<p><a href="#/proposals">← All proposals</a></p>
    ${pageHead(`Proposal ${shortId(p.id)}`)}
    <p>${badge(p.state)} ${esc(STATE_HELP[p.state])}
      <span class="muted">Created ${esc(age(p.created_at, ctx.now))} (${esc(p.origin)}) · ${esc(expiry(p, ctx.now))}</span></p>
    ${banner}${fail}${ctx.error ? renderError(ctx.error) : ''}
    ${stageRail(p)}
    ${summaryCard(p)}${confirmations}${actions}${panel}${outcomeCard(p)}${nodeCards(p)}${plan}`;
}

// ----- new proposal

export function renderPreview(pv) {
  if (!pv) return '';
  const s = pv.summary;
  return `<section class="card preview" aria-labelledby="pv-h"><h2 id="pv-h">Decoded preview</h2>
    <p class="hint">Decoded by the service from the exact ${esc(pv.message_len)} bytes it would sign. Nothing has been created yet.</p>
    <dl class="facts">
      <dt>Network</dt><dd>${esc(s.network)}</dd>
      <dt>From (the vault)</dt><dd><code class="wrap">${esc(s.from)}</code></dd>
      <dt>Recipient</dt><dd><code class="wrap strong">${esc(s.recipient)}</code></dd>
      <dt>Amount</dt><dd><strong class="big">${esc(s.amount.display)}</strong> <span class="muted">(${esc(s.amount.raw)} base units)</span></dd>
      <dt>Network fee</dt><dd>${esc(s.fee.display)}</dd>
      <dt>Memo</dt><dd>${s.memo ? esc(s.memo) : '<span class="muted">none</span>'}</dd>
      ${(s.notes ?? []).length ? `<dt>Notes</dt><dd><ul>${s.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul></dd>` : ''}
      <dt>Message SHA-256</dt><dd><code class="wrap">${esc(pv.message_sha256)}</code></dd>
    </dl></section>`;
}

export function validateNew(f) {
  const errs = {};
  if (!f.vault_id) errs.vault_id = 'Choose a vault.';
  if (!f.recipient.trim()) errs.recipient = 'Enter the recipient address.';
  if (!/^[1-9][0-9]*$/.test(f.amount.trim())) errs.amount = 'Enter a whole number of base units greater than zero, digits only.';
  if ([...f.memo].length > 140) errs.memo = 'The memo is at most 140 characters.';
  return errs;
}

export function renderNew({ vaults, form, errors = {}, preview, previewStale, error, importForm, importError, busy }) {
  const opts = vaults.map((v) => `<option value="${esc(v.id)}"${v.id === form.vault_id ? ' selected' : ''}>${esc(v.name)} (${esc(v.chain)})</option>`).join('');
  const v = vaults.find((x) => x.id === form.vault_id);
  const unit = v?.balance ? `1 ${v.balance.symbol} = 10^${v.balance.decimals} base units.` : 'Base units are the chain’s smallest unit (lamports on Solana).';
  const fe = (k) => (errors[k] ? `<p class="field-error" id="e-${k}">${esc(errors[k])}</p>` : '');
  const inv = (k) => (errors[k] ? ` aria-invalid="true" aria-describedby="e-${k}"` : '');
  const canSubmit = preview && !previewStale && !busy;
  return `${pageHead('New proposal', 'Preview first. The preview is decoded by the service from the transaction it would sign.')}
  ${renderError(error)}
  <form class="card" data-form="new" novalidate>
    <label for="f-vault">Vault</label>
    <select id="f-vault" name="vault_id" data-input="vault_id" aria-invalid="${errors.vault_id ? 'true' : 'false'}">${opts}</select>${fe('vault_id')}
    <label for="f-recipient">Recipient address</label>
    <input id="f-recipient" name="recipient" data-input="recipient" value="${esc(form.recipient)}" autocomplete="off" spellcheck="false"${inv('recipient')}>${fe('recipient')}
    <label for="f-amount">Amount in base units</label>
    <input id="f-amount" name="amount" data-input="amount" value="${esc(form.amount)}" inputmode="numeric" autocomplete="off"${inv('amount')}>
    <p class="hint">${esc(unit)}</p>${fe('amount')}
    <label for="f-memo">Memo (optional, at most 140 characters)</label>
    <input id="f-memo" name="memo" data-input="memo" value="${esc(form.memo)}" maxlength="140" autocomplete="off"${inv('memo')}>${fe('memo')}
    <div class="row">
      <button type="submit" id="do-preview"${busy ? ' disabled' : ''}>Preview</button>
      <button type="button" class="primary" data-action="submit-proposal"${canSubmit ? '' : ' disabled'}>Submit proposal</button>
    </div>
    ${previewStale ? '<p class="hint" role="status">The form changed after the preview. Preview again before submitting.</p>' : ''}
    ${!preview ? '<p class="hint">Submit unlocks after a preview.</p>' : ''}
  </form>
  ${renderPreview(preview)}
  <details class="card"><summary>Import a proposal from another operator</summary>
    ${renderError(importError)}
    <form data-form="import">
      <label for="i-plan">Signing plan JSON (from the other operator)</label>
      <textarea id="i-plan" data-input="import_plan" rows="6" class="mono" spellcheck="false">${esc(importForm.plan)}</textarea>
      <p class="hint">Imported into the vault chosen above. The service decodes the plan itself and refuses anything it cannot verify.</p>
      <button type="submit"${busy ? ' disabled' : ''}>Import</button>
    </form></details>`;
}

// ----- activity

export function renderEvents(events, { error, now }) {
  const rows = events.slice().reverse().map((e) => `<li><time datetime="${esc(e.at)}">${esc(e.at)}</time>
    <span class="tag">${esc(e.kind)}</span> ${esc(e.message)}${e.proposal_id ? ` <a href="#/proposals/${encodeURIComponent(e.proposal_id)}">proposal ${esc(shortId(e.proposal_id))}</a>` : ''}</li>`).join('');
  return `${pageHead('Activity', 'Events as the service reports them, newest first.')}${renderError(error)}
    ${events.length ? `<ol class="plain log" aria-label="Events">${rows}</ol>` : '<div class="card"><p>No events yet.</p></div>'}
    <p class="hint">${events.length} events loaded${now ? '' : ''}.</p>`;
}
