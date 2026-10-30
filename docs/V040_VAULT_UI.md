# v0.4.0 Vault UI (Agent 6)

Date: 2026-10-27. Result: a no-build static UI in `ui/vault/` with the five screens. It was run against an in-page mock (real-browser click-through) and against the real `mpc-vault demo` service on a mock chain (API level, using the UI's own client and renderer). It has not been run against the Solana devnet rehearsal.

Development evidence, not production custody, not an independent audit.

## What it is

Plain HTML, CSS and ES modules. No dependencies, no CDN, no fonts, no external requests. The vault service serves it under `/ui/` (`--ui-dir ui/vault`). The service CSP is `default-src 'self'`, so there is no inline script. Light and dark themes follow the OS, with a toggle. The only thing stored in `localStorage` is the theme name.

| File | Role |
|---|---|
| `render.js` | Pure functions, data to escaped HTML. Runs in the browser and under node. |
| `api.js` | Fetch client. The bearer token is held in a closure only. Writes are sent once and never retried. |
| `mock.js` | In-page mock shaped like `crates/mpc-vault/openapi.yaml`. All data is marked EXAMPLE. |
| `app.js` | Routing, polling (3 s on the proposal and activity screens), event handling. |
| `test/render.test.mjs` | 15 checks: `node --test ui/vault/test`. |
| `scripts/live_contract.mjs` | Optional: drives a real service with the UI's client and renderer. |

Open `/ui/?mock` for example data, or `/ui/` and paste the token from the token file.

## Screens

1. **Vaults**: name, chain, address (group public key), live balance or the balance error, 2 of 3, group status, members, limits notes.
2. **Proposals**: grouped by state in lifecycle order. Each row shows amount, shortened recipient, fee, confirmations x of 2 with a meter, age, expiry, this node's task, and a mismatch tag.
3. **Detail**: mismatch banner, stage rail, decoded transaction (full recipient, amount, fee, memo, hash, length, operation id), confirmations, per-signer cards with a per-node timeline, outcome (signature, txid, uncertain broadcast), Approve and Reject.
   - Approve opens an on-page panel that repeats recipient, amount and hash. Its confirm button stays disabled until a checkbox is ticked. It sends `{confirm:true, message_sha256}` with the hash that was displayed. No `confirm()`.
   - Reject has its own panel.
4. **New proposal**: validated form, `POST /proposals/preview`, decoded preview. Submit stays disabled until a preview exists, and any edit invalidates the preview. It also has an Import form for another operator's plan.
5. **Activity**: `/events`, newest first, linked to proposals.

## Rules and how they are met

- The banner "Development build. Devnet only. Not production custody." is in the static HTML on every screen. Mock mode adds an EXAMPLE DATA banner.
- The token lives in memory only. The field is cleared on submit. Disconnect or a 401 drops it. A test checks that nothing token-like touches storage.
- On `integrity.status = mismatch`: red alert with the detail and what to do, summary labelled "Unverified", Approve disabled, and the panel is not rendered even if requested. The service also refuses (409 `bytes_summary_mismatch`).
- Approve is also disabled when the state is not proposed or approved, this node is not a signer, it already approved, or a local task is running. Reject is disabled once this node has approved.
- Errors show the API's message and action plus the code. A network failure on a write says the outcome is unknown and not to repeat it. There are no retry buttons. "Re-read approvals" and "Check chain once" call the read-only `/refresh`.
- Keyboard and layout: skip link, visible focus ring, focus moves to the title on navigation and into the panel on open, focus survives polling re-renders, aria-live announcements. Checked at 420 px wide with no horizontal scroll.

## Evidence

| Command | Result |
|---|---|
| `node --test ui/vault/test` | 15 passed, 0 failed. Covers every state in list and detail, the mismatch path, approve gating and the confirmation step, reject gating, no retry controls, uncertain broadcast, error format, escaping, the API client (single attempt, uncertain writes), a full mock run, and static rules (no external URLs, dialogs, inline style or script). |
| `scripts/live_contract.mjs` against `mpc-vault demo` (Agent 5 debug build) | Passed. Vaults, preview, create, wrong hash refused (`hash_mismatch`), approve, polled to `confirmed` at 2 of 2, events, plan. The renderer was fed the real responses. |
| Headless Chrome click-through of the mock at 420 px, light and dark (throwaway script, not part of the patch) | As expected: approve panel, checkbox gating, focus kept across re-render, mismatch approval disabled, preview and submit gating, no horizontal scroll. |

Screenshots are in `ui/vault/screenshots/`: mismatch and approve panel at 400 px light, new-proposal preview at 400 px dark, proposals at desktop width. The desktop one was taken before the mock was made static, so its groups differ slightly from today's mock.

Manual walkthrough: open `/ui/?mock`, go to Proposals, open the first proposed item, choose Approve, tick the box, Confirm. It moves through approving, signing, signed, broadcast, confirmed in about 12 s. Open the last proposed item (mismatch) to see the banner.

## Not verified

- The real Solana devnet flow, and the UI against the Phase 6 rehearsal. Agent 5's end-to-end run was still waiting on faucet funds.
- Screen readers. Only keyboard order and ARIA structure were checked.
- Firefox and Safari.
- The Import form against a real plan (the mock cannot import).

## Contract gaps found

1. The API returns no raw message bytes for a proposal, only the decoded summary, hash and length. `/plan` carries `message`. A `message_hex` field would let operators check with their own tools.
2. The UI cannot tell whether auto-broadcast is on, and offers no broadcast button. A `signed` proposal on a node with auto-broadcast off cannot be broadcast from the UI. Operator decision.
3. The generic 400 `action` ("Fix the request and try again.") is weak.
4. `approve` returns `state: proposed` with `local_task: approving`. Remote approval stays `null` until `/refresh`.
5. The `replay` error carries no `proposal_id`, so the UI cannot link to the existing proposal.
6. `group_status` has a single value, so an unhealthy group cannot be shown.

## Handover edits proposed

Tick "vault UI built against openapi.yaml (mock and demo service)". Leave "devnet rehearsal with UI" open. History row: 2026-10-27 Agent 6 vault UI.

## Operator decisions

Where to merge, whether `--ui-dir ui/vault` becomes the default, and the auto-broadcast question.
