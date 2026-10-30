# Agent 6: Vault UI

Read `00-COMMON-RULES.md` first. Start when Agent 5 has delivered
`crates/mpc-vault/openapi.yaml`; until then build against the mock below.

## Goal

A web UI for the threshold vault: see pending proposals with confirmation counts,
read exactly what is being signed, approve or reject, and watch status through
to confirmation.

## Scope

You own a NEW directory `ui/vault/` and `docs/V040_VAULT_UI.md`. No changes
outside it. Plain HTML, CSS and JavaScript with no build step, or a small
dependency-free toolchain; keep it servable as static files by the vault
service on 127.0.0.1. No external network calls, CDNs or fonts at runtime
(the app runs offline). The existing demo page gives the visual direction:
node cards, stage rail, event log, both light and dark themes.

## Screens

1. Vaults: list, address (group public key), balance, members and threshold
   (2 of 3), group status.
2. Proposals: queue grouped by state; each row shows recipient, amount, fee,
   confirmations x of 2, age and expiry.
3. Proposal detail: the decoded transaction from the API (the exact signed
   bytes), who approved, a per-node timeline, and Approve / Reject buttons.
   Approve requires an explicit confirmation step on the page (no
   `confirm()` dialogs; build it into the page). Show a warning banner when the
   API reports a bytes/summary mismatch and disable approval.
4. New proposal: recipient, amount, memo; shows the decoded preview before
   submission.
5. Activity log: events as the service reports them.

## Rules

- Never display or store passphrases, shares or tokens beyond the session. The
  bearer token lives in memory only.
- Show a persistent banner: "Development build. Devnet only. Not production
  custody."
- Every error shows what failed and what to do; no retry buttons for signing or
  broadcast (uncertain writes).
- Accessible: keyboard operable, visible focus, readable at 400 px width.

## Tasks

1. Mock API (a small static JSON fixture server or in-page fixtures) matching
   `openapi.yaml`, with example data clearly marked as examples.
2. Implement the five screens against the contract.
3. Tests: a script-based check of state rendering for every proposal state, and
   of the mismatch-banner path. A screenshot or manual walkthrough in the doc.

## Done when

The UI runs against the mock and, if Agent 5 is done, against the real service on
the rehearsal; the report lists any contract gaps found.
