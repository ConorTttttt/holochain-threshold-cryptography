# Common rules for every agent (read first)

Project: Holochain MPC Core, dealerless 2-of-3 FROST Ed25519 over Holochain 0.7.1
(hdk =0.7.1, hdi =0.8.1). Status and risks live in the Claude Docs handover
(https://claude.ai/artifact/JUYgv811jAwynxs5GPtwCE). Read `docs/ARCHITECTURE.md`,
`docs/SECURITY.md` and the document named in your brief before changing code.

## Hard limits

1. Never touch `~/mpc-phase5b-sandbox` or `~/mpc-phase5c-sandbox`. Never start,
   stop or write to a persistent conductor. Never run `update_coordinators`,
   the 5C-B audit or any 5C-C step. Those are operator-only.
2. No real keys or real passphrases. Rehearsals use only the disposable harness
   under `~/mpc-phase6-rehearsal` with a throwaway passphrase fed through a
   pseudo-terminal (see `scripts/phase6_rehearsal.py`).
3. Do not change the integrity zome or any DNA property. A rebuilt integrity
   WASM changes the DNA hash (limitation L2). Coordinator-only changes are fine.
   Do not change the SDK pins.
4. Do not touch the lockfile except as your brief says. Work offline
   (`--offline --locked` where the scripts do).
5. No `git commit`, `git reset`, `git clean` or checkout over existing files.
   Work in your own copy of the tree (for example `cp -a` to a new directory, or a
   git worktree) and return a patch plus a list of changed and new files.
   The operator merges. Checkpoint refs are created by the operator.
6. Edit only the files your brief says you own. If you need a change elsewhere,
   write it up in your report and stop; do not make it.
7. Do not edit the Claude Docs handover. Put proposed handover edits (checklist
   ticks, history row, risk changes) in your report under "Handover edits".

## Method

- Write the failing test first, then the fix. Every new refusal path gets a test.
- Run the focused `npm run test:*` scripts for your area, then `npm run test:native`
  if you changed shared crates. Report each command and its real result. If a
  test fails or you skipped it, say so; never claim a pass you did not see.
- Keep the existing style: comment density, naming and error handling of the
  surrounding code. Fail closed. Never log secrets, shares or passphrases.
- Add or update a doc under `docs/` in the same style as `docs/V040_PHASE8_SIGNING.md`,
  starting with the date, the result and a "development evidence, not production
  custody, not an independent audit" disclaimer.

## Report format (final message)

1. Result in two sentences.
2. Files changed or added (paths).
3. Commands run, with pass or fail.
4. What is still unproven or deliberately not done.
5. Handover edits proposed.
6. Anything that needs an operator decision.
