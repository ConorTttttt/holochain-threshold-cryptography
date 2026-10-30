"""The help-notice and binary-inventory logic of scripts/release_check.py
(Stage 2B, I-2). Pure functions only; the real binaries are checked by the
`help-notices` step of `npm run check:release` and by `npm run test:cli-notices`."""
from __future__ import annotations
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import release_check as rc  # noqa: E402

NOTICE = rc.canonical_notice((ROOT / "crates/mpc-dkg-worker/src/notice.rs").read_text())
WORKER_BINS = {"mpc-dkg-worker", "mpc-node", "mpc-conductor-call", "mpc-lair-live-probe", "mpc-lair-signer",
               "mpc-phase5b-bootstrap", "mpc-phase5c-provision", "mpc-relay-service", "mpc-conductor-connect",
               "mpc-sign", "mpc-transport-probe"}


def metadata(bins: dict[str, str]) -> dict:
    packages: dict[str, list] = {}
    for name, package in bins.items():
        packages.setdefault(package, []).append({"name": name, "kind": ["bin"]})
    return {"workspace_members": [f"id-{p}" for p in packages],
            "packages": [{"id": f"id-{p}", "name": p, "targets": t + [{"name": p, "kind": ["lib"]}]}
                         for p, t in packages.items()] +
                        [{"id": "registry-dep", "name": "dep", "targets": [{"name": "dep-tool", "kind": ["bin"]}]}]}


class Notice(unittest.TestCase):
    def test_canonical_notice_is_the_three_line_text(self):
        self.assertEqual(NOTICE.splitlines(), [
            "NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE.",
            "Do not use it with real keys, funds, identities or secret shares. Custody is",
            "development-grade and no independent audit has been done (see SECURITY.md)."])

    def test_cli_copies_are_word_for_word_the_canonical_notice(self):
        for source in ("crates/mpc-runtime/src/bin/mpc-custody.rs", "crates/mpc-vault/src/main.rs"):
            text = (ROOT / source).read_text()
            self.assertEqual(rc.canonical_notice(text), NOTICE, source)
            self.assertIn(rc.CUSTODY_WARNING, text, source)

    def test_help_output_rules(self):
        good = f"mpc-x\n\n{NOTICE}\n\n{rc.CUSTODY_WARNING}\n\nusage: mpc-x\n"
        self.assertEqual(rc.help_problems("mpc-x", "--help", 0, good, NOTICE, True), [])
        self.assertEqual(rc.help_problems("mpc-x", "-h", 1, good, NOTICE, False), ["mpc-x -h: exit 1"])
        self.assertEqual(rc.help_problems("mpc-x", "--help", 0, "usage: mpc-x\n", NOTICE, False),
                         ["mpc-x --help: canonical non-production notice missing"])
        partial = good.replace("Custody is\ndevelopment-grade", "Custody is development-grade")
        self.assertIn("mpc-x --help: canonical non-production notice missing",
                      rc.help_problems("mpc-x", "--help", 0, partial, NOTICE, False))
        self.assertEqual(rc.help_problems("mpc-x", "--help", 0, f"{NOTICE}\n", NOTICE, True),
                         ["mpc-x --help: custody warning missing"])


class BinaryInventory(unittest.TestCase):
    approved = json.loads((ROOT / "scripts/release_inventory.json").read_text())["binaries"]

    def test_inventory_lists_every_shipped_binary(self):
        self.assertEqual(set(self.approved), WORKER_BINS | {"mpc-custody", "mpc-vault"})
        self.assertEqual({n for n, i in self.approved.items() if i.get("custody_warning")}, {"mpc-custody", "mpc-vault"})
        self.assertEqual(self.approved["mpc-custody"]["package"], "holochain-mpc-runtime")
        self.assertEqual(self.approved["mpc-vault"]["package"], "holochain-mpc-vault")

    def test_matching_workspace_passes_and_registry_binaries_are_ignored(self):
        found = rc.shipped_binaries(metadata({n: i["package"] for n, i in self.approved.items()}))
        self.assertNotIn("dep-tool", found)
        self.assertEqual(rc.binary_problems(found, self.approved), [])

    def test_unexpected_missing_and_moved_binaries_fail(self):
        bins = {n: i["package"] for n, i in self.approved.items()}
        bins["mpc-new-tool"] = "holochain-mpc-runtime"
        del bins["mpc-vault"]
        bins["mpc-custody"] = "holochain-mpc-dkg-worker"
        problems = rc.binary_problems(rc.shipped_binaries(metadata(bins)), self.approved)
        self.assertEqual(problems, [
            "mpc-custody: built by holochain-mpc-dkg-worker, approved holochain-mpc-runtime",
            "approved binary mpc-vault (holochain-mpc-vault) is not built by the workspace",
            "unexpected binary mpc-new-tool (holochain-mpc-runtime): not in release_inventory.json"])


if __name__ == "__main__":
    unittest.main()
