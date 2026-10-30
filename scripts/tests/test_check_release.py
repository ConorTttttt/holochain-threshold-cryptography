"""scripts/check_release.py against the approved inventory (Stage 2B, I-1).

Each test copies this source tree (without build output) to a temporary
directory, changes one thing and runs the checker there as a subprocess, so the
real tree is never modified."""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IGNORE = shutil.ignore_patterns("target", "target-*", "node_modules", "__pycache__", ".git")
APPROVED = {
    "holochain-mpc-core": "crates/mpc-core",
    "holochain-mpc-frost-ed25519": "crates/mpc-frost-ed25519",
    "holochain-mpc-security": "crates/mpc-security",
    "holochain-mpc-runtime": "crates/mpc-runtime",
    "holochain-mpc-dkg-worker": "crates/mpc-dkg-worker",
    "holochain-mpc-vault": "crates/mpc-vault",
    "holochain-mpc-adapter": "adapters/holochain-0.7",
    "mpc_integrity": "dnas/mpc/zomes/integrity/mpc_integrity",
    "mpc": "dnas/mpc/zomes/coordinator/mpc",
}


class CheckRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "tree"
        shutil.copytree(ROOT, self.root, ignore=IGNORE, symlinks=True)

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, *args: str) -> tuple[int, str]:
        p = subprocess.run([sys.executable, "-I", str(self.root / "scripts/check_release.py"), *args],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def edit(self, rel: str, old: str, new: str):
        path = self.root / rel
        text = path.read_text()
        self.assertEqual(text.count(old), 1, f"{rel}: {old!r}")
        path.write_text(text.replace(old, new))

    def assertFails(self, *expected: str) -> str:
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        for line in expected:
            self.assertIn(f"FAIL: {line}", out)
        return out

    def test_inventory_lists_the_nine_approved_packages(self):
        inventory = json.loads((ROOT / "scripts/release_inventory.json").read_text())
        self.assertEqual({n: p["path"] for n, p in inventory["packages"].items()}, APPROVED)
        self.assertEqual(inventory["workspace"]["members"], [
            "crates/mpc-core", "crates/mpc-frost-ed25519", "crates/mpc-security", "crates/mpc-runtime",
            "crates/mpc-dkg-worker", "crates/mpc-vault", "adapters/holochain-0.7",
            "dnas/mpc/zomes/integrity/mpc_integrity", "dnas/mpc/zomes/coordinator/mpc"])

    def test_approved_nine_package_workspace_passes(self):
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS: 9 Cargo packages match the approved inventory", out)

    def test_missing_required_package_fails(self):
        self.edit("Cargo.toml", '  "crates/mpc-vault",\n', "")
        self.assertFails("missing approved package: holochain-mpc-vault (crates/mpc-vault)",
                         "workspace members differ")

    def test_removed_package_directory_fails(self):
        shutil.rmtree(self.root / "crates/mpc-vault")
        self.assertFails("workspace path missing: crates/mpc-vault",
                         "missing approved package: holochain-mpc-vault (crates/mpc-vault)")

    def test_unexpected_package_fails(self):
        extra = self.root / "crates/mpc-extra"
        (extra / "src").mkdir(parents=True)
        (extra / "src/lib.rs").write_text("")
        (extra / "Cargo.toml").write_text('[package]\nname = "holochain-mpc-extra"\nversion = "0.1.0"\nedition = "2021"\n')
        self.edit("Cargo.toml", '  "crates/mpc-vault",\n', '  "crates/mpc-vault",\n  "crates/mpc-extra",\n')
        out = self.assertFails("unexpected workspace package: holochain-mpc-extra (crates/mpc-extra)")
        self.assertNotIn("missing approved package", out)

    def test_renamed_package_fails(self):
        self.edit("crates/mpc-vault/Cargo.toml", 'name = "holochain-mpc-vault"', 'name = "holochain-mpc-safe"')
        self.assertFails("renamed package at crates/mpc-vault: approved holochain-mpc-vault, found holochain-mpc-safe")

    def test_changed_and_added_dependencies_fail(self):
        self.edit("crates/mpc-vault/Cargo.toml", 'serde_json = "1.0"\n', 'serde_json = "1.0.200"\nhex = "0.4"\n')
        self.assertFails('holochain-mpc-vault: [dependencies] serde_json changed: approved "1.0", found "1.0.200"',
                         'holochain-mpc-vault: [dependencies] unapproved dependency hex = "0.4"')

    def test_workspace_dependency_pin_change_fails(self):
        self.edit("Cargo.toml", 'hdk = "=0.7.1"', 'hdk = "=0.7.2"')
        self.assertFails('workspace: [workspace.dependencies] hdk changed: approved "=0.7.1", found "=0.7.2"')

    def test_package_version_change_fails(self):
        self.edit("crates/mpc-vault/Cargo.toml", 'version = "0.1.0"', 'version = "0.2.0"')
        self.assertFails("holochain-mpc-vault: version '0.2.0', approved '0.1.0'")

    def test_other_manifest_drift_fails(self):
        self.edit("crates/mpc-vault/Cargo.toml", 'edition = "2021"', 'edition = "2024"')
        self.assertFails("holochain-mpc-vault: crates/mpc-vault/Cargo.toml changed "
                         "(manifest drift outside version and dependencies)")

    def test_lockfile_change_fails_and_names_the_package(self):
        self.edit("Cargo.lock", 'name = "bs58"\nversion = "0.5.1"', 'name = "bs58"\nversion = "0.5.0"')
        self.assertFails("Cargo.lock differs from the approved lockfile: added bs58 0.5.0; removed bs58 0.5.1")

    def test_missing_inventory_fails_closed(self):
        (self.root / "scripts/release_inventory.json").unlink()
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL: cannot read scripts/release_inventory.json", out)

    def test_recording_needs_confirmation(self):
        before = (self.root / "scripts/release_inventory.json").read_bytes()
        rc, out = self.check("--record-inventory")
        self.assertEqual(rc, 1, out)
        self.assertIn("refusing", out)
        self.assertEqual((self.root / "scripts/release_inventory.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
