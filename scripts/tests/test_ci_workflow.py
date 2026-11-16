"""Offline policy/syntax regression checks for the GitHub Actions CI workflow.

These checks do not execute GitHub Actions, Nix, Cargo, or Holochain.
"""
from __future__ import annotations

import subprocess
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class CiWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # BaseLoader preserves the YAML 1.1-sensitive 'on' key as a string.
        cls.document = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)

    @classmethod
    def commands(cls):
        for name, job in cls.document["jobs"].items():
            for step in job["steps"]:
                if "run" in step:
                    yield name, step["run"]

    def test_expected_event_and_job_split(self):
        triggers = self.document["on"]
        self.assertEqual(set(triggers), {"pull_request", "push", "workflow_dispatch"})
        self.assertEqual(set(self.document["jobs"]),
                         {"static", "native", "integration", "release"})
        self.assertEqual(triggers["workflow_dispatch"]["inputs"]["suite"]["options"],
                         ["quick", "integration", "release", "all"])
        self.assertIn("github.event_name == 'workflow_dispatch'",
                      self.document["jobs"]["release"]["if"])
        self.assertIn("github.event_name == 'push'",
                      self.document["jobs"]["integration"]["if"])

    def test_no_automatic_artifact_approval_or_deployment(self):
        joined = "\n".join(command for _, command in self.commands())
        self.assertNotIn("--record", joined)
        self.assertNotIn("--confirm-record", joined)
        self.assertNotIn("update_coordinators", joined)
        self.assertNotIn("secrets.", WORKFLOW.read_text())
        self.assertIn("npm run check:release",
                      "\n".join(c for j, c in self.commands() if j == "release"))
        self.assertIn("git diff --exit-code -- Cargo.lock scripts/release_inventory.json scripts/release_hashes.json",
                      joined)

    def test_sdk_absence_is_not_mislabeled_a_pass(self):
        commands = "\n".join(c for j, c in self.commands() if j == "native")
        self.assertIn("if test -f crates/holochain-dkg-sdk/Cargo.toml; then", commands)
        self.assertIn("cargo test --offline --locked -p holochain-dkg-sdk --all-targets", commands)
        self.assertIn("cargo test --offline --locked -p holochain-dkg-sdk --all-targets --features native-holochain", commands)
        self.assertIn("NOT RUN: SDK crate is not yet on this branch", commands)

    def test_privileged_live_write_example_requires_opt_in_feature(self):
        manifest_path = ROOT / "crates/mpc-dkg-worker/Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text())
        declared = [example for example in manifest.get("example", [])
                    if example.get("name") == "phase5c_live_writes"]
        self.assertEqual(len(declared), 1)
        self.assertIn("lair-signer", declared[0].get("required-features", []))
        commands = "\n".join(c for j, c in self.commands() if j == "native")
        self.assertIn(
            "cargo check --offline --locked -p holochain-mpc-dkg-worker --features lair-signer --example phase5c_live_writes",
            commands)
        self.assertNotIn("cargo run", commands)

    def test_all_shell_steps_have_valid_bash_syntax(self):
        for job, command in self.commands():
            with self.subTest(job=job, command=command[:60]):
                proc = subprocess.run(["bash", "-n", "-c", command],
                                      capture_output=True, text=True, check=False)
                self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
