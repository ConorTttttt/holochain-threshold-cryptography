#!/usr/bin/env python3
"""Dependency-path and manifest sanity checks; NOT a Rust compiler or security audit."""
from __future__ import annotations
import json
from pathlib import Path
import tomllib
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())
errors = []
packages = []
for member in workspace['workspace']['members']:
    cargo_path = ROOT / member / 'Cargo.toml'
    if not cargo_path.exists():
        errors.append(f'workspace path missing: {member}')
        continue
    data = tomllib.loads(cargo_path.read_text())
    packages.append(data['package']['name'])
    for dep, cfg in data.get('dependencies', {}).items():
        if isinstance(cfg, dict) and 'path' in cfg:
            path = (cargo_path.parent / cfg['path'] / 'Cargo.toml').resolve()
            if not path.is_file():
                errors.append(f'{member} missing {dep} dependency path {path}')
if len(packages) != len(set(packages)):
    errors.append('duplicate package name')
expected = {'holochain-mpc-core', 'holochain-mpc-frost-ed25519',
            'holochain-mpc-adapter', 'holochain-mpc-security', 'holochain-mpc-runtime', 'holochain-mpc-dkg-worker', 'mpc', 'mpc_integrity'}
if set(packages) != expected:
    errors.append(f'wrong package inventory: {packages}')
package = json.loads((ROOT / 'package.json').read_text())
if package['version'] != '0.3.5':
    errors.append('package version mismatch')
for yml in ['workdir/happ.yaml', 'dnas/mpc/workdir/dna.yaml']:
    d = yaml.safe_load((ROOT / yml).read_text())
    if d.get('manifest_version') != '0':
        errors.append(f'manifest version mismatch: {yml}')
    if not d.get('name'):
        errors.append(f'missing name: {yml}')
for file in ['crates/mpc-frost-ed25519/src/lib.rs',
             'crates/mpc-frost-ed25519/tests/three_agents.rs',
             'docs/FROST_PROVIDER.md',
             'crates/mpc-security/src/lib.rs',
             'crates/mpc-security/src/sealed.rs',
             'crates/mpc-security/tests/security_protocol.rs',
             'docs/SECURITY_PROTOCOL.md',
             'crates/mpc-runtime/src/lib.rs',
             'crates/mpc-runtime/tests/durable.rs',
             'crates/mpc-security/src/activation.rs',
             'crates/mpc-security/tests/group_activation.rs',
             'docs/V032_SECURITY_DESIGN.md',
             'docs/V033_DKG_RESEARCH_UPGRADE.md',
             'docs/V034_LIVE_DKG_INTEGRATION.md',
             'dnas/mpc/zomes/coordinator/mpc/tests/dkg_live.rs',
             'crates/mpc-dkg-worker/src/lib.rs',
             'crates/mpc-dkg-worker/src/main.rs',
             'crates/mpc-dkg-worker/tests/three_processes.rs',
             'docs/V035_PROCESS_ISOLATED_DKG.md']:
    if not (ROOT / file).is_file():
        errors.append(f'missing file: {file}')
if errors:
    for err in errors:
        print('FAIL:', err)
    sys.exit(1)
print('PASS: 8 Cargo packages; dependency paths; YAML and JSON; source inventory')
print('NOTE: cargo/rustc/hc compilation and tests NOT exercised by this check')
