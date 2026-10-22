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
if package['version'] != '0.4.0':
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
             'docs/V035_PROCESS_ISOLATED_DKG.md',
             'crates/mpc-dkg-worker/src/ipc.rs',
             'crates/mpc-dkg-worker/tests/ipc_process.rs',
             'docs/V036_AUTHENTICATED_NODE_IPC.md',
             'crates/mpc-runtime/src/dkg.rs',
             'crates/mpc-runtime/tests/dkg_journal.rs',
             'crates/mpc-dkg-worker/tests/dkg_restart.rs',
             'docs/V037_DKG_CRASH_SAFETY.md',
             'crates/mpc-dkg-worker/src/node_service.rs',
             'crates/mpc-dkg-worker/src/node_main.rs',
             'crates/mpc-dkg-worker/tests/node_service.rs',
             'docs/V038_INDEPENDENT_NODE_SERVICE.md',
             'crates/mpc-dkg-worker/src/conductor_bridge.rs',
             'crates/mpc-dkg-worker/tests/conductor_bridge.rs',
             'docs/V039_CONDUCTOR_BRIDGE.md',
             'crates/mpc-dkg-worker/src/connection_policy.rs',
             'crates/mpc-dkg-worker/src/conductor_client.rs',
             'crates/mpc-dkg-worker/src/conductor_connect_main.rs',
             'docs/V040_APP_WEBSOCKET_PREFLIGHT.md',
             'crates/mpc-dkg-worker/src/signed_call_policy.rs',
             'crates/mpc-dkg-worker/src/conductor_call_main.rs',
             'docs/V040_SIGNED_ZOME_CALLS_PHASE2.md',
             'crates/mpc-dkg-worker/src/relay.rs',
             'crates/mpc-dkg-worker/src/signed_relay.rs',
             'crates/mpc-dkg-worker/tests/relay_simulation.rs',
             'docs/V040_AUTOMATIC_DKG_RELAY_PHASE3.md',
             'crates/mpc-dkg-worker/src/relay_supervisor.rs',
             'crates/mpc-dkg-worker/src/socket_signer.rs',
             'crates/mpc-dkg-worker/src/relay_service_main.rs',
             'docs/V040_RELAY_SERVICE_PHASE4.md',
             'crates/mpc-dkg-worker/src/lair_signer.rs',
             'crates/mpc-dkg-worker/src/lair_signer_main.rs',
             'docs/V040_LAIR_SIGNER_PHASE5A.md',
             'crates/mpc-dkg-worker/src/lair_live_probe_main.rs',
             'docs/V040_LAIR_LIVE_PROBE_PHASE5B.md',
             'crates/mpc-dkg-worker/src/phase5b_bootstrap_main.rs',
             'scripts/phase5b_preflight.py',
             'docs/V040_PHASE5B_BOOTSTRAP.md',
             'crates/mpc-dkg-worker/src/capability_exchange.rs',
             'crates/mpc-dkg-worker/src/phase5c_provision_main.rs',
             'crates/mpc-dkg-worker/tests/capability_provisioning.rs',
             'docs/V040_PHASE5C_B_PROVISIONING.md',
             'crates/mpc-dkg-worker/src/transport_probe.rs',
             'crates/mpc-dkg-worker/src/probe_signer.rs',
             'crates/mpc-dkg-worker/src/transport_probe_main.rs',
             'crates/mpc-dkg-worker/tests/transport_probe.rs',
             'crates/mpc-runtime/src/probe.rs',
             'docs/V040_PHASE5C_C_TRANSPORT_PROBE.md',
             'docs/V040_PHASE5C_C_OFFLINE_REPORT.md',
             'scripts/check_wasm_imports.py',
             'scripts/phase5c_b_audit.sh']:
    if not (ROOT / file).is_file():
        errors.append(f'missing file: {file}')
if errors:
    for err in errors:
        print('FAIL:', err)
    sys.exit(1)
print('PASS: 8 Cargo packages; dependency paths; YAML and JSON; source inventory')
print('NOTE: cargo/rustc/hc compilation and tests NOT exercised by this check')
