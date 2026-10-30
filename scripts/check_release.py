#!/usr/bin/env python3
"""Dependency-path and manifest sanity checks; NOT a Rust compiler or security audit.

The workspace is compared with the approved inventory in
scripts/release_inventory.json: the ordered member list, every package's name,
path and version, its dependency tables, a hash of every member manifest, the
`Cargo.lock` hash and package list, and the shipped binaries. Any difference is
reported by name. Approving a change means reviewing it and then re-recording
with `--record-inventory --confirm-record` (an operator action, like
`release_check.py --record`).

Usage:
  python3 -I scripts/check_release.py [--root DIR]
  python3 -I scripts/check_release.py --record-inventory --confirm-record
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import tomllib
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "scripts/release_inventory.json"
SCHEMA = 1
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
SOURCE_FILES = [
    'crates/mpc-frost-ed25519/src/lib.rs',
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
    'scripts/phase5c_b_audit.sh',
    'crates/mpc-dkg-worker/tests/share_custody.rs',
    'docs/V040_PHASE7_SHARE_CUSTODY.md',
    'scripts/phase6_rehearsal.py',
    'docs/V040_PHASE6_REHEARSAL.md',
    'crates/mpc-dkg-worker/src/signing.rs',
    'crates/mpc-dkg-worker/src/signing_signer.rs',
    'crates/mpc-dkg-worker/src/sign_main.rs',
    'crates/mpc-dkg-worker/tests/signing_session.rs',
    'docs/V040_PHASE8_SIGNING.md',
    'docs/V040_SECURITY_REVIEW_2026-10-22.md',
    'docs/security-profile.yaml',
    'SECURITY.md',
    'docs/THREAT_MODEL.md',
    'docs/V040_RELEASE_HARDENING.md',
    'scripts/release_check.py',
    'scripts/release_hashes.json',
    'crates/mpc-dkg-worker/src/notice.rs',
    'crates/mpc-security/tests/wire_validation.rs',
    'crates/mpc-dkg-worker/tests/input_validation.rs',
    # Phase 7 custody hardening (Agent 2)
    'crates/mpc-runtime/src/custody.rs',
    'crates/mpc-runtime/src/bin/mpc-custody.rs',
    'scripts/custody_check.sh',
    'docs/V040_PHASE7_CUSTODY_HARDENING.md',
    # Phase 6/8 fault injection (Agent 3, Stage 2A)
    'scripts/phase6_faults.py',
    'scripts/faults_env.py',
    'scripts/faults_scenarios.py',
    'scripts/faults_signing.py',
    'scripts/faults_portfwd.py',
    'docs/V040_PHASE6_FAULT_TESTS.md',
    'docs/V040_STAGE2A_PARTITION_HARNESS_FIX.md',
    # vault service (Agent 5)
    'crates/mpc-vault/src/lib.rs',
    'crates/mpc-vault/src/main.rs',
    'crates/mpc-vault/src/engine.rs',
    'crates/mpc-vault/tests/state_machine.rs',
    'crates/mpc-vault/tests/http_api.rs',
    'docs/V040_VAULT_APP.md',
    # release validation (Stage 2B)
    INVENTORY,
    'scripts/tests/test_check_release.py',
    'scripts/tests/test_release_check.py',
    'crates/mpc-runtime/tests/cli_notice.rs',
    'crates/mpc-vault/tests/cli_notice.rs',
    'docs/V040_STAGE2B_RELEASE_VALIDATION.md',
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependency_tables(manifest: dict) -> dict:
    """Every dependency table of a manifest, target-specific ones included."""
    tables = {t: manifest[t] for t in DEP_TABLES if t in manifest}
    for target, cfg in sorted(manifest.get('target', {}).items()):
        for t in DEP_TABLES:
            if t in cfg:
                tables[f'target.{target}.{t}'] = cfg[t]
    return tables


def lock_packages(lock_text: str) -> list[str]:
    lock = tomllib.loads(lock_text)
    return sorted(f"{p['name']} {p['version']}" + ("" if 'source' in p else " (workspace)")
                  for p in lock.get('package', []))


def measure(root: Path) -> tuple[dict, list[str]]:
    """The workspace as it is on disk, in the inventory's shape, plus structural errors."""
    errors: list[str] = []
    workspace = tomllib.loads((root / 'Cargo.toml').read_text())
    ws = workspace['workspace']
    state = {
        'workspace': {'members': ws.get('members', []), 'default_members': ws.get('default-members', []),
                      'resolver': ws.get('resolver'), 'dependencies': ws.get('dependencies', {}),
                      'manifest_sha256': sha256(root / 'Cargo.toml')},
        'packages': {},
    }
    for member in ws.get('members', []):
        cargo_path = root / member / 'Cargo.toml'
        if not cargo_path.exists():
            errors.append(f'workspace path missing: {member}')
            continue
        data = tomllib.loads(cargo_path.read_text())
        name = data['package']['name']
        if name in state['packages']:
            errors.append(f'duplicate package name: {name}')
        for table, deps in dependency_tables(data).items():
            for dep, cfg in deps.items():
                if isinstance(cfg, dict) and 'path' in cfg:
                    path = (cargo_path.parent / cfg['path'] / 'Cargo.toml').resolve()
                    if not path.is_file():
                        errors.append(f'{member} missing {dep} dependency path {path}')
        state['packages'][name] = {'path': member, 'version': data['package'].get('version'),
                                   'dependencies': dependency_tables(data), 'manifest_sha256': sha256(cargo_path)}
    lock = root / 'Cargo.lock'
    state['cargo_lock'] = {'sha256': sha256(lock), 'packages': lock_packages(lock.read_text())}
    return state, errors


def _diff_deps(name: str, approved: dict, found: dict) -> list[str]:
    out = []
    for table in sorted(set(approved) | set(found)):
        a, f = approved.get(table, {}), found.get(table, {})
        for dep in sorted(set(a) | set(f)):
            if dep not in f:
                out.append(f'{name}: [{table}] {dep} removed (approved {json.dumps(a[dep])})')
            elif dep not in a:
                out.append(f'{name}: [{table}] unapproved dependency {dep} = {json.dumps(f[dep])}')
            elif a[dep] != f[dep]:
                out.append(f'{name}: [{table}] {dep} changed: approved {json.dumps(a[dep])}, found {json.dumps(f[dep])}')
    return out


def inventory_problems(state: dict, inventory: dict) -> list[str]:
    """Every difference between the measured workspace and the approved inventory."""
    problems = []
    aw, fw = inventory['workspace'], state['workspace']
    if fw['members'] != aw['members']:
        problems.append(f"workspace members differ: approved {aw['members']}, found {fw['members']}")
    for key in ('default_members', 'resolver'):
        if fw[key] != aw[key]:
            problems.append(f'workspace {key} differs: approved {aw[key]!r}, found {fw[key]!r}')
    problems += _diff_deps('workspace', {'workspace.dependencies': aw['dependencies']},
                           {'workspace.dependencies': fw['dependencies']})
    if fw['manifest_sha256'] != aw['manifest_sha256'] and not problems:
        problems.append('workspace Cargo.toml changed (manifest drift outside members and dependencies)')

    approved, found = inventory['packages'], state['packages']
    by_path = {p['path']: n for n, p in found.items()}
    for name, want in approved.items():
        if name in found:
            continue
        other = by_path.get(want['path'])
        if other:
            problems.append(f"renamed package at {want['path']}: approved {name}, found {other}")
        else:
            problems.append(f"missing approved package: {name} ({want['path']})")
    approved_paths = {p['path'] for p in approved.values()}
    for name, got in found.items():
        if name not in approved and got['path'] not in approved_paths:
            problems.append(f"unexpected workspace package: {name} ({got['path']})")
    for name in sorted(set(approved) & set(found)):
        want, got = approved[name], found[name]
        if got['path'] != want['path']:
            problems.append(f"{name}: moved from {want['path']} to {got['path']}")
        if got['version'] != want['version']:
            problems.append(f"{name}: version {got['version']!r}, approved {want['version']!r}")
        dep_problems = _diff_deps(name, want['dependencies'], got['dependencies'])
        problems += dep_problems
        if got['manifest_sha256'] != want['manifest_sha256'] and not dep_problems and got['version'] == want['version']:
            problems.append(f"{name}: {got['path']}/Cargo.toml changed (manifest drift outside version and dependencies)")

    al, fl = inventory['cargo_lock'], state['cargo_lock']
    if fl['sha256'] != al['sha256']:
        added = sorted(set(fl['packages']) - set(al['packages']))
        removed = sorted(set(al['packages']) - set(fl['packages']))
        detail = '; '.join(filter(None, [f"added {', '.join(added)}" if added else '',
                                         f"removed {', '.join(removed)}" if removed else '']))
        problems.append('Cargo.lock differs from the approved lockfile' + (f': {detail}' if detail else
                        ' (same package versions; checksums, sources or dependency edges changed)'))
    return problems


def static_problems(root: Path) -> list[str]:
    errors = []
    package = json.loads((root / 'package.json').read_text())
    if package['version'] != '0.4.0':
        errors.append('package version mismatch')
    for yml in ['workdir/happ.yaml', 'dnas/mpc/workdir/dna.yaml']:
        d = yaml.safe_load((root / yml).read_text())
        if d.get('manifest_version') != '0':
            errors.append(f'manifest version mismatch: {yml}')
        if not d.get('name'):
            errors.append(f'missing name: {yml}')
    for file in SOURCE_FILES:
        if not (root / file).is_file():
            errors.append(f'missing file: {file}')
    return errors


def check(root: Path) -> tuple[list[str], int]:
    """(errors, number of approved packages)."""
    try:
        inventory = json.loads((root / INVENTORY).read_text())
    except (OSError, ValueError) as e:
        return [f'cannot read {INVENTORY}: {e}'], 0
    if inventory.get('schema') != SCHEMA:
        return [f'{INVENTORY} schema is not {SCHEMA}'], 0
    state, errors = measure(root)
    errors += inventory_problems(state, inventory)
    errors += static_problems(root)
    return errors, len(inventory['packages'])


def record(root: Path) -> None:
    """Write the inventory from the tree as it is. Keeps the reviewed binary list."""
    path = root / INVENTORY
    old = json.loads(path.read_text()) if path.exists() else {}
    state, errors = measure(root)
    if errors:
        raise SystemExit('not recording: ' + '; '.join(errors))
    doc = {'schema': SCHEMA,
           'note': ('Approved workspace inventory (scripts/check_release.py). Re-record with '
                    '--record-inventory --confirm-record only after reviewing the change.'),
           **state, 'binaries': old.get('binaries', {})}
    path.write_text(json.dumps(doc, indent=2) + '\n')
    print(f'recorded {INVENTORY}: {len(state["packages"])} packages, {len(state["cargo_lock"]["packages"])} lock entries')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', type=Path, default=ROOT)
    ap.add_argument('--record-inventory', action='store_true')
    ap.add_argument('--confirm-record', action='store_true')
    a = ap.parse_args()
    root = a.root.resolve()
    if a.record_inventory:
        if not a.confirm_record:
            print('refusing: --record-inventory needs --confirm-record', file=sys.stderr)
            return 1
        record(root)
        return 0
    errors, count = check(root)
    if errors:
        for err in errors:
            print('FAIL:', err)
        return 1
    print(f'PASS: {count} Cargo packages match the approved inventory; dependency paths; YAML and JSON; source inventory')
    print('NOTE: cargo/rustc/hc compilation and tests NOT exercised by this check')
    return 0


if __name__ == '__main__':
    sys.exit(main())
