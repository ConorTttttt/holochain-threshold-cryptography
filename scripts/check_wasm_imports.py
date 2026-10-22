#!/usr/bin/env python3
"""Fail if a built zome WASM imports anything but Holochain 0.7.1 host functions.

Rust 1.96+ zome builds pass `-C link-arg=--allow-undefined` so the intended
`env.__hc__*` host imports link. That flag also accepts ACCIDENTAL undefined
symbols (for example a `getrandom` or `wasm-bindgen` shim) and turns them into
imports the conductor cannot satisfy or should not provide. This script parses
each module's import section and allows only function imports from `env`
whose names the Holochain 0.7.1 ribosome registers.

This is a static check of built artifacts, NOT a WASM provenance or security
audit. Build first with `npm run build:zomes`.

Usage: python3 -I scripts/check_wasm_imports.py [--verify-against real_ribosome.rs] [WASM ...]
"""
from __future__ import annotations
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WASM = [
    ROOT / "target/wasm32-unknown-unknown/release/mpc.wasm",
    ROOT / "target/wasm32-unknown-unknown/release/mpc_integrity.wasm",
]

# Host functions registered by holochain 0.7.1 src/core/ribosome/real_ribosome.rs,
# excluding the guest-exported allocate/deallocate. Regenerate on any SDK bump.
HOLOCHAIN_0_7_1_HOST_FUNCTIONS = frozenset("""
__hc__accept_countersigning_preflight_request_1 __hc__agent_info_1 __hc__call_1
__hc__call_info_1 __hc__capability_claims_1 __hc__capability_grants_1
__hc__capability_info_1 __hc__close_chain_1 __hc__count_links_1 __hc__create_1
__hc__create_clone_cell_1 __hc__create_link_1 __hc__create_x25519_keypair_1
__hc__delete_1 __hc__delete_clone_cell_1 __hc__delete_link_1
__hc__disable_clone_cell_1 __hc__dna_info_1 __hc__dna_info_2
__hc__ed_25519_x_salsa20_poly1305_decrypt_1 __hc__ed_25519_x_salsa20_poly1305_encrypt_1
__hc__emit_signal_1 __hc__enable_clone_cell_1 __hc__get_1 __hc__get_agent_activity_1
__hc__get_details_1 __hc__get_init_properties_1 __hc__get_links_1
__hc__get_links_details_1 __hc__get_validation_receipts_1 __hc__must_get_action_1
__hc__must_get_agent_activity_1 __hc__must_get_entry_1 __hc__must_get_valid_record_1
__hc__open_chain_1 __hc__query_1 __hc__random_bytes_1 __hc__schedule_1
__hc__send_remote_signal_1 __hc__sign_1 __hc__sign_ephemeral_1 __hc__sleep_1
__hc__sys_time_1 __hc__trace_1 __hc__update_1 __hc__verify_signature_1
__hc__x_25519_x_salsa20_poly1305_decrypt_1 __hc__x_25519_x_salsa20_poly1305_encrypt_1
__hc__x_salsa20_poly1305_decrypt_1 __hc__x_salsa20_poly1305_encrypt_1
__hc__x_salsa20_poly1305_shared_secret_create_random_1
__hc__x_salsa20_poly1305_shared_secret_export_1
__hc__x_salsa20_poly1305_shared_secret_ingest_1 __hc__zome_info_1
""".split())
GUEST_EXPORTS = frozenset({"__hc__allocate_1", "__hc__deallocate_1"})
KINDS = {0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"}


def leb(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, i


def name(data: bytes, i: int) -> tuple[str, int]:
    n, i = leb(data, i)
    return data[i:i + n].decode("utf-8"), i + n


def skip_limits(data: bytes, i: int) -> int:
    flags, i = leb(data, i)
    _, i = leb(data, i)
    if flags & 1:
        _, i = leb(data, i)
    return i


def imports(path: Path) -> list[tuple[str, str, str]]:
    data = path.read_bytes()
    if data[:4] != b"\0asm" or data[4:8] != b"\1\0\0\0":
        raise ValueError("not a version-1 WebAssembly module")
    found, i = [], 8
    while i < len(data):
        section = data[i]
        size, i = leb(data, i + 1)
        end = i + size
        if section == 2:
            count, j = leb(data, i)
            for _ in range(count):
                module, j = name(data, j)
                field, j = name(data, j)
                kind = data[j]
                j += 1
                if kind == 0:
                    _, j = leb(data, j)
                elif kind == 1:
                    j = skip_limits(data, j + 1)
                elif kind == 2:
                    j = skip_limits(data, j)
                elif kind == 3:
                    j += 2
                elif kind == 4:
                    j += 1
                    _, j = leb(data, j)
                else:
                    raise ValueError(f"unknown import kind {kind}")
                found.append((module, field, KINDS[kind]))
        i = end
    return found


def main(argv: list[str]) -> int:
    allowed = HOLOCHAIN_0_7_1_HOST_FUNCTIONS
    if argv[:1] == ["--verify-against"]:
        source = Path(argv[1]).read_text()
        registered = set(re.findall(r'"(__hc__[a-z0-9_]+)"', source)) - GUEST_EXPORTS
        if registered != allowed:
            print("FAIL: embedded host-function list differs from", argv[1])
            print("  missing:", sorted(registered - allowed))
            print("  extra:  ", sorted(allowed - registered))
            return 1
        argv = argv[2:]
    errors = []
    for path in [Path(a) for a in argv] or DEFAULT_WASM:
        try:
            found = imports(path)
        except (OSError, ValueError, IndexError, UnicodeDecodeError) as e:
            errors.append(f"{path}: cannot parse ({e})")
            continue
        bad = [f"{m}.{f} ({k})" for m, f, k in found
               if m != "env" or k != "function" or f not in allowed]
        errors += [f"{path.name}: unexpected import {b}" for b in bad]
        if not bad:
            print(f"PASS: {path.name} imports {len(found)} Holochain 0.7.1 host functions only")
    for e in errors:
        print("FAIL:", e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
