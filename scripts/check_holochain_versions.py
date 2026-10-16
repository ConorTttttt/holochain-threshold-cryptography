#!/usr/bin/env python3
"""Fail on inconsistent Holochain 0.7.1 app/test dependency pins.

This is a static check, NOT a Rust compilation or security audit.
If Cargo.lock exists, also check core-family transitive crate versions.
"""
from __future__ import annotations
from pathlib import Path
import tomllib
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

def load(rel):
    return tomllib.loads((ROOT / rel).read_text())

root = load("Cargo.toml")
ws = root["workspace"]["dependencies"]
for name, want in (("hdk", "=0.7.1"), ("hdi", "=0.8.1"),
                   ("holochain_serialized_bytes", "=0.0.57")):
    if ws.get(name) != want:
        errors.append(f"root {name} is {ws.get(name)!r}; expected {want!r}")

adapter = load("adapters/holochain-0.7/Cargo.toml")
if adapter["dependencies"].get("hdk") != {"workspace": True}:
    errors.append("adapter must use workspace hdk")

integrity = load("dnas/mpc/zomes/integrity/mpc_integrity/Cargo.toml")
if integrity["dependencies"].get("hdi") != {"workspace": True}:
    errors.append("integrity must use workspace hdi")
if integrity["dependencies"].get("holochain_serialized_bytes") != {"workspace": True}:
    errors.append("integrity must use workspace holochain_serialized_bytes")

coordinator = load("dnas/mpc/zomes/coordinator/mpc/Cargo.toml")
if coordinator["dependencies"].get("hdk") != {"workspace": True}:
    errors.append("coordinator must use workspace hdk")
if coordinator["dev-dependencies"]["holochain"].get("version") != "=0.7.1":
    errors.append("Sweettest holochain must be exactly 0.7.1")

lockfile = ROOT / "Cargo.lock"
if lockfile.exists():
    lock = tomllib.loads(lockfile.read_text())
    family = {
        "holochain", "hdk", "hdk_derive", "holochain_conductor_api",
        "holochain_integrity_types", "holochain_types", "holochain_zome_types",
        "holochain_state", "holochain_keystore", "holochain_test_wasm_common",
        "holochain_cascade", "holo_hash", "holochain_conductor_config",
    }
    for package in lock.get("package", []):
        name = package["name"]
        if name in family and package["version"] != "0.7.1":
            errors.append(f"Cargo.lock {name}={package['version']}, expected 0.7.1")
        if name == "hdi" and package["version"] != "0.8.1":
            errors.append(f"Cargo.lock hdi={package['version']}, expected 0.8.1")

if errors:
    for message in errors:
        print("FAIL:", message)
    sys.exit(1)
print("PASS: Holochain app/Sweettest/HDK/HDI version pins align")
print("NOTE: Rust compilation, Holochain conductor and protocol security not verified here")
