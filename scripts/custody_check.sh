#!/usr/bin/env bash
# v0.4.0 Phase 7 hardening: read-only custody audit of one node state directory.
#
#   scripts/custody_check.sh <absolute-state-dir> [--lair-root <dir>] [--conductor-root <dir>]
#
# Checks ownership, modes, links and placement of the custody files, the
# master-key source and the anti-rollback anchor named in custody.json, and
# that the Lair and conductor roots (if given) belong to other users.
#
# It never writes, never needs the master key and never starts a project
# binary. Its journal/anchor comparison is therefore UNAUTHENTICATED;
# `mpc-custody verify <state-dir>` authenticates both with the key.
# Run it as the custody user or root. Exit 0: no FAIL; 1: a FAIL; 2: usage.
# Development evidence, not production custody, not an independent audit.
set -uo pipefail
export LC_ALL=C

fails=0
warns=0
pass() { printf 'PASS %s\n' "$*"; }
info() { printf 'INFO %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; warns=$((warns + 1)); }
fail() { printf 'FAIL %s\n' "$*"; fails=$((fails + 1)); }
usage() { echo "usage: $0 <absolute-state-dir> [--lair-root <dir>] [--conductor-root <dir>]" >&2; exit 2; }
finish() {
  printf 'custody_check: %d FAIL, %d WARN\n' "$fails" "$warns"
  echo "Read-only audit. Development evidence, not production custody, not an independent audit."
  [ "$fails" -eq 0 ] && exit 0
  exit 1
}

[ $# -ge 1 ] || usage
state=${1%/}
shift
other_roots=()
while [ $# -gt 0 ]; do
  case $1 in
    --lair-root | --conductor-root) [ $# -ge 2 ] || usage; other_roots+=("$2"); shift 2 ;;
    *) usage ;;
  esac
done
case $state in /?*) ;; *) usage ;; esac

# owner uid, group gid, octal mode (with special bits), link count, file type
meta() { stat -c '%u %g %a %h %F' -- "$1" 2>/dev/null; }

if [ -L "$state" ] || ! m=$(meta "$state"); then
  fail "$state is missing or a symlink"
  finish
fi
read -r custody_uid custody_gid mode _ type <<<"$m"
if [ "$type" != directory ]; then fail "$state is not a directory"; finish; fi
if [ "$custody_uid" = 0 ]; then
  fail "state directory is owned by root; custody must run as a dedicated user"
else
  pass "state directory owned by uid $custody_uid (the custody user)"
fi
if [ $((8#$mode & 8#777)) -eq $((8#700)) ]; then pass "state directory mode 0700"; else fail "state directory mode $mode (want 0700)"; fi

# Every ancestor, lexical and resolved, must be owned by root or the custody
# user. Others may not write to it unless it is root-owned and sticky (/tmp);
# group write is tolerated, with a warning, only for the custody user's own
# group (a umask-0002 user-private group). Same rule as `Custody::load`.
ancestors() {
  local label=$1 start dir u g mo bits bad=0 seen=" "
  for start in "$(dirname -- "$2")" "$(readlink -f -- "$(dirname -- "$2")" 2>/dev/null)"; do
    dir=$start
    while [ -n "$dir" ]; do
      case $seen in *" $dir "*) break ;; esac
      seen+="$dir "
      if ! m=$(meta "$dir"); then fail "$label: cannot stat ancestor $dir"; bad=1; break; fi
      read -r u g mo _ _ <<<"$m"
      bits=$((8#$mo))
      if [ "$u" != 0 ] && [ "$u" != "$custody_uid" ]; then
        fail "$label: ancestor $dir is owned by uid $u, who could rename it"; bad=1
      elif (( bits & 8#1000 )) && [ "$u" = 0 ]; then
        :
      elif (( bits & 8#002 )); then
        fail "$label: ancestor $dir (mode $mo) is writable by others"; bad=1
      elif (( bits & 8#020 )) && [ "$g" != "$custody_gid" ]; then
        fail "$label: ancestor $dir (mode $mo) is writable by group $g"; bad=1
      elif (( bits & 8#020 )); then
        warn "$label: ancestor $dir (mode $mo) is writable by the custody user's group $g; keep that group private"
      fi
      [ "$dir" = / ] && break
      dir=$(dirname -- "$dir")
    done
  done
  [ "$bad" = 0 ] && pass "$label: ancestor directories are safe"
}
ancestors "state directory" "$state"

# private <path> <label> <required 0|1> <strict 0|1>: strict means no group or
# other bits at all; otherwise only group/other write is fatal.
private() {
  local p=$1 label=$2 u mo links type bits problems=()
  if [ ! -e "$p" ] && [ ! -L "$p" ]; then
    if [ "$3" = 1 ]; then fail "$label is missing: $p"; else info "$label absent"; fi
    return
  fi
  if [ -L "$p" ]; then fail "$label is a symlink: $p"; return; fi
  read -r u _ mo links type <<<"$(meta "$p")"
  bits=$((8#$mo))
  case $type in "regular file" | "regular empty file") ;; *) problems+=("not a regular file") ;; esac
  [ "$u" = "$custody_uid" ] || problems+=("owned by uid $u")
  [ "$links" = 1 ] || problems+=("$links hard links")
  if [ "$4" = 1 ]; then
    (( bits & 8#077 )) && problems+=("mode $mo (want 0600 or 0400)")
  else
    (( bits & 8#022 )) && problems+=("mode $mo is writable by group or others")
    (( bits & 8#044 )) && warn "$label is readable by group or others (mode $mo)"
  fi
  if [ ${#problems[@]} -eq 0 ]; then pass "$label (mode $mo)"; else fail "$label $p: ${problems[*]}"; fi
}
private "$state/node.json" "node.json" 1 1
private "$state/custody.json" "custody.json" 1 1
private "$state/ipc.key" "ipc.key (DKG IPC key)" 0 1
private "$state/journal.sqlite" "journal.sqlite" 0 1
private "$state/transport.sqlite" "transport.sqlite" 0 1
private "$state/group-descriptor.json" "group-descriptor.json" 0 1
for side in journal.sqlite-wal journal.sqlite-shm transport.sqlite-wal transport.sqlite-shm; do
  [ -e "$state/$side" ] || [ -L "$state/$side" ] && private "$state/$side" "$side" 0 0
done
known=" node.json ipc.key storage.key custody.json journal.sqlite journal.sqlite-wal journal.sqlite-shm \
journal.sqlite-journal transport.sqlite transport.sqlite-wal transport.sqlite-shm group-descriptor.json controller.sock "
for entry in "$state"/* "$state"/.[!.]*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  name=${entry##*/}
  case $known in
    *" $name "*) [ "$name" = controller.sock ] && info "controller.sock present: the node is serving a DKG" ;;
    *) warn "unexpected entry in the state directory: $name" ;;
  esac
done

if ! config=$(python3 -I -c '
import json, sys
c = json.load(open(sys.argv[1]))
k = c.get("master_key") or {}
for value in (c.get("schema"), c.get("anchor"), c.get("layout"), k.get("kind"),
              k.get("path") or k.get("name"), c.get("retired_share_retention_days")):
    print("" if value is None else value)
for path in c.get("separate_from") or []:
    print(path)
' "$state/custody.json" 2>/dev/null); then
  fail "custody.json is unreadable or invalid; adopt the directory with 'mpc-custody init'"
  finish
fi
mapfile -t field <<<"$config"
# Command substitution drops trailing empty lines, so absent values default to "".
anchor=${field[1]-} layout=${field[2]-} key_kind=${field[3]-} key_ref=${field[4]-} retention=${field[5]-}
separate=("${field[@]:6}")
[ "${field[0]-}" = 1 ] || fail "custody.json schema '${field[0]-}' (want 1)"
case $layout in
  production) fail "production custody is NOT VERIFIED: no independent snapshot witness or attested protected key source" ;;
  hardened) warn "hardened candidate: software checks only; NOT production custody" ;;
  separated) pass "separated layout (NOT production custody)" ;;
  development) warn "development layout: one user may run the node, signer and Lair" ;;
  *) fail "unknown layout '$layout'" ;;
esac
if [ "$layout" = hardened ] && [ "$key_kind" != systemd_credential ]; then
  fail "hardened candidate requires a separately injected systemd credential"
fi

case $key_kind in
  state_directory)
    private "$state/storage.key" "master key storage.key" 1 1
    if [ "$layout" != development ]; then fail "non-development layout with the master key inside the state directory"
    else warn "master key sits beside the journal it protects (development layout only)"; fi ;;
  file | systemd_credential)
    if [ -e "$state/storage.key" ] || [ -L "$state/storage.key" ]; then
      fail "storage.key is still in the state directory although the key source is external"
    fi
    if [ "$key_kind" = systemd_credential ]; then
      info "systemd credential '$key_ref' selected; cannot attest TPM sealing or LoadCredentialEncrypted from this audit"
    else
      case $key_ref in "$state"/* | "$(readlink -f -- "$state")"/*) fail "external key file is inside the state directory" ;; esac
      if [ -L "$key_ref" ] || ! m=$(meta "$key_ref"); then fail "external key file $key_ref is missing or a symlink"
      else
        read -r u g mo links _ <<<"$m"
        bits=$((8#$mo))
        if [ "$links" != 1 ]; then fail "external key file has $links hard links"
        elif [ "$u" = "$custody_uid" ] && ! (( bits & 8#077 )); then pass "external key file owned by the custody user (mode $mo)"
        elif [ "$u" = 0 ] && ! (( bits & 8#037 )) && { ! (( bits & 8#040 )) || [ "$g" = "$custody_gid" ]; }; then
          pass "external key file owned by root, readable only by the custody group (mode $mo)"
        else fail "external key file $key_ref: owner uid $u, group $g, mode $mo"; fi
        ancestors "external key file" "$key_ref"
      fi
    fi ;;
  *) fail "unknown master key source '$key_kind'" ;;
esac

case $anchor in /?*) ;; *) fail "anchor path '$anchor' is not absolute"; finish ;; esac
case $anchor in "$state"/* | "$(readlink -f -- "$state")"/*) fail "anchor is inside the state directory; restoring the directory rewinds it" ;; esac
last_seq=
if [ -L "$anchor" ] || ! m=$(meta "$anchor"); then
  fail "anti-rollback anchor $anchor is missing or a symlink"
else
  read -r u _ mo links _ <<<"$m"
  if [ "$u" = "$custody_uid" ] && [ "$links" = 1 ] && ! (( 8#$mo & 8#022 )); then pass "anchor file (mode $mo)"
  else fail "anchor $anchor: owner uid $u, mode $mo, $links links (want the custody user, no group/other write, one link)"; fi
  if head -n 1 -- "$anchor" | grep -Eq '^holochain-mpc custody-anchor v1 [0-9a-f]{64}$'; then
    last_seq=$(tail -n 1 -- "$anchor" | cut -d ' ' -f 1)
    pass "anchor header valid; $(( $(wc -l < "$anchor") - 1 )) record line(s), last seq ${last_seq:-?} (unauthenticated)"
  else
    fail "anchor header is not a custody anchor"
  fi
  ancestors "anchor" "$anchor"
  read -r pu _ pmo _ _ <<<"$(meta "$(dirname -- "$anchor")")"
  if [ "$pu" = "$custody_uid" ] || (( 8#$pmo & 8#022 )); then
    if [ "$layout" != development ]; then fail "non-development layout: the anchor's directory is writable by the custody user"
    else warn "the custody user can replace the anchor (its directory is writable by it)"; fi
  else
    pass "anchor directory belongs to uid $pu and is not writable by the custody user"
  fi
  if [ "$layout" = hardened ] && [ "$pu" != 0 ]; then
    fail "hardened candidate requires a root-owned anchor parent"
  fi
  if attrs=$(lsattr -d -- "$anchor" 2>/dev/null); then
    case ${attrs%% *} in *a*) pass "anchor is append-only (chattr +a)" ;; *) warn "anchor is not append-only; set chattr +a as root" ;; esac
  else
    warn "cannot read the anchor's file attributes here; check chattr +a"
  fi
fi

if [ -e "$state/journal.sqlite" ] && [ -n "$last_seq" ]; then
  if [ -e "$state/journal.sqlite-wal" ]; then
    info "journal is open or was not closed cleanly; head comparison skipped (use mpc-custody verify)"
  elif head_seq=$(python3 -I -c '
import sqlite3, sys, urllib.parse
uri = "file:" + urllib.parse.quote(sys.argv[1]) + "?immutable=1"
row = sqlite3.connect(uri, uri=True).execute("SELECT seq FROM custody_head WHERE id=1").fetchone()
print(row[0] if row else "")
' "$state/journal.sqlite" 2>/dev/null) && [ -n "$head_seq" ]; then
    if [ "$head_seq" -lt "$last_seq" ]; then fail "journal seq $head_seq is behind anchor seq $last_seq: an older journal was restored"
    elif [ "$head_seq" -eq "$last_seq" ]; then pass "journal seq $head_seq matches the anchor (unauthenticated)"
    else info "journal seq $head_seq is ahead of anchor seq $last_seq; the next anchored open records it"; fi
  else
    warn "journal has no custody chain yet or is unreadable"
  fi
fi

if [ "$layout" = separated ] && [ ${#separate[@]} -eq 0 ]; then fail "separated layout without separate_from"; fi
if [ "$layout" = hardened ] && [ ${#separate[@]} -ne 3 ]; then
  fail "hardened candidate requires exactly three role roots (relay, Lair signer, conductor)"
fi
role_uids=" "
for path in "${separate[@]}" "${other_roots[@]}"; do
  [ -n "$path" ] || continue
  if ! m=$(meta "$path"); then fail "$path does not exist"; continue; fi
  read -r u _ mo _ _ <<<"$m"
  if [ "$u" != "$custody_uid" ]; then pass "$path belongs to uid $u, not the custody user"
  elif [ "$layout" != development ]; then fail "$path belongs to the custody user (uid $u)"
  else warn "$path belongs to the custody user (uid $u): node, signer and Lair share one user"; fi
  if [ "$layout" = hardened ]; then
    if [ -L "$path" ] || [ ! -d "$path" ] || [ "$mo" != 700 ] || [ "$u" = 0 ]; then
      fail "hardened role root $path must be a non-symlinked 0700 directory of a non-root user"
    fi
    case $role_uids in *" $u "*) fail "hardened role root UID $u is reused" ;; esac
    role_uids="$role_uids$u "
  fi
done
[ -n "$retention" ] && info "retired shares are erased after $retention day(s) by mpc-custody apply-retention"
finish
