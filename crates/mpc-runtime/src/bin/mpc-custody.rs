//! v0.4.0 Phase 7 hardening: operator commands for one node's share custody.
//!
//! Run as the node's custody user, never as root, with the signer stopped for
//! `restore`. Nothing here prints key material. Writes need an explicit
//! `--confirm-*` flag. See docs/V040_PHASE7_CUSTODY_HARDENING.md.
#[cfg(unix)]
mod cli {
    use holochain_mpc_runtime::custody::{self, Custody, CustodyConfig, KeySource, Layout};
    use holochain_mpc_runtime::lifecycle::EpochState;
    use std::path::PathBuf;

    pub const USAGE: &str = "usage:
  mpc-custody verify <state-dir>
  mpc-custody init <state-dir> --anchor <abs-file> [--key-file <abs-file> | --key-credential <name>]
              [--separated | --hardened | --production] [--separate-from <abs-path>...] [--retention-days <n>]
              --hardened expects exactly three ordered roots: relay, Lair signer, conductor
              --production always refuses until hardware key custody and an independent witness are implemented
  mpc-custody backup <state-dir> --out <abs-file>
  mpc-custody restore --bundle <abs-file> --state-dir <abs-new-dir> --master-key-file <abs-file> --confirm-restore
  mpc-custody retire-epoch <state-dir> --proposal-hex <78-hex> --epoch <n> --reason <text> --confirm-retire
  mpc-custody erase-share <state-dir> --proposal-hex <78-hex> --epoch <n> --confirm-erase
  mpc-custody apply-retention <state-dir> --confirm-erase";

    struct Flags { values: Vec<(String, String)>, switches: Vec<String> }
    impl Flags {
        fn parse(args: &[String], switches: &[&str]) -> Result<Self, String> {
            let (mut values, mut seen) = (Vec::new(), Vec::new());
            let mut it = args.iter();
            while let Some(flag) = it.next() {
                if !flag.starts_with("--") { return Err(format!("unexpected argument {flag}")); }
                if switches.contains(&flag.as_str()) { seen.push(flag.clone()); continue; }
                let value = it.next().ok_or_else(|| format!("missing value for {flag}"))?;
                values.push((flag.clone(), value.clone()));
            }
            Ok(Self { values, switches: seen })
        }
        fn all(&self, flag: &str) -> Vec<&str> {
            self.values.iter().filter(|(f, _)| f == flag).map(|(_, v)| v.as_str()).collect()
        }
        fn one(&self, flag: &str) -> Result<Option<&str>, String> {
            match self.all(flag).as_slice() {
                [] => Ok(None),
                [value] => Ok(Some(value)),
                _ => Err(format!("{flag} given more than once")),
            }
        }
        fn need(&self, flag: &str) -> Result<&str, String> { self.one(flag)?.ok_or_else(|| format!("missing {flag}")) }
        fn has(&self, switch: &str) -> bool { self.switches.iter().any(|s| s == switch) }
        fn confirmed(&self, switch: &str) -> Result<(), String> {
            if self.has(switch) { Ok(()) } else { Err(format!("refusing to write without {switch}")) }
        }
    }

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
    fn proposal(text: &str) -> Result<Vec<u8>, String> {
        if text.len() != 78 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("--proposal-hex must be 39 bytes of hex".into());
        }
        (0..78).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string())).collect()
    }
    fn now_ms() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64).unwrap_or(0)
    }
    fn dir(args: &[String]) -> Result<(PathBuf, &[String]), String> {
        let first = args.first().ok_or(USAGE)?;
        if first.starts_with("--") { return Err(USAGE.into()); }
        Ok((PathBuf::from(first), &args[1..]))
    }

    pub fn run(args: &[String]) -> Result<(), String> {
        let command = args.first().map(String::as_str).ok_or(USAGE)?;
        let rest = &args[1..];
        match command {
            "verify" => {
                let (dir, rest) = dir(rest)?;
                Flags::parse(rest, &[])?;
                let custody = Custody::load(&dir).map_err(|e| e.to_string())?;
                let found = custody.inspect().map_err(|e| e.to_string())?;
                println!("PASS: local layout {:?}, key source {:?}; NOT PRODUCTION VERIFIED", custody.config().layout, custody.config().master_key);
                println!("journal_seq={} anchor_seq={} anchor_records={} skipped_anchor_lines={} bound={}",
                    found.head.seq, found.anchor.last.seq, found.anchor.records, found.anchor.skipped_lines,
                    found.head.anchor_id.is_some());
                for e in found.epochs {
                    println!("epoch proposal={} epoch={} state={:?} sealed_share={}",
                        hex(&e.proposal), e.epoch, e.state, e.sealed_share);
                }
                Ok(())
            }
            "init" => {
                let (dir, rest) = dir(rest)?;
                let f = Flags::parse(rest, &["--separated", "--hardened", "--production"])?;
                if ["--separated", "--hardened", "--production"].iter()
                    .filter(|name| f.has(name)).count() > 1 {
                    return Err("choose only one custody layout".into());
                }
                let master_key = match (f.one("--key-file")?, f.one("--key-credential")?) {
                    (None, None) => KeySource::StateDirectory,
                    (Some(path), None) => KeySource::File { path: PathBuf::from(path) },
                    (None, Some(name)) => KeySource::SystemdCredential { name: name.to_owned() },
                    _ => return Err("choose one of --key-file and --key-credential".into()),
                };
                let config = CustodyConfig {
                    schema: 1, anchor: PathBuf::from(f.need("--anchor")?), master_key,
                    layout: if f.has("--production") { Layout::Production }
                        else if f.has("--hardened") { Layout::Hardened }
                        else if f.has("--separated") { Layout::Separated }
                        else { Layout::Development },
                    separate_from: f.all("--separate-from").into_iter().map(PathBuf::from).collect(),
                    retired_share_retention_days: f.one("--retention-days")?
                        .map(|d| d.parse().map_err(|_| "invalid --retention-days")).transpose()?,
                };
                custody::adopt(&dir, &config).map_err(|e| e.to_string())?;
                println!("PASS: custody.json written and anchor created at {}; NOT PRODUCTION VERIFIED", config.anchor.display());
                println!("Existing journal state was trusted as it stands (trust on first use).");
                Ok(())
            }
            "backup" => {
                let (dir, rest) = dir(rest)?;
                let f = Flags::parse(rest, &[])?;
                let out = PathBuf::from(f.need("--out")?);
                let custody = Custody::load(&dir).map_err(|e| e.to_string())?;
                let summary = custody.backup(&out).map_err(|e| e.to_string())?;
                println!("PASS: encrypted backup written; journal_seq={} bytes={}", summary.head_seq, summary.bytes);
                println!("It is stale after this node's next journal write. Back up the master key separately.");
                Ok(())
            }
            "restore" => {
                let f = Flags::parse(rest, &["--confirm-restore"])?;
                f.confirmed("--confirm-restore")?;
                let key = custody::read_key_file(&PathBuf::from(f.need("--master-key-file")?))
                    .map_err(|e| e.to_string())?;
                let summary = custody::restore(&PathBuf::from(f.need("--bundle")?),
                    &PathBuf::from(f.need("--state-dir")?), &key).map_err(|e| e.to_string())?;
                println!("PASS: state restored and checked against its anti-rollback anchor; journal_seq={}",
                    summary.head_seq);
                Ok(())
            }
            "retire-epoch" => {
                let (dir, rest) = dir(rest)?;
                let f = Flags::parse(rest, &["--confirm-retire"])?;
                f.confirmed("--confirm-retire")?;
                let epoch: u64 = f.need("--epoch")?.parse().map_err(|_| "invalid --epoch")?;
                let proposal = proposal(f.need("--proposal-hex")?)?;
                let custody = Custody::load(&dir).map_err(|e| e.to_string())?;
                let mut store = custody.open_journal().map_err(|e| e.to_string())?;
                store.retire_epoch(&proposal, epoch, now_ms(), f.need("--reason")?).map_err(|e| e.to_string())?;
                println!("PASS: epoch {epoch} retired on this node; signing with it is refused from now on");
                Ok(())
            }
            "erase-share" => {
                let (dir, rest) = dir(rest)?;
                let f = Flags::parse(rest, &["--confirm-erase"])?;
                f.confirmed("--confirm-erase")?;
                let epoch: u64 = f.need("--epoch")?.parse().map_err(|_| "invalid --epoch")?;
                let proposal = proposal(f.need("--proposal-hex")?)?;
                let custody = Custody::load(&dir).map_err(|e| e.to_string())?;
                let mut store = custody.open_journal().map_err(|e| e.to_string())?;
                if store.epoch_state(&proposal, epoch).map_err(|e| e.to_string())? != EpochState::Retired {
                    return Err("only a retired epoch's share can be erased".into());
                }
                let rows = store.erase_share(&proposal, epoch, now_ms()).map_err(|e| e.to_string())?;
                println!("PASS: {rows} sealed share row(s) erased (best effort: backups, snapshots and the disk \
                    may still hold copies; destroy them, or the master key once no epoch needs it)");
                Ok(())
            }
            "apply-retention" => {
                let (dir, rest) = dir(rest)?;
                let f = Flags::parse(rest, &["--confirm-erase"])?;
                f.confirmed("--confirm-erase")?;
                let custody = Custody::load(&dir).map_err(|e| e.to_string())?;
                let erased = custody.apply_retention(now_ms()).map_err(|e| e.to_string())?;
                for (proposal, epoch) in &erased {
                    println!("erased proposal={} epoch={epoch}", hex(proposal));
                }
                println!("PASS: retention applied; {} share(s) erased", erased.len());
                Ok(())
            }
            _ => Err(USAGE.into()),
        }
    }
}

/// The repository-wide non-production notice, word for word as in
/// `holochain_mpc_dkg_worker::notice::NOTICE` (this crate cannot depend on the
/// worker). `scripts/release_check.py` asserts the exact text for every binary.
const NOTICE: &str = "NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE.\n\
Do not use it with real keys, funds, identities or secret shares. Custody is\n\
development-grade and no independent audit has been done (see SECURITY.md).";
const CUSTODY_WARNING: &str = "Development build. Not production custody. Do not use with real funds.";

/// `--help`/`-h` as the first argument prints the notice and exits 0, before any
/// file is read. Every other invocation is unchanged.
fn exit_on_help(usage: &str) {
    if matches!(std::env::args().nth(1).as_deref(), Some("--help" | "-h")) {
        print!("mpc-custody\n\n{NOTICE}\n\n{CUSTODY_WARNING}\n\n{usage}\n");
        std::process::exit(0);
    }
}

#[cfg(unix)]
fn main() {
    exit_on_help(cli::USAGE);
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = cli::run(&args) {
        eprintln!("FAIL: mpc-custody: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    exit_on_help("mpc-custody supports Unix custody layouts only");
    eprintln!("FAIL: mpc-custody supports Unix custody layouts only");
    std::process::exit(1);
}
