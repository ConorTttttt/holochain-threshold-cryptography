//! Durable state: one private JSON file per vault and per proposal, plus an
//! append-only event log. Files are written atomically (temp, fsync, rename)
//! in a 0700 directory owned by this user.
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct Store {
    root: PathBuf,
}

fn private_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let info = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !info.is_dir() || info.file_type().is_symlink() || info.uid() != unsafe { libc::geteuid() }
        || info.permissions().mode() & 0o077 != 0 {
        return Err(format!("{} must be a real directory owned by this user with mode 0700", path.display()));
    }
    Ok(())
}

impl Store {
    pub fn open(root: &Path) -> Result<Self, String> {
        if !root.is_absolute() { return Err("data directory must be an absolute path".into()); }
        private_dir(root)?;
        for d in ["vaults", "proposals", "w"] { private_dir(&root.join(d))?; }
        Ok(Self { root: root.to_path_buf() })
    }

    pub fn work_dir(&self, id: &str) -> Result<PathBuf, String> {
        let dir = self.root.join("w").join(id);
        private_dir(&dir)?;
        Ok(dir)
    }

    fn path(&self, kind: &str, id: &str) -> Result<PathBuf, String> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("invalid id".into());
        }
        Ok(self.root.join(kind).join(format!("{id}.json")))
    }

    pub fn save<T: Serialize>(&self, kind: &str, id: &str, value: &T) -> Result<(), String> {
        let path = self.path(kind, id)?;
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(&bytes).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        File::open(path.parent().unwrap()).and_then(|d| d.sync_all()).map_err(|e| e.to_string())
    }

    pub fn load_all<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>, String> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join(kind)).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().map_or(true, |e| e != "json") { continue; }
            let info = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if !info.is_file() || info.permissions().mode() & 0o077 != 0 {
                return Err(format!("{} must be a private regular file", path.display()));
            }
            out.push(serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("{}: {e}", path.display()))?);
        }
        Ok(out)
    }

    pub fn append_event<T: Serialize>(&self, event: &T) -> Result<(), String> {
        let mut line = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let mut f = OpenOptions::new().append(true).create(true).mode(0o600).open(self.root.join("events.jsonl"))
            .map_err(|e| e.to_string())?;
        f.write_all(&line).map_err(|e| e.to_string())
    }

    pub fn load_events<T: DeserializeOwned>(&self) -> Result<Vec<T>, String> {
        match fs::read(self.root.join("events.jsonl")) {
            Ok(b) => b.split(|c| *c == b'\n').filter(|l| !l.is_empty())
                .map(|l| serde_json::from_slice(l).map_err(|e| e.to_string())).collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }
}
