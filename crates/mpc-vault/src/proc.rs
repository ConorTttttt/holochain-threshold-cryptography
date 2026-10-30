//! Child processes for the existing operator tools. Lair prompts for its
//! passphrase on /dev/tty, so a child either inherits the service's terminal
//! (the operator types the passphrase there) or, for a disposable rehearsal
//! only, gets its own pseudo-terminal and a passphrase read from a 0600 file.
//! The passphrase never appears in argv, the API, or the captured output.
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Child {
    child: std::process::Child,
    output: Arc<Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

/// The passphrase prompt Lair prints: a line mentioning "passphrase" that ends in `:` or `>`.
fn is_prompt(buf: &[u8]) -> bool {
    let tail = buf.rsplit(|b| *b == b'\n').next().unwrap_or(&[]);
    let text = String::from_utf8_lossy(tail).to_lowercase();
    let t = text.trim_end();
    t.contains("passphrase") && (t.ends_with(':') || t.ends_with('>'))
}

fn redact(buf: &[u8], secret: &[u8]) -> Vec<u8> {
    if secret.is_empty() { return buf.to_vec(); }
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i..].starts_with(secret) { out.extend_from_slice(b"[redacted]"); i += secret.len(); } else { out.push(buf[i]); i += 1; }
    }
    out
}

impl Child {
    /// `passphrase` Some: run on a private pseudo-terminal and answer Lair's prompt.
    /// None: inherit this process's terminal; stdout is captured.
    pub fn spawn(argv: &[OsString], passphrase: Option<Vec<u8>>) -> std::io::Result<Child> {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        let output = Arc::new(Mutex::new(Vec::new()));
        if let Some(secret) = passphrase {
            let (mut master, mut slave) = (0, 0);
            if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
            unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(slave.as_raw_fd(), &mut t) == 0 {
                    t.c_lflag &= !libc::ECHO; // never echo what we type
                    libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &t);
                }
            }
            cmd.stdin(Stdio::from(slave.try_clone()?)).stdout(Stdio::from(slave.try_clone()?)).stderr(Stdio::from(slave.try_clone()?));
            // Its own session with the pty as controlling terminal, like a login terminal.
            unsafe { cmd.pre_exec(|| { libc::setsid(); libc::ioctl(0, libc::TIOCSCTTY, 0); Ok(()) }); }
            let child = cmd.spawn()?;
            drop(slave);
            let sink = output.clone();
            let reader = std::thread::spawn(move || {
                let mut file = std::fs::File::from(master);
                let (mut buf, mut answered, mut chunk) = (Vec::<u8>::new(), 0_usize, [0_u8; 1024]);
                loop {
                    match file.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.len() > answered && is_prompt(&buf) {
                                answered = buf.len();
                                let mut line = secret.clone();
                                line.push(b'\n');
                                let _ = file.write_all(&line);
                                line.iter_mut().for_each(|b| *b = 0);
                            }
                            *sink.lock().unwrap() = redact(&buf, &secret);
                        }
                    }
                }
            });
            return Ok(Child { child, output, reader: Some(reader) });
        }
        cmd.stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = cmd.spawn()?;
        let mut stdout = child.stdout.take().expect("piped");
        let sink = output.clone();
        let reader = std::thread::spawn(move || {
            let mut chunk = [0_u8; 1024];
            while let Ok(n) = stdout.read(&mut chunk) {
                if n == 0 { break; }
                sink.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        Ok(Child { child, output, reader: Some(reader) })
    }

    pub fn text(&self) -> String { String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned() }

    pub fn wait_for(&mut self, needle: &str, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        while Instant::now() < end {
            if self.text().contains(needle) { return true; }
            if let Ok(Some(_)) = self.child.try_wait() { return self.text().contains(needle); }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    pub fn wait(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let end = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(s)) => {
                    // Drain the output, but never hang on a grandchild that kept the pipe open.
                    if let Some(r) = self.reader.take() {
                        let drain_end = Instant::now() + Duration::from_secs(2);
                        while !r.is_finished() && Instant::now() < drain_end { std::thread::sleep(Duration::from_millis(10)); }
                        if r.is_finished() { let _ = r.join(); }
                    }
                    return Some(s);
                }
                Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
                _ => return None,
            }
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Child {
    fn drop(&mut self) { if let Ok(None) = self.child.try_wait() { self.kill(); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sh(script: &str) -> Vec<OsString> { vec!["/bin/sh".into(), "-c".into(), script.into()] }

    #[test]
    fn answers_the_prompt_on_a_private_tty_and_redacts_it() {
        let script = "printf 'Enter passphrase: '; read -r p; if [ \"$p\" = hunter2 ]; then echo \"OK got $p\"; else echo BAD; exit 3; fi";
        let mut c = Child::spawn(&sh(script), Some(b"hunter2".to_vec())).unwrap();
        let status = c.wait(Duration::from_secs(10)).expect("exits");
        assert!(status.success(), "output: {}", c.text());
        assert!(c.text().contains("OK got [redacted]"), "{}", c.text());
        assert!(!c.text().contains("hunter2"));
    }

    #[test]
    fn captures_stdout_without_a_passphrase() {
        let mut c = Child::spawn(&sh("echo hello; exit 4"), None).unwrap();
        let status = c.wait(Duration::from_secs(10)).unwrap();
        assert_eq!(status.code(), Some(4));
        assert!(c.text().contains("hello"));
    }

    #[test]
    fn wait_for_and_kill() {
        let mut c = Child::spawn(&sh("echo ready; sleep 30"), None).unwrap();
        assert!(c.wait_for("ready", Duration::from_secs(10)));
        assert!(c.wait(Duration::from_millis(100)).is_none());
        c.kill();
        assert!(c.wait(Duration::from_secs(5)).is_some());
    }

    #[test]
    fn prompt_detection() {
        assert!(is_prompt(b"x\nEnter Lair passphrase: "));
        assert!(is_prompt(b"passphrase>"));
        assert!(!is_prompt(b"the passphrase was wrong\n"));
        assert!(!is_prompt(b"hello:"));
    }
}
