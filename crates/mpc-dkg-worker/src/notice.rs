//! The non-production notice every binary prints for `--help` (see the
//! repository's `SECURITY.md`). The notice stays until the removal criteria
//! there are independently met.

pub const NOTICE: &str = "NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE.\n\
Do not use it with real keys, funds, identities or secret shares. Custody is\n\
development-grade and no independent audit has been done (see SECURITY.md).";

/// The full `--help` text for one tool.
pub fn help_text(name: &str, usage: &str) -> String {
    format!("{name}\n\n{NOTICE}\n\n{usage}\n")
}

/// Call first in `main`: prints the help and exits 0 when the first argument is
/// `--help` or `-h`, before the tool reads stdin, files or the network.
pub fn exit_on_help(name: &str, usage: &str) {
    if matches!(std::env::args().nth(1).as_deref(), Some("--help" | "-h")) {
        print!("{}", help_text(name, usage));
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn help_text_carries_the_notice() {
        let text = help_text("mpc-demo", "usage: mpc-demo");
        assert!(text.starts_with("mpc-demo\n"));
        assert!(text.contains("NOT PRODUCTION SOFTWARE"));
        assert!(text.contains("usage: mpc-demo"));
    }
}
