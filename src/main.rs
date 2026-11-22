//! Command-line entry point for `gmdiag`.
//!
//! Parses the arguments, runs [`gmdiag::cli::run`] with a terminal confirmation callback, prints
//! the result, and exits with its code. The confirmation prompt is where a gated write stops for
//! a human: it prints what is about to be sent and reads `y/N` from standard input.

use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut confirm = terminal_confirm;
    let (code, text) = gmdiag::cli::run(&args, &mut confirm);
    println!("{text}");
    match write_session_log(&args, &text, code) {
        Ok(Some(path)) => println!("\n[session log saved: {}]", path.display()),
        Ok(None) => {}
        Err(error) => eprintln!("\n[could not write the session log: {error}]"),
    }
    std::process::exit(code);
}

/// Write the full session output to a timestamped log in the current directory, so a
/// read can be troubleshot piece by piece from the saved record. Returns the path
/// written, or `None` when there was nothing to log. The file goes in the cwd the
/// operator ran from (e.g. the removable drive), never in the repository.
fn write_session_log(
    args: &[String],
    text: &str,
    code: i32,
) -> io::Result<Option<std::path::PathBuf>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let command: String = args
        .first()
        .map_or("gmdiag", String::as_str)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let path = std::path::PathBuf::from(format!("gmdiag-{command}-{secs}.log"));
    let header = format!(
        "gmdiag session log\ncommand: gmdiag {}\nexit code: {code}\n{}\n\n",
        args.join(" "),
        "-".repeat(60),
    );
    std::fs::write(&path, format!("{header}{text}\n"))?;
    Ok(Some(path))
}

/// Print the pending action and read `y/N` from the terminal. Anything but `y`/`yes` is a no.
fn terminal_confirm(action: &str) -> bool {
    print!("about to send: {action}\nproceed? [y/N] ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
