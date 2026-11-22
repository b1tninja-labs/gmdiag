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
    std::process::exit(code);
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
