//! Spawn a `fakeobd serve` process for the dry-run / replay path.
//!
//! fakeobd-first: the whole stack is exercised against the `fakeobd` simulator with no hardware.
//! Like `voltkit`'s lab command, gmdiag spawns the `fakeobd` *binary* and dials it over TCP; it
//! does not link `fakeobd` as a crate. The simulator prints a line containing `listening` to its
//! stderr once the socket is bound, which this helper waits for so a connection is never opened
//! before the peer is ready.

use std::io::{self, Read};
use std::net::TcpListener;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Environment variable naming the `fakeobd` binary. When unset, `fakeobd` on `PATH` is used.
pub const PROGRAM_ENV: &str = "GMDIAG_FAKEOBD";

/// The `fakeobd` program: the override from [`PROGRAM_ENV`], else `fakeobd` on `PATH`.
#[must_use]
pub fn program() -> std::ffi::OsString {
    std::env::var_os(PROGRAM_ENV).unwrap_or_else(|| std::ffi::OsString::from("fakeobd"))
}

/// Pick a free loopback port by binding `:0`, reading the port, and dropping the listener.
///
/// # Errors
/// Returns [`Error::Io`] when a loopback socket cannot be bound.
pub fn free_loopback_addr() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(format!("127.0.0.1:{port}"))
}

/// A running `fakeobd serve` process, killed on drop.
#[derive(Debug)]
pub struct FakeObd {
    child: Child,
    addr: String,
}

impl FakeObd {
    /// Spawn `fakeobd serve --listen <addr>` and wait until it reports it is listening.
    ///
    /// Pass extra args (e.g. `--policy`, `--profile`) in `extra`.
    ///
    /// # Errors
    /// Returns [`Error::Io`] when the program cannot start, exits early, or never reports that it
    /// is listening within a few seconds.
    pub fn spawn(program: &std::ffi::OsStr, addr: &str, extra: &[&str]) -> Result<Self> {
        let mut args = vec!["serve", "--listen", addr];
        args.extend_from_slice(extra);
        let mut child = Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::Io(io::Error::other(format!(
                    "could not start fakeobd ({}): {e}",
                    program.to_string_lossy()
                )))
            })?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Io(io::Error::other("fakeobd stderr was already taken")))?;
        let ready = wait_until_listening(stderr);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(Error::Io(io::Error::other(format!(
                    "fakeobd exited ({status}) before it reported listening on {addr}"
                ))));
            }
            match ready.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => break,
                Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    let _ = child.kill();
                    return Err(Error::Io(io::Error::other(format!(
                        "fakeobd did not report listening on {addr}"
                    ))));
                }
            }
        }
        Ok(Self {
            child,
            addr: addr.to_string(),
        })
    }

    /// The address the simulator is listening on.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }
}

impl Drop for FakeObd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until_listening(mut stderr: ChildStderr) -> Receiver<()> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        // Read the banner for the `listening` line, then keep draining stderr for the child's
        // whole life. The pipe must stay open: `fakeobd` writes an audit line to stderr on every
        // denied request, and if the read end were closed its `eprintln!` would hit a broken pipe
        // and panic the session thread, dropping the connection mid-exchange.
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        let mut announced = false;
        loop {
            match stderr.read(&mut tmp) {
                Ok(n) if n > 0 => {
                    if !announced {
                        buf.extend_from_slice(&tmp[..n]);
                        if String::from_utf8_lossy(&buf)
                            .to_ascii_lowercase()
                            .contains("listening")
                        {
                            let _ = tx.send(());
                            announced = true;
                            buf = Vec::new(); // stop accumulating; just drain from here on
                        }
                    }
                    // else: discard the drained bytes.
                }
                // End of stream or a read error: nothing more to drain.
                Ok(_) | Err(_) => return,
            }
        }
    });
    rx
}
