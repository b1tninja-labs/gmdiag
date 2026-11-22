//! The crate error type.
//!
//! One error type spans the transport (socket, adapter line protocol), the session
//! (a negative response the caller asked to treat as fatal, a timeout), and argument
//! parsing. It carries a message; it is not a rich typed hierarchy, because the useful
//! distinction here is transport-versus-protocol, which the variants below draw.

use std::fmt;

/// Anything that can go wrong driving a diagnostic link.
#[derive(Debug)]
pub enum Error {
    /// An I/O failure on the underlying link (socket closed, timed out, refused).
    Io(std::io::Error),
    /// The adapter returned a status line that is not diagnostic data
    /// (`NO DATA`, `CAN ERROR`, `UNABLE TO CONNECT`, `?`, ...).
    Adapter(String),
    /// A reply arrived but did not parse as a PDU.
    Protocol(String),
    /// The server answered with a negative response the caller did not tolerate.
    Negative(String),
    /// A guard refused the action (a write without `--write`, a non-loopback peer, ...).
    Refused(String),
    /// An error surfaced by one of the model libraries (`udskit`, `gmdtcdb`, ...).
    Model(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Adapter(m) => write!(f, "adapter: {m}"),
            Error::Protocol(m) => write!(f, "protocol: {m}"),
            Error::Refused(m) => write!(f, "refused: {m}"),
            Error::Negative(m) | Error::Model(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

impl From<udskit::Error> for Error {
    fn from(value: udskit::Error) -> Self {
        Error::Model(value.to_string())
    }
}

/// The crate result type.
pub type Result<T> = core::result::Result<T, Error>;
