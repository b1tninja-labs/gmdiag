//! An ELM327-over-TCP [`Transport`]: AT lines and hex PDUs to an adapter that runs ISO-TP.
//!
//! The adapter does the transport layer (ISO-TP segmentation and flow control); gmdiag speaks
//! the ELM327 carriage-return line protocol to it and sends UDS application PDUs as hex. A
//! command is terminated by a carriage return and a reply ends at the `>` prompt; `NUL` bytes
//! on the way in are ignored. The reset-and-format sequence and the single-frame / CAF
//! multi-frame reply parsing follow the ones the 2026-11-14 bench trial used and the read-only
//! `voltkit` client proved against the same `fakeobd` simulator.
//!
//! This transport is neutral: it sends whatever PDU it is handed. Unlike `voltkit`, it does not
//! refuse a write service — that decision belongs to the session and the CLI.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::transport::{Target, Transport};

/// The datasheet reset-and-format sequence, in the order the bench trial sent it.
///
/// `ATSP6` selects ELM protocol 6 — ISO 15765-4 CAN, 11-bit id, 500 kbaud. `ATE0` turns the
/// echo off, `ATH0` the headers off, `ATL0`/`ATS0` the linefeeds and spaces off, and `ATCAF1`
/// leaves CAN auto-formatting (ISO-TP) on so the adapter reassembles multi-frame responses.
pub const INIT: [&str; 7] = ["ATZ", "ATL0", "ATH0", "ATS0", "ATSP6", "ATE0", "ATCAF1"];

/// Adapter status words that are a reply but not diagnostic data.
const STATUS_WORDS: &[&str] = &[
    "OK",
    "SEARCHING...",
    "SEARCHING",
    "NO DATA",
    "STOPPED",
    "UNABLE TO CONNECT",
    "CAN ERROR",
    "BUFFER FULL",
    "BUS INIT",
    "BUS ERROR",
    "FB ERROR",
    "DATA ERROR",
    "<DATA ERROR",
    "ERR",
    "?",
];

/// A connected ELM327-over-TCP session.
pub struct Elm327Tcp {
    stream: TcpStream,
    target: Option<Target>,
}

impl std::fmt::Debug for Elm327Tcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elm327Tcp")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Elm327Tcp {
    /// Connect to a loopback peer and run the reset sequence.
    ///
    /// The default link is loopback: `fakeobd`, or `obd-bridge` in front of a real adapter, both
    /// bind loopback. A non-loopback adapter is a deliberate choice made through
    /// [`Elm327Tcp::connect_any`].
    ///
    /// # Errors
    /// Returns [`Error::Refused`] when `addr` is not a single loopback socket address, and
    /// [`Error::Io`] when the connection or the reset fails.
    pub fn connect(addr: &str) -> Result<Self> {
        let sa = single_addr(addr)?;
        if !sa.ip().is_loopback() {
            return Err(Error::Refused(format!(
                "{addr} is not loopback; pass an explicit non-loopback flag to reach a real adapter"
            )));
        }
        Self::dial(sa)
    }

    /// Connect to any single socket address (a real adapter on the network) and run the reset.
    ///
    /// # Errors
    /// Returns [`Error::Refused`] when `addr` does not resolve to exactly one socket, and
    /// [`Error::Io`] when the connection or the reset fails.
    pub fn connect_any(addr: &str) -> Result<Self> {
        Self::dial(single_addr(addr)?)
    }

    fn dial(sa: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&sa, Duration::from_secs(3))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut session = Self {
            stream,
            target: None,
        };
        session.init()?;
        Ok(session)
    }

    /// Run the reset-and-format sequence. Each line's reply is read and discarded;
    /// a failure to reach the prompt is an error.
    fn init(&mut self) -> Result<()> {
        for line in INIT {
            self.exchange(line)?;
        }
        Ok(())
    }

    /// Set how long a read waits for the next byte. Used by tests and slow links.
    ///
    /// # Errors
    /// Returns the socket error when the timeout cannot be set.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.stream.set_read_timeout(timeout)?;
        Ok(())
    }

    /// Write `line` and a carriage return, then read raw bytes through the `>` prompt.
    fn exchange(&mut self, line: &str) -> Result<Vec<String>> {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\r');
        self.stream.write_all(&buf)?;
        let raw = self.read_prompt()?;
        Ok(split_reply(&raw))
    }

    fn read_prompt(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = self.stream.read(&mut buf)?;
            if n == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before the prompt",
                )));
            }
            for &b in &buf[..n] {
                if b == 0 {
                    continue;
                }
                out.push(b);
                if b == b'>' {
                    return Ok(out);
                }
            }
        }
    }
}

impl Transport for Elm327Tcp {
    fn set_target(&mut self, target: Target) -> Result<()> {
        self.exchange(&format!("ATSH{:03X}", target.request_id))?;
        self.exchange(&format!("ATCRA{:03X}", target.response_id))?;
        self.exchange(&format!("ATFCSH{:03X}", target.flow_control_id))?;
        self.target = Some(target);
        Ok(())
    }

    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        if pdu.is_empty() {
            return Err(Error::Protocol("empty request pdu".into()));
        }
        let hex = hex_compact(pdu);
        let lines = self.exchange(&hex)?;
        parse_payload(&hex, &lines)
    }

    fn read_more(&mut self) -> Result<Vec<u8>> {
        // No write: just read the next message through the prompt. The ELM presents a
        // response-pending follow-up as a later reply on the same request.
        let raw = self.read_prompt()?;
        let lines = split_reply(&raw);
        parse_payload("", &lines)
    }
}

/// Resolve `addr` when it names exactly one socket address.
fn single_addr(addr: &str) -> Result<SocketAddr> {
    let mut iter = addr
        .to_socket_addrs()
        .map_err(|e| Error::Refused(format!("{addr}: {e}")))?;
    match (iter.next(), iter.next()) {
        (Some(sa), None) => Ok(sa),
        (Some(_), Some(_)) => Err(Error::Refused(format!(
            "{addr} names more than one socket address"
        ))),
        (None, _) => Err(Error::Refused(format!("{addr} names no socket address"))),
    }
}

/// Whether `ip` is a loopback address (test helper mirror of the guard in [`Elm327Tcp::connect`]).
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Split a raw reply on carriage return and linefeed, dropping blanks and the prompt.
#[must_use]
pub fn split_reply(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    text.split(['\r', '\n'])
        .map(|l| l.trim().trim_end_matches('>').trim())
        .filter(|l| !l.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Diagnostic payload from a reply.
///
/// A leading echo of `request` and any adapter status word are dropped. What remains is either a
/// single hex frame, or the ELM CAF multi-frame form — a 3-hex-digit total length followed by
/// `i:` indexed lines. Returns [`Error::Adapter`] when the only content is a status word, and
/// [`Error::Protocol`] when the hex does not parse.
///
/// # Errors
/// See above.
pub fn parse_payload(request_hex: &str, lines: &[String]) -> Result<Vec<u8>> {
    let echo = squash(request_hex);
    let mut status: Option<String> = None;
    let content: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| squash(l) != echo)
        .filter(|l| {
            let up = l.trim().to_ascii_uppercase();
            if STATUS_WORDS.contains(&up.as_str()) {
                status = Some(l.trim().to_string());
                false
            } else {
                true
            }
        })
        .collect();

    if content.is_empty() {
        let word = status.unwrap_or_else(|| "no data".to_string());
        return Err(Error::Adapter(word));
    }

    // CAF multi-frame: first content line is a 3-hex-digit total length, then `i:` lines.
    if content[0].len() == 3
        && content[0].chars().all(|c| c.is_ascii_hexdigit())
        && content.len() > 1
    {
        return assemble(&content);
    }

    // Otherwise one or more plain hex lines; join them.
    let mut out = Vec::new();
    for line in &content {
        out.extend(hex_bytes(line)?);
    }
    Ok(out)
}

fn assemble(lines: &[&str]) -> Result<Vec<u8>> {
    let expect = usize::from_str_radix(lines[0], 16)
        .map_err(|_| Error::Protocol(format!("bad multi-frame length {:?}", lines[0])))?;
    let mut data = Vec::with_capacity(expect);
    for (i, line) in lines[1..].iter().enumerate() {
        let (idx, rest) = line
            .split_once(':')
            .ok_or_else(|| Error::Protocol(format!("multi-frame line without index: {line:?}")))?;
        let n = usize::from(
            u8::from_str_radix(idx, 16)
                .map_err(|_| Error::Protocol(format!("bad frame index {idx:?}")))?,
        );
        if n != i % 16 {
            return Err(Error::Protocol(format!(
                "multi-frame out of order: expected {}, got {n}",
                i % 16
            )));
        }
        data.extend(hex_bytes(rest)?);
    }
    data.truncate(expect);
    Ok(data)
}

fn hex_bytes(text: &str) -> Result<Vec<u8>> {
    let hex: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if hex.len() < 2 || hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Protocol(format!("not a hex frame: {text:?}")));
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let h = std::str::from_utf8(&bytes[i..i + 2]).expect("ascii hex");
        out.push(u8::from_str_radix(h, 16).expect("validated hex digit"));
        i += 2;
    }
    Ok(out)
}

fn squash(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Hex with no separators, upper case: the on-wire form the adapter expects for a PDU.
#[must_use]
pub fn hex_compact(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_frame_reply_parses() {
        let lines = vec!["62 00 2F 6C".to_string()];
        assert_eq!(
            parse_payload("22002F", &lines).unwrap(),
            vec![0x62, 0x00, 0x2F, 0x6C]
        );
    }

    #[test]
    fn multi_frame_reply_reassembles_and_trims_to_length() {
        let lines = vec![
            "22002F".to_string(), // echo (ATE0 off, but filtered defensively)
            "008".to_string(),    // total length 8
            "0:6200112233445566".to_string(),
            "1:7788".to_string(),
        ];
        let got = parse_payload("22002F", &lines).unwrap();
        assert_eq!(got.len(), 8);
        assert_eq!(got, vec![0x62, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn status_words_become_adapter_errors() {
        for word in ["NO DATA", "CAN ERROR", "?", "UNABLE TO CONNECT"] {
            let err = parse_payload("1902AF", &[word.to_string()]).unwrap_err();
            assert!(matches!(err, Error::Adapter(_)), "{word}");
        }
    }

    #[test]
    fn negative_response_is_passed_through_as_a_pdu() {
        // 7F 22 31 is a negative response; the transport is neutral and returns the bytes.
        let lines = vec!["7F 22 31".to_string()];
        assert_eq!(
            parse_payload("22002F", &lines).unwrap(),
            vec![0x7F, 0x22, 0x31]
        );
    }

    #[test]
    fn hex_compact_has_no_separators() {
        assert_eq!(hex_compact(&[0x22, 0x00, 0x2F]), "22002F");
        assert_eq!(hex_compact(&[]), "");
    }

    #[test]
    fn init_sequence_is_the_trial_order() {
        assert_eq!(
            INIT,
            ["ATZ", "ATL0", "ATH0", "ATS0", "ATSP6", "ATE0", "ATCAF1"]
        );
    }
}
