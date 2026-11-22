//! The real-hardware VCX `$1A` identity read command: a **read-only** debugging
//! tool for iterating the dongle exchange against the owner's own vehicle.
//!
//! This is the one CLI path that actually transmits to a vehicle through the
//! VCX-NANO. It is deliberately narrow and loud:
//!
//! - **Read-only.** It builds only two read-only services — TesterPresent
//!   (`$3E 00`, the keep-alive probe) and GMLAN `$1A` ReadDataByIdentifier
//!   (`udskit`, via [`build_identity_request`]) — frames them with the recovered
//!   codecs, and parses the `$7E` / `$5A` replies. A runtime guard (`frame_request`)
//!   refuses to transmit any other service, so it never builds or sends
//!   SecurityAccess `$27`, and no write or actuation is reachable.
//! - **TesterPresent first.** The safest real transmission is `$3E 00`: it reads no
//!   data and changes no state. `--ping` sends only that (the "does the pipe work at
//!   all?" test); the full `$1A` read runs a TesterPresent **preflight** first and
//!   stops, dumping the bytes, if it does not come back positive.
//! - **Owner-gated.** Without `--owner-unhold` it is a **dry run**: it builds and
//!   prints the framed request bytes and the channel-open plan, opens nothing, and
//!   sends nothing. Only with `--owner-unhold` (and a `y` at the confirmation) does
//!   it open the dongle and transmit. The real transmit is Windows-only
//!   (`#[cfg(windows)]`, like [`VcxByteSource::open`](crate::vcx_device::VcxByteSource));
//!   off Windows, or without the flag, it stays a dry run.
//! - **Loud.** Every stage prints hex: the reconstructed `VCX_PRO_Open` frame, the
//!   `VCX_PRO_Send` header template, each framed `$1A` Send PDU, and the raw reply
//!   payload. On a malformed or garbled reply it dumps whatever bytes came back
//!   instead of only erroring, because the point is to learn the real exchange.
//!
//! The exchange was reverse-engineered only partly (`VCX_PRO_Recv` is
//! VMProtect-virtualised and its reply shape was inferred from a secondary parser),
//! so the live exchange is **unproven on hardware**: this command exists to drive it
//! against the real dongle and fix the codecs from the bytes it returns.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::vcx::{DEFAULT_IDENTITY_LIDS, build_identity_request};
use vcxtoolkit::collect::{ISO15765_PROTOCOL, frame_identity_request};
use vcxtoolkit::{Command, open_code, open_payload, pack, pro_send_header};

// The byte seam (open the dongle and exchange) is driven only by the Windows
// live-transmit path and by the tests. On a non-Windows, non-test build these would be
// unused, so they are gated together with their users (`#[cfg(any(windows, test))]`).
#[cfg(any(windows, test))]
use crate::vcx::{ByteSource, parse_identity_reply};
#[cfg(any(windows, test))]
use vcxtoolkit::collect::reply_application_bytes;

/// The default exchange timeout (mirrors `vcx_device::DEFAULT_EXCHANGE_TIMEOUT`).
const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// Parsed `vcx-read` options.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opts {
    /// The COM port number the detection layer found (never hardcoded).
    port: u32,
    /// Explicit owner consent: without it this is a dry run that transmits nothing.
    owner_unhold: bool,
    /// TesterPresent-only mode: transmit just `$3E 00` and stop (the "does the pipe
    /// work at all?" probe). Skips the `$1A` identity loop entirely.
    ping: bool,
    /// The `$1A` identifiers to read, in order.
    lids: Vec<u8>,
    /// Where to write the assembled saved-read, if anywhere.
    out: Option<String>,
    /// The controller name the saved-read is filed under (metadata only).
    ecu: String,
    /// The saved-read request header (metadata only; not the transmitted CAN id).
    req_header: u16,
    /// The saved-read response header (metadata only).
    resp_header: u16,
    /// The VCX framing channel byte (caller-supplied, not recovered).
    channel: u8,
    /// The VCX framing caller byte (caller-supplied, not recovered).
    caller: u8,
    /// Per-step exchange timeout.
    timeout: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            port: 0,
            owner_unhold: false,
            ping: false,
            lids: DEFAULT_IDENTITY_LIDS.to_vec(),
            out: None,
            ecu: "BECM".to_string(),
            req_header: 0x7E4,
            resp_header: 0x7EC,
            channel: 0,
            caller: 0,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

/// Run `vcx-read`. Returns `(exit_code, text)`, like [`crate::cli::run`].
///
/// `confirm` is asked once, before any byte is transmitted, with a one-line
/// description of the read. A dry run never calls it.
#[must_use]
pub fn run(args: &[String], confirm: &mut dyn FnMut(&str) -> bool) -> (i32, String) {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(e) => return (2, format!("{e}\n\n{}", usage())),
    };

    // The real transmit is Windows-only; off Windows we stay a dry run with a note.
    let can_transmit = cfg!(windows);
    if opts.owner_unhold && can_transmit {
        transmit(&opts, confirm)
    } else {
        dry_run(&opts, can_transmit)
    }
}

// ----- dry run (opens nothing, sends nothing) ---------------------------------------------

/// Build and print the framed request bytes and the channel-open plan. No port is
/// opened and no byte is transmitted.
fn dry_run(opts: &Opts, can_transmit: bool) -> (i32, String) {
    let mut log = String::new();
    header(&mut log, opts, "DRY RUN");
    match open_plan_lines(opts) {
        Ok(lines) => log.push_str(&lines),
        Err(e) => return (1, format!("{log}\nerror building open plan: {e}")),
    }

    // The TesterPresent probe is sent first in every real mode (alone for --ping, as
    // the preflight before the $1A loop otherwise). Show it first here too.
    logln(&mut log, "");
    logln(
        &mut log,
        "TesterPresent probe that WOULD be sent FIRST (nothing is transmitted):",
    );
    match frame_for_display(build_tester_present()) {
        Ok((req, framed)) => {
            logln(
                &mut log,
                format!("    UDS request (3E 00):           {}", hex(&req)),
            );
            logln(
                &mut log,
                format!("    framed VCX_PRO_Send PDU:       {}", hex(&framed)),
            );
        }
        Err(e) => return (1, format!("{log}\nerror framing TesterPresent: {e}")),
    }

    if !opts.ping {
        logln(&mut log, "");
        logln(
            &mut log,
            "framed $1A requests that WOULD follow a positive probe (nothing is transmitted):",
        );
        for &lid in &opts.lids {
            match frame_for_display(build_identity_request(lid)) {
                Ok((req, framed)) => {
                    logln(&mut log, format!("  lid {lid:02X}:"));
                    logln(
                        &mut log,
                        format!("    UDS request (udskit 1A <lid>): {}", hex(&req)),
                    );
                    logln(
                        &mut log,
                        format!("    framed VCX_PRO_Send PDU:       {}", hex(&framed)),
                    );
                }
                Err(e) => return (1, format!("{log}\nerror framing lid {lid:02X}: {e}")),
            }
        }
    }

    logln(&mut log, "");
    if opts.owner_unhold && !can_transmit {
        logln(
            &mut log,
            "NOTE: --owner-unhold was given, but the real VCX transmit is Windows-only; \
             staying a dry run on this platform.",
        );
    }
    let what = if opts.ping {
        "the TesterPresent probe above"
    } else {
        "the TesterPresent preflight then the $1A read above"
    };
    logln(
        &mut log,
        format!(
            "DRY RUN COMPLETE: no port opened, no byte sent. Re-run with --owner-unhold on \
             Windows to open the dongle and transmit {what}."
        ),
    );
    (0, log)
}

// ----- the real transmit (Windows-only) ---------------------------------------------------

#[cfg(windows)]
fn transmit(opts: &Opts, confirm: &mut dyn FnMut(&str) -> bool) -> (i32, String) {
    use crate::vcx_device::VcxByteSource;

    let mut log = String::new();
    let mode = if opts.ping {
        "LIVE TesterPresent PROBE (owner-unhold)"
    } else {
        "LIVE READ (owner-unhold)"
    };
    header(&mut log, opts, mode);
    match open_plan_lines(opts) {
        Ok(lines) => log.push_str(&lines),
        Err(e) => return (1, format!("{log}\nerror building open plan: {e}")),
    }

    let prompt = if opts.ping {
        format!(
            "VCX TesterPresent probe ($3E 00) on COM{} — READ-ONLY (reads nothing, no $27, no writes)",
            opts.port
        )
    } else {
        format!(
            "VCX $1A identity READ on COM{} — READ-ONLY (TesterPresent preflight + {} identifiers, no $27, no writes)",
            opts.port,
            opts.lids.len()
        )
    };
    if !confirm(&prompt) {
        logln(&mut log, "");
        logln(
            &mut log,
            "refused: owner consent prompt declined; nothing opened, nothing sent.",
        );
        return (1, log);
    }

    logln(&mut log, "");
    logln(
        &mut log,
        format!("opening VCX-NANO on COM{} ...", opts.port),
    );
    let mut source =
        match VcxByteSource::open_with_params(opts.port, opts.channel, opts.caller, opts.timeout) {
            Ok(s) => s,
            Err(e) => {
                logln(&mut log, format!("  !! could not open the dongle: {e}"));
                return (1, log);
            }
        };
    logln(&mut log, "  dongle port opened (no vehicle byte sent yet).");

    // TesterPresent first: the safest real transmission. For --ping it is the whole
    // job; otherwise it is the preflight, and a non-positive answer stops the read.
    logln(&mut log, "");
    logln(&mut log, "TesterPresent probe ($3E 00):");
    let proven = tester_present(&mut source, &mut log);
    if opts.ping {
        logln(&mut log, "");
        return if proven.is_ok() {
            logln(
                &mut log,
                "PROBE OK: the VCX exchange is proven on this vehicle. Re-run without --ping \
                 to read the $1A identities.",
            );
            (0, log)
        } else {
            logln(
                &mut log,
                "PROBE FAILED: the pipe did not return a positive $7E (bytes above). Debug the \
                 VCX transport on this simplest case before attempting the $1A read.",
            );
            (1, log)
        };
    }
    let Ok(proof) = proven else {
        logln(&mut log, "");
        logln(
            &mut log,
            "PREFLIGHT FAILED: TesterPresent did not return a positive $7E (bytes above). \
             Stopping before the $1A read — the transport is not proven, so a $1A attempt \
             would only add noise. Fix the probe first (or re-run with --ping to iterate it).",
        );
        return (1, log);
    };

    let code = read_identities_live(&mut source, opts, &mut log, proof);
    (code, log)
}

#[cfg(not(windows))]
fn transmit(opts: &Opts, _confirm: &mut dyn FnMut(&str) -> bool) -> (i32, String) {
    // Unreachable from `run` off Windows (it routes to `dry_run`); kept so the symbol
    // exists on every platform.
    dry_run(opts, false)
}

/// Run the `$1A` identity loop over `source` (the TesterPresent preflight already
/// passed), assemble and serialize the saved-read, and write `--out` if set.
/// Returns the process exit code. Driven over any [`ByteSource`], so it is unit-tested
/// over the fake serial. It is reached only from the Windows `transmit`.
///
/// The `_proof: PipeProven` parameter is the gate: this function cannot be called
/// without a token minted by a positive [`tester_present`], so the `$1A` read is
/// structurally unreachable until the pipe is proven.
#[cfg(windows)]
fn read_identities_live(
    source: &mut dyn ByteSource,
    opts: &Opts,
    log: &mut String,
    _proof: PipeProven,
) -> i32 {
    let mut reads = Vec::new();
    let mut failures = 0u32;
    logln(log, "");
    for &lid in &opts.lids {
        logln(log, format!("lid {lid:02X}:"));
        match read_one_identity(source, lid, log) {
            Ok(read) => reads.push(read),
            Err(_) => failures += 1,
        }
    }

    logln(log, "");
    if reads.is_empty() {
        logln(
            log,
            "no identities read: every exchange failed (see the byte dumps above). The live \
             exchange is unproven on hardware — these raw bytes are how we fix the codecs.",
        );
        return 1;
    }

    let read_count = opts.lids.len() - failures as usize;
    match crate::vcx::assemble_module_read(
        &opts.ecu,
        opts.req_header,
        opts.resp_header,
        false,
        reads,
    )
    .and_then(|block| crate::vcx::serialize_saved_read(&[block]))
    {
        Ok(saved) => {
            logln(
                log,
                format!(
                    "parsed {read_count} identit{} ({failures} failed). saved-read ({}):",
                    if read_count == 1 { "y" } else { "ies" },
                    opts.ecu
                ),
            );
            for line in saved.lines() {
                logln(log, format!("  {line}"));
            }
            if let Some(path) = &opts.out {
                match std::fs::write(path, &saved) {
                    Ok(()) => logln(log, format!("wrote saved-read to {path}")),
                    Err(e) => logln(log, format!("could not write {path}: {e}")),
                }
            }
        }
        Err(e) => logln(log, format!("could not assemble the saved-read: {e}")),
    }

    logln(
        log,
        "DONE. Reminder: this exchange is unproven on hardware; if the bytes above look \
         garbled, that is the data we iterate the VCX codecs from.",
    );
    0
}

// ----- the staged, logged exchange (testable over any ByteSource) -------------------------

/// The only services this command may ever transmit — both read-only: TesterPresent
/// (`$3E`) and GMLAN ReadDataByIdentifier (`$1A`). The guard in [`frame_request`]
/// refuses anything else, so `$27` or any write service can never reach the wire.
const ALLOWED_SERVICES: [u8; 2] = [
    udskit::testerpresent::TESTER_PRESENT,
    crate::vcx::GM_READ_DATA_BY_IDENTIFIER,
];

/// Build the TesterPresent request (`$3E 00`): the keep-alive, read-nothing probe.
fn build_tester_present() -> Vec<u8> {
    udskit::testerpresent::build_request()
}

/// Frame a UDS request for the VCX send codec, refusing any service not in
/// [`ALLOWED_SERVICES`].
///
/// This is the hard read-only gate: it is a runtime check (not a debug assert), so a
/// release build cannot transmit a write or `$27` even if a future caller tried.
///
/// # Errors
/// [`Error::Refused`] when `uds` is empty or its service id is not read-only;
/// [`Error::from`] on a framing error.
fn frame_request(uds: &[u8]) -> Result<Vec<u8>> {
    let sid = uds.first().copied();
    if !sid.is_some_and(|s| ALLOWED_SERVICES.contains(&s)) {
        return Err(Error::Refused(format!(
            "vcx-read refuses service {}: only read-only $3E and $1A may be transmitted",
            sid.map_or_else(|| "(none)".to_string(), |s| format!("{s:#04X}"))
        )));
    }
    Ok(frame_identity_request(uds)?)
}

/// Frame, exchange, and unwrap one request over `source`, logging every stage's bytes.
///
/// Drives the seam in stages — frame, exchange, unwrap envelope — so the raw reply
/// payload is logged before any application parse can discard it: on a malformed or
/// garbled reply the bytes are dumped, not swallowed. Returns the application PDU
/// (ready for `udskit`), or the error (already logged).
#[cfg(any(windows, test))]
fn exchange_and_unwrap(
    source: &mut dyn ByteSource,
    uds: &[u8],
    log: &mut String,
) -> Result<Vec<u8>> {
    let framed = frame_request(uds)?;
    logln(log, format!("  -> UDS request:             {}", hex(uds)));
    logln(
        log,
        format!("  -> framed VCX_PRO_Send PDU: {}", hex(&framed)),
    );

    let payload = match source.exchange(&framed) {
        Ok(p) => p,
        Err(e) => {
            logln(
                log,
                format!("  !! exchange failed; no reply bytes recovered: {e}"),
            );
            return Err(e);
        }
    };
    logln(
        log,
        format!(
            "  <- raw reply payload (VCX_PRO_Recv envelope): {}",
            hex(&payload)
        ),
    );

    match reply_application_bytes(&payload) {
        Ok(app) => {
            logln(log, format!("  <- application PDU:         {}", hex(app)));
            Ok(app.to_vec())
        }
        Err(e) => {
            logln(
                log,
                format!("  !! reply envelope malformed (raw bytes above): {e}"),
            );
            Err(e.into())
        }
    }
}

/// Proof that the VCX pipe answered a TesterPresent with a positive `$7E`.
///
/// This is an internal capability token, in the spirit of the crate's other gates
/// (`session::Arm`, `vcxtoolkit::collect::vehicle_read_gate`): it is zero-sized and
/// only [`tester_present`] mints one, so the `$1A` identity loop
/// ([`read_identities_live`]) — which **requires** a `PipeProven` — is structurally
/// unreachable until the probe has come back positive. A future caller cannot forget
/// the preflight; the type system forbids skipping it.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy)]
#[must_use]
struct PipeProven(());

/// Send TesterPresent (`$3E 00`) and, on a positive `$7E`, mint the [`PipeProven`]
/// token that unlocks the `$1A` read.
///
/// This is the safest real transmission: it reads no data and changes no state, so it
/// is the first probe (via `--ping`) and the preflight before the `$1A` loop. On any
/// non-positive answer the bytes are already dumped by [`exchange_and_unwrap`] and no
/// token is returned, so the read cannot proceed.
///
/// # Errors
/// Transport/envelope errors from [`exchange_and_unwrap`]; [`Error::Negative`] on a
/// `0x7F` answer; [`Error::Protocol`] when the positive response id is not `$7E`.
#[cfg(any(windows, test))]
fn tester_present(source: &mut dyn ByteSource, log: &mut String) -> Result<PipeProven> {
    use udskit::message::{Response, decode_response};

    let app = exchange_and_unwrap(source, &build_tester_present(), log)?;
    match decode_response(&app)? {
        Response::Positive(p) if p.response_sid == TESTER_PRESENT_POSITIVE_SID => {
            logln(
                log,
                "  == TesterPresent OK (positive $7E) — the VCX pipe works; $1A read unlocked.",
            );
            Ok(PipeProven(()))
        }
        Response::Positive(p) => {
            let e = Error::Protocol(format!(
                "TesterPresent got response id {:#04X}, not $7E",
                p.response_sid
            ));
            logln(log, format!("  !! {e}"));
            Err(e)
        }
        Response::Negative(n) => {
            let e = Error::Negative(n.describe());
            logln(log, format!("  !! TesterPresent negative: {e}"));
            Err(e)
        }
    }
}

/// The positive-response id for TesterPresent (`$3E | 0x40`).
#[cfg(any(windows, test))]
const TESTER_PRESENT_POSITIVE_SID: u8 = udskit::testerpresent::TESTER_PRESENT | 0x40;

/// Read one `$1A` identity over `source`, logging every stage's bytes.
///
/// Returns the parsed [`IdentifierRead`](vcxtoolkit::modread::IdentifierRead), or the
/// error (already logged) on failure.
#[cfg(any(windows, test))]
fn read_one_identity(
    source: &mut dyn ByteSource,
    lid: u8,
    log: &mut String,
) -> Result<vcxtoolkit::modread::IdentifierRead> {
    let app = exchange_and_unwrap(source, &build_identity_request(lid), log)?;
    match parse_identity_reply(&app, lid) {
        Ok(value) => {
            logln(
                log,
                format!("  == identity {lid:02X} value:       {}", hex(&value)),
            );
            Ok(vcxtoolkit::modread::IdentifierRead::lid(lid, value))
        }
        Err(e) => {
            logln(
                log,
                format!("  !! could not parse reply (raw/app bytes above): {e}"),
            );
            Err(e)
        }
    }
}

/// Build and frame one request for the dry-run display, returning `(uds, framed)`.
///
/// Routed through [`frame_request`], so the dry run shows exactly the bytes the live
/// path would send and inherits the same read-only guard.
fn frame_for_display(uds: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let framed = frame_request(&uds)?;
    Ok((uds, framed))
}

// ----- shared report pieces ---------------------------------------------------------------

fn header(log: &mut String, opts: &Opts, mode: &str) {
    logln(log, format!("gmdiag vcx-read — {mode}"));
    let scope = if opts.ping {
        "TesterPresent $3E 00 only".to_string()
    } else {
        format!(
            "ecu {}  lids {}",
            opts.ecu,
            opts.lids
                .iter()
                .map(|l| format!("{l:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    logln(
        log,
        format!(
            "  port COM{}  {scope}  (READ-ONLY: $3E/$1A only, no $27, no writes)",
            opts.port
        ),
    );
}

/// The reconstructed channel-open plan: the recovered ISO 15765 open dword, the
/// packed `VCX_PRO_Open` frame, and the `VCX_PRO_Send` header template. These are
/// what vcxtoolkit's `Channel` writes; printing them makes the open legible.
fn open_plan_lines(opts: &Opts) -> Result<String> {
    let mut out = String::new();
    let dword = open_code(ISO15765_PROTOCOL)?;
    let payload = open_payload(ISO15765_PROTOCOL)?;
    let open_frame = pack(Command::ProOpen.header(opts.channel), &payload)
        .map_err(|e| Error::Protocol(format!("pack VCX_PRO_Open: {e}")))?;
    let send_header = pro_send_header(opts.caller, opts.channel);

    logln(&mut out, "channel-open plan (ISO 15765, recovered):");
    logln(&mut out, format!("  VCX_PRO_Open dword:  {dword:#06X}"));
    logln(
        &mut out,
        format!("  VCX_PRO_Open frame:  {}", hex(&open_frame)),
    );
    logln(
        &mut out,
        format!("  VCX_PRO_Send header: {}", hex(&send_header)),
    );
    logln(
        &mut out,
        format!(
            "  channel byte {:#04X}  caller byte {:#04X}  timeout {}ms",
            opts.channel,
            opts.caller,
            opts.timeout.as_millis()
        ),
    );
    Ok(out)
}

// ----- parsing ----------------------------------------------------------------------------

fn parse(args: &[String]) -> Result<Opts> {
    let mut opts = Opts::default();
    let mut port_set = false;
    let mut lids: Vec<u8> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--owner-unhold" => opts.owner_unhold = true,
            "--ping" => opts.ping = true,
            "--port" => {
                opts.port = parse_port(next(&mut it, "--port")?)?;
                port_set = true;
            }
            "--lid" => lids.push(parse_u8(next(&mut it, "--lid")?)?),
            "--out" => opts.out = Some(next(&mut it, "--out")?.clone()),
            "--ecu" => opts.ecu.clone_from(next(&mut it, "--ecu")?),
            "--req" => opts.req_header = parse_u16(next(&mut it, "--req")?)?,
            "--resp" => opts.resp_header = parse_u16(next(&mut it, "--resp")?)?,
            "--channel" => opts.channel = parse_u8(next(&mut it, "--channel")?)?,
            "--caller" => opts.caller = parse_u8(next(&mut it, "--caller")?)?,
            "--timeout-ms" => {
                let v = next(&mut it, "--timeout-ms")?;
                let ms = v
                    .parse::<u64>()
                    .map_err(|_| Error::Refused(format!("{v:?} is not a millisecond count")))?;
                opts.timeout = Duration::from_millis(ms);
            }
            other => {
                return Err(Error::Refused(format!(
                    "vcx-read: unexpected argument {other:?}; try `gmdiag help`"
                )));
            }
        }
    }
    if !port_set {
        return Err(Error::Refused(
            "vcx-read needs --port <N> (the COM number the doctor/detection layer found)".into(),
        ));
    }
    if !lids.is_empty() {
        opts.lids = lids;
    }
    Ok(opts)
}

fn next<'a>(it: &mut std::slice::Iter<'a, String>, flag: &str) -> Result<&'a String> {
    it.next()
        .ok_or_else(|| Error::Refused(format!("{flag} needs a value")))
}

/// Parse a COM port: accepts `COM4`, `com4`, or a bare `4`.
fn parse_port(s: &str) -> Result<u32> {
    let t = s.trim();
    let digits = t
        .strip_prefix("COM")
        .or_else(|| t.strip_prefix("com"))
        .unwrap_or(t);
    digits
        .parse::<u32>()
        .map_err(|_| Error::Refused(format!("{s:?} is not a COM port number")))
}

fn parse_u8(s: &str) -> Result<u8> {
    u8::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Refused(format!("{s:?} is not a byte hex value")))
}

fn parse_u16(s: &str) -> Result<u16> {
    u16::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Refused(format!("{s:?} is not a 16-bit hex value")))
}

/// Spaced, upper-case hex, or `(empty)` for no bytes.
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".to_string();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn logln(log: &mut String, line: impl AsRef<str>) {
    log.push_str(line.as_ref());
    log.push('\n');
}

/// The `vcx-read` usage block, folded into the CLI's help.
#[must_use]
pub fn usage() -> String {
    "gmdiag vcx-read — real VCX-NANO $1A identity read (READ-ONLY, owner-gated).\n\
     \n\
     USAGE: gmdiag vcx-read --port <N> [--owner-unhold] [options]\n\
     \n\
     \u{20}  --port <N>         COM number the doctor/detection layer found (COM4, com4, or 4)\n\
     \u{20}  --owner-unhold     owner consent: open the dongle and TRANSMIT (without it, and\n\
     \u{20}                     off Windows, this is a dry run: nothing is sent)\n\
     \u{20}  --ping             send only TesterPresent ($3E 00) — the safest first probe:\n\
     \u{20}                     proves the VCX pipe works before any data read\n\
     \u{20}  --lid <hex>        a $1A identifier to read (repeatable; default C1..CA, CB, CC)\n\
     \u{20}  --out <file>       write the assembled saved-read to <file>\n\
     \u{20}  --ecu <name>       saved-read controller name (metadata; default BECM)\n\
     \u{20}  --req <hex>        saved-read request header (metadata; default 7E4)\n\
     \u{20}  --resp <hex>       saved-read response header (metadata; default 7EC)\n\
     \u{20}  --channel <hex>    VCX framing channel byte (default 00)\n\
     \u{20}  --caller <hex>     VCX framing caller byte (default 00)\n\
     \u{20}  --timeout-ms <n>   per-step exchange timeout (default 2000)\n\
     \n\
     Read-only: builds only TesterPresent $3E and GMLAN $1A, never $27, no write or\n\
     actuation. The full read runs a TesterPresent preflight first and stops if it is\n\
     not positive. Every stage prints hex (open frame, each Send PDU, raw reply). The\n\
     live exchange is unproven on hardware; this command exists to drive it and fix\n\
     the codecs from real bytes."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vcx::{FakeByteSource, GM_IDENTITY_POSITIVE_SID};

    fn reply_pdu(app: &[u8]) -> Vec<u8> {
        // The recovered VCX_PRO_Recv envelope: flags u32 LE, len u16 LE, then app bytes.
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&0_u32.to_le_bytes());
        pdu.extend_from_slice(&u16::try_from(app.len()).unwrap().to_le_bytes());
        pdu.extend_from_slice(app);
        pdu
    }

    fn positive(lid: u8, value: &[u8]) -> Vec<u8> {
        let mut app = vec![GM_IDENTITY_POSITIVE_SID, lid];
        app.extend_from_slice(value);
        reply_pdu(&app)
    }

    /// A positive TesterPresent reply: `$7E 00`.
    fn tp_positive() -> Vec<u8> {
        reply_pdu(&[TESTER_PRESENT_POSITIVE_SID, 0x00])
    }

    #[test]
    fn parse_requires_a_port() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["--owner-unhold".into()]).is_err());
        let o = parse(&["--port".into(), "4".into()]).unwrap();
        assert_eq!(o.port, 4);
        assert!(!o.owner_unhold);
        assert_eq!(o.lids, DEFAULT_IDENTITY_LIDS.to_vec());
    }

    #[test]
    fn parse_accepts_com_forms_and_flags() {
        for form in ["COM4", "com4", "4"] {
            assert_eq!(parse_port(form).unwrap(), 4);
        }
        assert!(parse_port("ttyUSB0").is_err());
        let o = parse(&[
            "--port".into(),
            "COM7".into(),
            "--owner-unhold".into(),
            "--lid".into(),
            "C1".into(),
            "--lid".into(),
            "CC".into(),
            "--out".into(),
            "r.txt".into(),
            "--ecu".into(),
            "EBCM".into(),
        ])
        .unwrap();
        assert_eq!(o.port, 7);
        assert!(o.owner_unhold);
        assert_eq!(o.lids, vec![0xC1, 0xCC]);
        assert_eq!(o.out.as_deref(), Some("r.txt"));
        assert_eq!(o.ecu, "EBCM");
    }

    #[test]
    fn frame_request_allows_only_read_only_services() {
        // $1A and $3E frame; the framed Send PDU carries the app bytes at offset 6.
        assert_eq!(
            frame_request(&[0x1A, 0xC1]).unwrap(),
            vec![0, 0, 0, 0, 0, 2, 0x1A, 0xC1]
        );
        assert_eq!(
            frame_request(&build_tester_present()).unwrap(),
            vec![0, 0, 0, 0, 0, 2, 0x3E, 0x00]
        );
        // The guard is a hard runtime refusal: $27 SecurityAccess and $2E write and an
        // empty request are all rejected before any byte could be framed.
        for bad in [vec![0x27, 0x01], vec![0x2E, 0xC1, 0x00], Vec::new()] {
            let err = frame_request(&bad).unwrap_err();
            assert!(matches!(err, Error::Refused(_)), "{err:?}");
        }
    }

    #[test]
    fn frame_for_display_routes_through_the_guard() {
        // The dry-run display builder shows exactly the live bytes and inherits the guard.
        let (uds, framed) = frame_for_display(build_identity_request(0xCC)).unwrap();
        assert_eq!(uds, vec![0x1A, 0xCC]);
        assert_eq!(framed, vec![0, 0, 0, 0, 0, 2, 0x1A, 0xCC]);
        assert!(frame_for_display(vec![0x27, 0x01]).is_err());
    }

    #[test]
    fn tester_present_confirms_a_positive_7e() {
        let mut source = FakeByteSource::new(vec![tp_positive()]);
        let mut log = String::new();
        assert!(tester_present(&mut source, &mut log).is_ok());
        assert!(log.contains("3E 00"), "the $3E 00 request is logged: {log}");
        assert!(log.contains("raw reply payload"), "{log}");
        assert!(log.contains("TesterPresent OK"), "{log}");
        // The exact framed $3E 00 reached the seam.
        assert_eq!(source.sent(), &[vec![0, 0, 0, 0, 0, 2, 0x3E, 0x00]]);
    }

    #[test]
    fn tester_present_dumps_a_non_positive_answer() {
        // A negative $7F to $3E: Err, and the raw bytes are dumped, not swallowed.
        let mut source = FakeByteSource::new(vec![reply_pdu(&[0x7F, 0x3E, 0x11])]);
        let mut log = String::new();
        let err = tester_present(&mut source, &mut log).unwrap_err();
        assert!(matches!(err, Error::Negative(_)), "{err:?}");
        assert!(log.contains("7F 3E 11"), "raw reply must be dumped: {log}");
        assert!(log.contains("TesterPresent negative"), "{log}");
    }

    #[test]
    fn tester_present_refuses_a_wrong_positive_id() {
        // A positive reply that is not $7E (here $5A) is refused with the bytes dumped.
        let mut source = FakeByteSource::new(vec![reply_pdu(&[0x5A, 0x00])]);
        let mut log = String::new();
        let err = tester_present(&mut source, &mut log).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "{err:?}");
        assert!(log.contains("5A 00"), "{log}");
    }

    #[test]
    fn read_one_identity_logs_bytes_and_parses() {
        let mut source = FakeByteSource::new(vec![positive(0xC1, &[0x31, 0x32])]);
        let mut log = String::new();
        let read = read_one_identity(&mut source, 0xC1, &mut log).unwrap();
        assert_eq!(
            read,
            vcxtoolkit::modread::IdentifierRead::lid(0xC1, vec![0x31, 0x32])
        );
        // The framed request and the raw reply are both in the log.
        assert!(log.contains("1A C1"), "{log}");
        assert!(log.contains("raw reply payload"), "{log}");
        assert!(log.contains("5A C1 31 32"), "{log}");
        assert!(log.contains("identity C1 value"), "{log}");
        // The exact framed bytes reached the seam.
        assert_eq!(source.sent(), &[vec![0, 0, 0, 0, 0, 2, 0x1A, 0xC1]]);
    }

    #[test]
    fn read_one_identity_dumps_a_garbled_reply_instead_of_swallowing_it() {
        // A positive $5A for the WRONG identifier: the parse fails, but the raw bytes
        // were already logged, which is the whole point of the tool.
        let mut source = FakeByteSource::new(vec![positive(0xC2, &[0xAB])]);
        let mut log = String::new();
        let err = read_one_identity(&mut source, 0xC1, &mut log).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "{err:?}");
        assert!(log.contains("5A C2 AB"), "raw reply must be dumped: {log}");
        assert!(log.contains("could not parse reply"), "{log}");
    }

    #[test]
    fn read_one_identity_dumps_a_short_envelope() {
        let mut source = FakeByteSource::new(vec![vec![0x00, 0x00]]);
        let mut log = String::new();
        assert!(read_one_identity(&mut source, 0xC1, &mut log).is_err());
        assert!(log.contains("raw reply payload"), "{log}");
        assert!(log.contains("envelope malformed"), "{log}");
    }

    #[test]
    fn read_one_identity_reports_an_exchange_failure() {
        // An empty fake seam errors on exchange: no reply bytes, logged as such.
        let mut source = FakeByteSource::new(vec![]);
        let mut log = String::new();
        assert!(read_one_identity(&mut source, 0xC1, &mut log).is_err());
        assert!(log.contains("exchange failed"), "{log}");
    }

    #[test]
    fn dry_run_prints_the_plan_and_sends_nothing() {
        let opts = parse(&["--port".into(), "4".into()]).unwrap();
        let (code, text) = dry_run(&opts, true);
        assert_eq!(code, 0);
        assert!(text.contains("DRY RUN"), "{text}");
        assert!(text.contains("VCX_PRO_Open frame"), "{text}");
        // The TesterPresent preflight is shown first, then every default lid.
        assert!(text.contains("3E 00"), "preflight probe shown: {text}");
        assert!(text.contains("1A C1"), "{text}");
        assert!(text.contains("1A CC"), "{text}");
        assert!(text.contains("no port opened, no byte sent"), "{text}");
        // Read-only: nothing resembling a SecurityAccess $27 request is built.
        assert!(
            !text.contains("27 "),
            "dry run must never frame a $27: {text}"
        );
    }

    #[test]
    fn dry_run_ping_shows_only_tester_present() {
        let opts = parse(&["--port".into(), "4".into(), "--ping".into()]).unwrap();
        assert!(opts.ping);
        let (code, text) = dry_run(&opts, true);
        assert_eq!(code, 0);
        // The $3E 00 probe is shown; no $1A identity request is.
        assert!(text.contains("3E 00"), "{text}");
        assert!(text.contains("TesterPresent $3E 00 only"), "{text}");
        assert!(!text.contains("1A C1"), "ping shows no $1A read: {text}");
        assert!(text.contains("the TesterPresent probe above"), "{text}");
    }

    #[test]
    fn dry_run_notes_when_owner_unhold_cannot_transmit() {
        // owner_unhold set but the platform cannot transmit: still a dry run, with a note.
        let mut opts = parse(&["--port".into(), "4".into(), "--owner-unhold".into()]).unwrap();
        opts.lids = vec![0xC1];
        let (code, text) = dry_run(&opts, false);
        assert_eq!(code, 0);
        assert!(text.contains("Windows-only"), "{text}");
    }

    #[test]
    fn run_without_owner_unhold_is_a_dry_run() {
        let mut no = |_: &str| false;
        let (code, text) = run(&["--port".into(), "4".into()], &mut no);
        assert_eq!(code, 0);
        assert!(text.contains("DRY RUN"), "{text}");
    }

    #[test]
    fn run_rejects_a_missing_port() {
        let mut yes = |_: &str| true;
        let (code, text) = run(&["--owner-unhold".into()], &mut yes);
        assert_eq!(code, 2);
        assert!(text.contains("needs --port"), "{text}");
    }

    #[cfg(windows)]
    #[test]
    fn read_identities_live_assembles_over_the_fake_serial() {
        // The $1A loop is gated by a PipeProven token: the test earns it by running the
        // TesterPresent probe first (positive $7E), then reads two identities.
        let mut source = FakeByteSource::new(vec![
            tp_positive(),
            positive(0xC1, &[0x00, 0x00, 0x00, 0x2A]),
            positive(0xCC, &[0x56, 0x49, 0x4E]),
        ]);
        let mut opts = parse(&["--port".into(), "4".into()]).unwrap();
        opts.lids = vec![0xC1, 0xCC];
        let mut log = String::new();
        let proof = tester_present(&mut source, &mut log).expect("probe positive");
        let code = read_identities_live(&mut source, &opts, &mut log, proof);
        assert_eq!(code, 0);
        assert!(log.contains("lid C1 0000002A"), "{log}");
        assert!(log.contains("lid CC 56494E"), "{log}");
        assert!(log.contains("parsed 2 identities (0 failed)"), "{log}");
    }

    #[cfg(windows)]
    #[test]
    fn read_identities_live_reports_total_failure() {
        // Probe positive earns the token; then every $1A exchange fails (seam drained):
        // exit code 1, with the byte-dump reminder.
        let mut source = FakeByteSource::new(vec![tp_positive()]);
        let mut opts = parse(&["--port".into(), "4".into()]).unwrap();
        opts.lids = vec![0xC1];
        let mut log = String::new();
        let proof = tester_present(&mut source, &mut log).expect("probe positive");
        assert_eq!(read_identities_live(&mut source, &opts, &mut log, proof), 1);
        assert!(log.contains("no identities read"), "{log}");
    }
}
