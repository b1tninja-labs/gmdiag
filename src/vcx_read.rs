//! The real-hardware VCX `$1A` identity read command: a **read-only** debugging
//! tool for iterating the dongle exchange against the owner's own vehicle.
//!
//! This is the one CLI path that actually transmits to a vehicle through the
//! VCX-NANO. It is deliberately narrow and loud:
//!
//! - **Read-only.** It builds only the GMLAN `$1A` ReadDataByIdentifier request
//!   (`udskit`, via [`build_identity_request`]),
//!   frames it with the recovered codecs, and parses the `$5A` reply. It never
//!   builds or sends SecurityAccess `$27`, and no write or actuation service is
//!   reachable from here.
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
use crate::vcx::{ByteSource, DEFAULT_IDENTITY_LIDS, build_identity_request, parse_identity_reply};
use vcxtoolkit::collect::{ISO15765_PROTOCOL, frame_identity_request, reply_application_bytes};
use vcxtoolkit::{Command, open_code, open_payload, pack, pro_send_header};

/// The default exchange timeout (mirrors `vcx_device::DEFAULT_EXCHANGE_TIMEOUT`).
const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// Parsed `vcx-read` options.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opts {
    /// The COM port number the detection layer found (never hardcoded).
    port: u32,
    /// Explicit owner consent: without it this is a dry run that transmits nothing.
    owner_unhold: bool,
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

    logln(&mut log, "");
    logln(
        &mut log,
        "framed $1A requests that WOULD be sent (nothing is transmitted):",
    );
    for &lid in &opts.lids {
        match frame_lid(lid) {
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

    logln(&mut log, "");
    if opts.owner_unhold && !can_transmit {
        logln(
            &mut log,
            "NOTE: --owner-unhold was given, but the real VCX transmit is Windows-only; \
             staying a dry run on this platform.",
        );
    }
    logln(
        &mut log,
        "DRY RUN COMPLETE: no port opened, no byte sent. Re-run with --owner-unhold on \
         Windows to open the dongle and transmit the $1A read above.",
    );
    (0, log)
}

// ----- the real transmit (Windows-only) ---------------------------------------------------

#[cfg(windows)]
fn transmit(opts: &Opts, confirm: &mut dyn FnMut(&str) -> bool) -> (i32, String) {
    use crate::vcx_device::VcxByteSource;

    let mut log = String::new();
    header(&mut log, opts, "LIVE READ (owner-unhold)");
    match open_plan_lines(opts) {
        Ok(lines) => log.push_str(&lines),
        Err(e) => return (1, format!("{log}\nerror building open plan: {e}")),
    }

    let prompt = format!(
        "VCX $1A identity READ on COM{} — READ-ONLY ({} identifiers, no $27, no writes)",
        opts.port,
        opts.lids.len()
    );
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

    let mut reads = Vec::new();
    let mut failures = 0u32;
    logln(&mut log, "");
    for &lid in &opts.lids {
        logln(&mut log, format!("lid {lid:02X}:"));
        match read_one_identity(&mut source, lid, &mut log) {
            Ok(read) => reads.push(read),
            Err(_) => failures += 1,
        }
    }

    logln(&mut log, "");
    if reads.is_empty() {
        logln(
            &mut log,
            "no identities read: every exchange failed (see the byte dumps above). The live \
             exchange is unproven on hardware — these raw bytes are how we fix the codecs.",
        );
        return (1, log);
    }

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
                &mut log,
                format!(
                    "parsed {} identit{} ({} failed). saved-read ({}):",
                    opts.lids.len() - failures as usize,
                    if opts.lids.len() - failures as usize == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    failures,
                    opts.ecu
                ),
            );
            for line in saved.lines() {
                logln(&mut log, format!("  {line}"));
            }
            if let Some(path) = &opts.out {
                match std::fs::write(path, &saved) {
                    Ok(()) => logln(&mut log, format!("wrote saved-read to {path}")),
                    Err(e) => logln(&mut log, format!("could not write {path}: {e}")),
                }
            }
        }
        Err(e) => logln(&mut log, format!("could not assemble the saved-read: {e}")),
    }

    logln(
        &mut log,
        "DONE. Reminder: this exchange is unproven on hardware; if the bytes above look \
         garbled, that is the data we iterate the VCX codecs from.",
    );
    (0, log)
}

#[cfg(not(windows))]
fn transmit(opts: &Opts, _confirm: &mut dyn FnMut(&str) -> bool) -> (i32, String) {
    // Unreachable from `run` off Windows (it routes to `dry_run`); kept so the symbol
    // exists on every platform.
    dry_run(opts, false)
}

// ----- the staged, logged single-identity read (testable over any ByteSource) -------------

/// Read one `$1A` identity over `source`, logging every stage's bytes.
///
/// This drives the seam in stages — frame, exchange, unwrap envelope, parse — so the
/// raw reply payload is logged before any parse can discard it: on a malformed or
/// garbled reply the bytes are dumped, not swallowed. Returns the parsed
/// [`IdentifierRead`](vcxtoolkit::modread::IdentifierRead), or the error (already
/// logged) on failure.
fn read_one_identity(
    source: &mut dyn ByteSource,
    lid: u8,
    log: &mut String,
) -> Result<vcxtoolkit::modread::IdentifierRead> {
    let (req, framed) = frame_lid(lid)?;
    logln(log, format!("  -> UDS request (1A <lid>):  {}", hex(&req)));
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

    let app = match reply_application_bytes(&payload) {
        Ok(a) => a,
        Err(e) => {
            logln(
                log,
                format!("  !! reply envelope malformed (raw bytes above): {e}"),
            );
            return Err(e.into());
        }
    };
    logln(log, format!("  <- application PDU:         {}", hex(app)));

    match parse_identity_reply(app, lid) {
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

/// Build and frame the read request for one identifier.
///
/// `build_identity_request` is `udskit`'s `1A <lid>`; it is asserted to be a `$1A`
/// read here so no other service can slip through this command.
fn frame_lid(lid: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let req = build_identity_request(lid);
    // Read-only guard: this command only ever sends GMLAN $1A.
    debug_assert_eq!(
        req.first().copied(),
        Some(crate::vcx::GM_READ_DATA_BY_IDENTIFIER)
    );
    let framed = frame_identity_request(&req)?;
    Ok((req, framed))
}

// ----- shared report pieces ---------------------------------------------------------------

fn header(log: &mut String, opts: &Opts, mode: &str) {
    logln(log, format!("gmdiag vcx-read — {mode}"));
    logln(
        log,
        format!(
            "  port COM{}  ecu {}  lids {}  (READ-ONLY: $1A only, no $27, no writes)",
            opts.port,
            opts.ecu,
            opts.lids
                .iter()
                .map(|l| format!("{l:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
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
     \u{20}  --owner-unhold     owner consent: open the dongle and TRANSMIT the $1A read\n\
     \u{20}                     (without it, and off Windows, this is a dry run: nothing is sent)\n\
     \u{20}  --lid <hex>        a $1A identifier to read (repeatable; default C1..CA, CB, CC)\n\
     \u{20}  --out <file>       write the assembled saved-read to <file>\n\
     \u{20}  --ecu <name>       saved-read controller name (metadata; default BECM)\n\
     \u{20}  --req <hex>        saved-read request header (metadata; default 7E4)\n\
     \u{20}  --resp <hex>       saved-read response header (metadata; default 7EC)\n\
     \u{20}  --channel <hex>    VCX framing channel byte (default 00)\n\
     \u{20}  --caller <hex>     VCX framing caller byte (default 00)\n\
     \u{20}  --timeout-ms <n>   per-step exchange timeout (default 2000)\n\
     \n\
     Read-only: builds only GMLAN $1A, never $27, no write or actuation. Every stage\n\
     prints hex (open frame, each Send PDU, raw reply). The live exchange is unproven\n\
     on hardware; this command exists to drive it and fix the codecs from real bytes."
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
    fn frame_lid_builds_only_1a_reads() {
        // The read-only invariant: the request service is always $1A, never $27.
        for lid in [0xC1u8, 0xCC, 0x03] {
            let (req, framed) = frame_lid(lid).unwrap();
            assert_eq!(req, vec![0x1A, lid]);
            assert_ne!(
                req[0], 0x27,
                "a $1A read must never be a SecurityAccess $27"
            );
            // The framed Send PDU carries the two app bytes at offset 6.
            assert_eq!(framed, vec![0, 0, 0, 0, 0, 2, 0x1A, lid]);
        }
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
        // Every default lid's framed request is present.
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
}
