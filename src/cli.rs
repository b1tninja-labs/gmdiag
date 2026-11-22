//! The gmdiag command line: read-first, with every write and actuation gated.
//!
//! [`run`] takes the argument vector and a confirmation callback and returns an exit code and the
//! text to print, so the whole CLI is testable without spawning a process. The binary's `main`
//! passes a callback that reads `y/N` from the terminal; tests pass a closure.
//!
//! Reads (`scan`, `did`, `seed`, `mode06`, `session`, `catalog`) run with no flag. Writes
//! (`write`, `clear`) need `--write`; actuation (`routine` start/stop, `iocontrol`, `sendkey`)
//! needs `--actuate`. Each gated command also asks the confirmation callback before it sends.
//!
//! Actuation has a second gate on top of the arm level: an [`Authorizer`](crate::authorizer). By
//! default it is [`NoAuthorizer`](crate::authorizer::NoAuthorizer), so `sendkey`, `routine`
//! start/stop and `iocontrol` are refused — gmdiag unlocks nothing on its own authority and holds
//! no key material. `--techline` installs the [`TechlinekitAuthorizer`], which delegates to the
//! operator's authenticated techlinekit subscription over a process boundary (a documented stub
//! today; see [`crate::authorizer`]).

use crate::authorizer::TechlinekitAuthorizer;
use crate::error::{Error, Result};
use crate::session::{Arm, Session};
use crate::spawn::{self, FakeObd};
use crate::transport::Target;
use crate::transport::elm327::Elm327Tcp;

/// The default loopback peer: where `fakeobd` and `obd-bridge` both listen.
pub const DEFAULT_TARGET: &str = "127.0.0.1:35000";

/// Parsed invocation options.
// Several independent on/off flags (dry-run, addressing, loopback, authorizer): an options struct,
// not a state machine, so the bool-count lint does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
struct Opts {
    target: String,
    dry_run: bool,
    request_id: u16,
    gmlan: bool,
    allow_non_loopback: bool,
    arm: Arm,
    use_techlinekit: bool,
    command: Vec<String>,
}

/// Run the CLI. Returns `(exit_code, text)`.
///
/// `confirm` is asked before any gated write or actuation; it is handed a one-line description of
/// what is about to be sent and returns whether to proceed.
#[must_use]
pub fn run(args: &[String], confirm: &mut dyn FnMut(&str) -> bool) -> (i32, String) {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(e) => return (2, format!("{e}\n\n{}", usage())),
    };
    if opts.command.first().map(String::as_str) == Some("help") || opts.command.is_empty() {
        return (0, usage());
    }
    // `catalog` is offline: it never opens a link.
    if opts.command[0] == "catalog" {
        return (0, catalog(&opts.command[1..]));
    }
    match dispatch(&opts, confirm) {
        Ok(text) => (0, text),
        Err(e) => (1, e.to_string()),
    }
}

const LINK_COMMANDS: &[&str] = &[
    "scan",
    "did",
    "seed",
    "mode06",
    "session",
    "write",
    "clear",
    "routine",
    "iocontrol",
    "sendkey",
];

fn dispatch(opts: &Opts, confirm: &mut dyn FnMut(&str) -> bool) -> Result<String> {
    let cmd = opts.command[0].as_str();
    // Validate the command before opening a link, so an unknown command never spawns a peer.
    if !LINK_COMMANDS.contains(&cmd) {
        return Err(Error::Refused(format!(
            "unknown command {cmd:?}; try `gmdiag help`"
        )));
    }
    // Keep the simulator alive for the session's lifetime when dry-running.
    let (mut session, _peer) = connect(opts)?;
    session.set_arm(opts.arm);
    // Install the external authorization gate when asked. The default is NoAuthorizer, so
    // actuation stays locked unless the operator opts into the techlinekit broker.
    if opts.use_techlinekit {
        session.set_authorizer(Box::new(TechlinekitAuthorizer::new()));
    }
    let rest = &opts.command[1..];
    match cmd {
        "scan" => scan(&mut session, rest),
        "did" => did(&mut session, rest),
        "seed" => seed(&mut session, rest),
        "mode06" => mode06(&mut session, rest),
        "session" => session_cmd(&mut session, rest),
        "write" => write(&mut session, rest, confirm),
        "clear" => clear(&mut session, rest, confirm),
        "routine" => routine(&mut session, rest, confirm),
        "iocontrol" => iocontrol(&mut session, rest, confirm),
        "sendkey" => sendkey(&mut session, rest, confirm),
        // Unreachable: LINK_COMMANDS gates the set above.
        other => Err(Error::Refused(format!("unhandled command {other:?}"))),
    }
}

/// Build a session: optionally spawn fakeobd, connect the ELM327 transport, set the target.
fn connect(opts: &Opts) -> Result<(Session<Elm327Tcp>, Option<FakeObd>)> {
    let (addr, peer) = if opts.dry_run {
        let addr = spawn::free_loopback_addr()?;
        let peer = FakeObd::spawn(&spawn::program(), &addr, &[])?;
        (peer.addr().to_string(), Some(peer))
    } else {
        (opts.target.clone(), None)
    };
    let transport = if opts.allow_non_loopback {
        Elm327Tcp::connect_any(&addr)?
    } else {
        Elm327Tcp::connect(&addr)?
    };
    let target = if opts.gmlan {
        Target::gmlan(opts.request_id)?
    } else {
        Target::obd(opts.request_id)?
    };
    let session = Session::new(transport, target)?;
    Ok((session, peer))
}

// ----- read commands ----------------------------------------------------------------------

fn scan(session: &mut Session<Elm327Tcp>, rest: &[String]) -> Result<String> {
    let mask = rest.first().map_or(Ok(0xFF), |h| parse_u8(h))?;
    let reports = session.read_dtcs(mask)?;
    if reports.is_empty() {
        return Ok(format!(
            "no DTCs for status mask {mask:02X} on {:03X}",
            session.target().request_id
        ));
    }
    let mut out = format!(
        "{} DTC(s) on {:03X} (mask {mask:02X}):\n",
        reports.len(),
        session.target().request_id
    );
    for r in reports {
        out.push_str("  ");
        out.push_str(&r.summary());
        out.push('\n');
    }
    Ok(out.trim_end().to_string())
}

fn did(session: &mut Session<Elm327Tcp>, rest: &[String]) -> Result<String> {
    let id = rest
        .first()
        .ok_or_else(|| Error::Refused("usage: did <hex-id>".into()))?;
    let did = parse_u16(id)?;
    let (echoed, value) = session.read_did(did)?;
    Ok(format!(
        "DID {echoed:04X} [{}] = {}",
        udskit::did::classify(echoed),
        hex(&value)
    ))
}

fn seed(session: &mut Session<Elm327Tcp>, rest: &[String]) -> Result<String> {
    let level = rest
        .first()
        .ok_or_else(|| Error::Refused("usage: seed <level-hex>".into()))?;
    let level = parse_u8(level)?;
    let seed = session.security_request_seed(level)?;
    Ok(format!(
        "SecurityAccess level {level:02X} seed = {} (no key derived; supply one with `sendkey`)",
        hex(&seed)
    ))
}

fn mode06(session: &mut Session<Elm327Tcp>, rest: &[String]) -> Result<String> {
    let obdmid = rest
        .first()
        .ok_or_else(|| Error::Refused("usage: mode06 <obdmid-hex>".into()))?;
    let obdmid = parse_u8(obdmid)?;
    let (bytes, labels) = session.mode06(obdmid)?;
    let mut out = format!("Mode $06 OBDMID {obdmid:02X} -> {}\n", hex(&bytes));
    if labels.is_empty() {
        out.push_str("  (no mode06kit label for this OBDMID)");
    } else {
        for l in labels {
            out.push_str("  ");
            out.push_str(&l);
            out.push('\n');
        }
    }
    Ok(out.trim_end().to_string())
}

fn session_cmd(session: &mut Session<Elm327Tcp>, rest: &[String]) -> Result<String> {
    let session_type = rest.first().map_or(Ok(0x03), |h| parse_u8(h))?;
    let p = session.enter_session(session_type)?;
    // One keep-alive to confirm the session holds.
    let tp = session.tester_present()?;
    Ok(format!(
        "entered session {session_type:02X} (resp {}); TesterPresent ok (resp {})",
        hex(&p.data),
        hex(&tp.data)
    ))
}

// ----- gated commands ---------------------------------------------------------------------

fn write(
    session: &mut Session<Elm327Tcp>,
    rest: &[String],
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Result<String> {
    let [id, value] = two(rest, "usage: write <did-hex> <value-hex>  (needs --write)")?;
    let did = parse_u16(id)?;
    let value = parse_hex(value)?;
    let line = format!(
        "WRITE DID {did:04X} = {} to {:03X}",
        hex(&value),
        session.target().request_id
    );
    if !confirm(&line) {
        return Err(Error::Refused("write not confirmed".into()));
    }
    let p = session.write_did(did, &value)?;
    Ok(format!("wrote DID {did:04X} (resp {})", hex(&p.data)))
}

fn clear(
    session: &mut Session<Elm327Tcp>,
    rest: &[String],
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Result<String> {
    let group = rest.first().map_or(Ok(0x00FF_FFFF), |h| parse_u24(h))?;
    let line = format!(
        "CLEAR DTC group {group:06X} on {:03X}",
        session.target().request_id
    );
    if !confirm(&line) {
        return Err(Error::Refused("clear not confirmed".into()));
    }
    session.clear_dtcs(group)?;
    Ok(format!("cleared DTC group {group:06X}"))
}

fn routine(
    session: &mut Session<Elm327Tcp>,
    rest: &[String],
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Result<String> {
    let action = rest.first().ok_or_else(|| {
        Error::Refused(
            "usage: routine <start|stop|results> <rid-hex> [data-hex]  (start/stop need --actuate)"
                .into(),
        )
    })?;
    let subfn = match action.as_str() {
        "start" => udskit::routine::START_ROUTINE,
        "stop" => udskit::routine::STOP_ROUTINE,
        "results" => udskit::routine::REQUEST_ROUTINE_RESULTS,
        other => {
            return Err(Error::Refused(format!(
                "routine action {other:?} is not start|stop|results"
            )));
        }
    };
    let rid = parse_u16(
        rest.get(1)
            .ok_or_else(|| Error::Refused("routine needs a routine id".into()))?,
    )?;
    let data = rest.get(2).map_or(Ok(Vec::new()), |h| parse_hex(h))?;
    if subfn != udskit::routine::REQUEST_ROUTINE_RESULTS {
        let line = format!(
            "ROUTINE {action} {rid:04X} data {} on {:03X}",
            hex(&data),
            session.target().request_id
        );
        if !confirm(&line) {
            return Err(Error::Refused("routine not confirmed".into()));
        }
    }
    let p = session.routine(subfn, rid, &data)?;
    Ok(format!(
        "routine {action} {rid:04X} (resp {})",
        hex(&p.data)
    ))
}

fn iocontrol(
    session: &mut Session<Elm327Tcp>,
    rest: &[String],
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Result<String> {
    let id = rest.first().ok_or_else(|| {
        Error::Refused(
            "usage: iocontrol <did-hex> <param-hex> [state-hex]  (needs --actuate)".into(),
        )
    })?;
    let did = parse_u16(id)?;
    let param = parse_u8(
        rest.get(1)
            .ok_or_else(|| Error::Refused("iocontrol needs a control parameter".into()))?,
    )?;
    let state = rest.get(2).map_or(Ok(Vec::new()), |h| parse_hex(h))?;
    let line = format!(
        "IOCONTROL DID {did:04X} param {param:02X} state {} on {:03X}",
        hex(&state),
        session.target().request_id
    );
    if !confirm(&line) {
        return Err(Error::Refused("iocontrol not confirmed".into()));
    }
    let p = session.io_control(did, param, &state)?;
    Ok(format!("iocontrol DID {did:04X} (resp {})", hex(&p.data)))
}

fn sendkey(
    session: &mut Session<Elm327Tcp>,
    rest: &[String],
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Result<String> {
    let [level, key] = two(
        rest,
        "usage: sendkey <level-hex> <key-hex>  (needs --actuate; key is supplied, never derived)",
    )?;
    let level = parse_u8(level)?;
    let key = parse_hex(key)?;
    let line = format!("SendKey level {level:02X} ({} key bytes)", key.len());
    if !confirm(&line) {
        return Err(Error::Refused("sendkey not confirmed".into()));
    }
    let p = session.security_send_key(level, &key)?;
    Ok(format!(
        "sendKey level {level:02X} accepted (resp {})",
        hex(&p.data)
    ))
}

// ----- offline catalog (no link) ----------------------------------------------------------

fn catalog(rest: &[String]) -> String {
    let what = rest.first().map_or("help", String::as_str);
    match what {
        "services" => udskit::services::all_services()
            .iter()
            .map(|s| format!("{:02X} {}", s.sid, s.name))
            .collect::<Vec<_>>()
            .join("\n"),
        "routines" => udskit::gm::routines::catalog()
            .iter()
            .map(|r| format!("{} {} (risk {}) — {}", r.hex(), r.name, r.risk, r.effect))
            .collect::<Vec<_>>()
            .join("\n"),
        "security" => udskit::gm::security::MECHANISMS
            .iter()
            .map(|(k, m)| format!("{k}: {} [{}] — {}", m.name, m.family, m.summary))
            .collect::<Vec<_>>()
            .join("\n\n"),
        "dids" => udskit::gm::dids::read_dids()
            .iter()
            .map(|d| format!("{} [{}]", d.hex(), d.category))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => "catalog <services|routines|security|dids>  — offline reference, no link".into(),
    }
}

// ----- parsing ----------------------------------------------------------------------------

fn parse(args: &[String]) -> Result<Opts> {
    let mut target = DEFAULT_TARGET.to_string();
    let mut dry_run = false;
    let mut request_id: u16 = 0x7E0;
    let mut gmlan = false;
    let mut allow_non_loopback = false;
    let mut write_flag = false;
    let mut actuate_flag = false;
    let mut use_techlinekit = false;
    let mut command = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => {
                let v = it
                    .next()
                    .ok_or_else(|| Error::Refused("--target needs an address".into()))?;
                target.clone_from(v);
            }
            "--request-id" => {
                let v = it
                    .next()
                    .ok_or_else(|| Error::Refused("--request-id needs a hex id".into()))?;
                request_id = parse_u16(v)?;
            }
            "--dry-run" => dry_run = true,
            "--gmlan" => gmlan = true,
            "--obd" => gmlan = false,
            "--allow-non-loopback" => allow_non_loopback = true,
            "--write" => write_flag = true,
            "--actuate" => {
                actuate_flag = true;
                write_flag = true;
            }
            "--techline" => use_techlinekit = true,
            _ => command.push(a.clone()),
        }
    }
    let arm = if actuate_flag {
        Arm::Actuate
    } else if write_flag {
        Arm::Write
    } else {
        Arm::ReadOnly
    };
    Ok(Opts {
        target,
        dry_run,
        request_id,
        gmlan,
        allow_non_loopback,
        arm,
        use_techlinekit,
        command,
    })
}

fn two<'a>(rest: &'a [String], usage: &str) -> Result<[&'a String; 2]> {
    match rest {
        [a, b, ..] => Ok([a, b]),
        _ => Err(Error::Refused(usage.to_string())),
    }
}

fn parse_u8(s: &str) -> Result<u8> {
    u8::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Refused(format!("{s:?} is not a byte hex value")))
}

fn parse_u16(s: &str) -> Result<u16> {
    u16::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Refused(format!("{s:?} is not a 16-bit hex value")))
}

fn parse_u24(s: &str) -> Result<u32> {
    let v = u32::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Refused(format!("{s:?} is not a hex value")))?;
    if v > 0x00FF_FFFF {
        return Err(Error::Refused(format!("{s:?} does not fit in 3 bytes")));
    }
    Ok(v)
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let hex: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    let hex = hex.trim_start_matches("0x");
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Refused(format!("{s:?} is not an even hex string")));
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let h = std::str::from_utf8(&bytes[i..i + 2]).expect("ascii");
        out.push(u8::from_str_radix(h, 16).expect("validated"));
        i += 2;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".into();
    }
    crate::transport::elm327::hex_compact(bytes)
}

/// The usage text.
#[must_use]
pub fn usage() -> String {
    format!(
        "gmdiag — live read/WRITE GM diagnostic driver (Techline/GDS2 side), read-first.\n\
         \n\
         USAGE: gmdiag [options] <command> [args]\n\
         \n\
         Options:\n\
         \u{20}  --target <addr>        TCP peer (default {DEFAULT_TARGET}: fakeobd / obd-bridge)\n\
         \u{20}  --dry-run              spawn fakeobd and talk to it (no hardware)\n\
         \u{20}  --request-id <hex>     physical request arbitration id (default 7E0)\n\
         \u{20}  --gmlan | --obd        response id = request +0x400 (GMLAN) or +0x08 (OBD, default)\n\
         \u{20}  --allow-non-loopback   permit a non-loopback adapter address\n\
         \u{20}  --write                arm coding/clearing (0x2E, 0x14)\n\
         \u{20}  --actuate              arm routines/device-control/sendKey (0x31, 0x2F, 0x27) + write\n\
         \u{20}  --techline             authorize actuation via techlinekit (default: none → locked)\n\
         \n\
         Read commands (no flag):\n\
         \u{20}  scan [mask]            ReadDTCInformation 0x19 02, named via gmdtcdb\n\
         \u{20}  did <hex>              ReadDataByIdentifier 0x22\n\
         \u{20}  seed <level>           SecurityAccess requestSeed (reads the seed; derives NO key)\n\
         \u{20}  mode06 <obdmid>        Mode $06 monitor results, labelled via mode06kit\n\
         \u{20}  session [type]         DiagnosticSessionControl 0x10 + TesterPresent 0x3E\n\
         \u{20}  catalog <what>         offline reference (services|routines|security|dids), no link\n\
         \n\
         Gated commands (need the flag AND a confirmation):\n\
         \u{20}  write <did> <hex>      WriteDataByIdentifier 0x2E            [--write]\n\
         \u{20}  clear [group]          ClearDiagnosticInformation 0x14      [--write]\n\
         \u{20}  routine start|stop|results <rid> [hex]  RoutineControl 0x31 [--actuate + authz for start/stop]\n\
         \u{20}  iocontrol <did> <param> [hex]  InputOutputControl 0x2F      [--actuate + authz]\n\
         \u{20}  sendkey <level> <key>  SecurityAccess sendKey (key supplied) [--actuate + authz]\n\
         \n\
         Actuation (sendkey/routine start-stop/iocontrol) also needs authorization: by default\n\
         none is configured, so it stays locked. gmdiag holds no key material and unlocks nothing\n\
         on its own; `--techline` routes authorization to the techlinekit subscription (stub).\n\
         Owner-authorised vehicles only. Every write is read-first-by-default and confirmed."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_empty_are_code_zero() {
        let mut yes = |_: &str| true;
        assert_eq!(run(&[], &mut yes).0, 0);
        assert_eq!(run(&["help".to_string()], &mut yes).0, 0);
    }

    #[test]
    fn catalog_is_offline_and_lists_services() {
        let mut yes = |_: &str| true;
        let (code, text) = run(&["catalog".to_string(), "services".to_string()], &mut yes);
        assert_eq!(code, 0);
        assert!(text.contains("10"), "{text}");
    }

    #[test]
    fn parse_sets_arm_from_flags() {
        assert_eq!(parse(&["scan".into()]).unwrap().arm, Arm::ReadOnly);
        assert_eq!(
            parse(&["--write".into(), "clear".into()]).unwrap().arm,
            Arm::Write
        );
        assert_eq!(
            parse(&["--actuate".into(), "sendkey".into()]).unwrap().arm,
            Arm::Actuate
        );
    }

    #[test]
    fn parse_sets_the_authorizer_from_the_techline_flag() {
        assert!(!parse(&["scan".into()]).unwrap().use_techlinekit);
        assert!(
            parse(&["--techline".into(), "sendkey".into()])
                .unwrap()
                .use_techlinekit
        );
    }

    #[test]
    fn parse_hex_round_trips() {
        assert_eq!(parse_hex("0x22 00 2F").unwrap(), vec![0x22, 0x00, 0x2F]);
        assert_eq!(parse_hex("").unwrap(), Vec::<u8>::new());
        assert!(parse_hex("0xZZ").is_err());
        assert!(parse_hex("abc").is_err());
    }

    #[test]
    fn unknown_command_is_rejected_without_opening_a_link() {
        let mut yes = |_: &str| true;
        // --dry-run would spawn a peer for a real command; an unknown command is refused first.
        let (code, text) = run(&["wat".to_string(), "--dry-run".to_string()], &mut yes);
        assert_eq!(code, 1);
        assert!(text.contains("unknown command"), "{text}");
    }
}
