//! End-to-end tests of the whole gmdiag stack against a spawned `fakeobd` simulator.
//!
//! fakeobd-first: no hardware. Each test spawns `fakeobd serve` on a free loopback port, connects
//! the real `Elm327Tcp` transport, and drives a [`Session`] exactly as the CLI would. The
//! assertions pin the synthetic Volt-lab profile's documented answers on HPCM2 (`7E0`/`7E8`):
//! a DTC pair, a demo DID, a multi-frame DID, Mode $06, and — the boundary that must hold —
//! SecurityAccess and every write refused.
//!
//! The `fakeobd` binary is found through `GMDIAG_FAKEOBD`, else the sibling build at
//! `../fakeobd/target/{debug,release}/fakeobd`. When neither exists the test prints `SKIP` and
//! returns, so the gate stays green on a checkout without the sibling; CI builds `fakeobd` first.

use std::ffi::OsString;
use std::path::PathBuf;

use gmdiag::Error;
use gmdiag::cli;
use gmdiag::session::{Arm, Session};
use gmdiag::spawn::{self, FakeObd};
use gmdiag::transport::Target;
use gmdiag::transport::elm327::Elm327Tcp;

/// Locate the `fakeobd` binary, or `None` to skip.
fn fakeobd_program() -> Option<OsString> {
    if let Some(p) = std::env::var_os(spawn::PROGRAM_ENV) {
        return Some(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let exe = if cfg!(windows) {
        "fakeobd.exe"
    } else {
        "fakeobd"
    };
    for profile in ["debug", "release"] {
        let cand = manifest
            .join("..")
            .join("fakeobd")
            .join("target")
            .join(profile)
            .join(exe);
        if cand.is_file() {
            return Some(cand.into_os_string());
        }
    }
    None
}

/// Spawn fakeobd on a fresh port and open a session on HPCM2 (7E0 -> 7E8, OBD addressing).
fn session_on_hpcm2(prog: &OsString) -> (FakeObd, Session<Elm327Tcp>) {
    let addr = spawn::free_loopback_addr().expect("free port");
    let peer = FakeObd::spawn(prog, &addr, &[]).expect("fakeobd should start");
    let transport = Elm327Tcp::connect(peer.addr()).expect("connect to fakeobd");
    let session = Session::new(transport, Target::obd(0x7E0).unwrap()).expect("open session");
    (peer, session)
}

#[test]
fn reads_the_whole_stack_against_the_simulator() {
    let Some(prog) = fakeobd_program() else {
        eprintln!("SKIP reads_the_whole_stack_against_the_simulator: fakeobd binary not found");
        return;
    };
    let (_peer, mut s) = session_on_hpcm2(&prog);

    // DiagnosticSessionControl 0x10 + TesterPresent 0x3E keep-alive.
    let entered = s.enter_session(0x01).expect("default session");
    assert_eq!(entered.response_sid, 0x50);
    let tp = s.tester_present().expect("tester present");
    assert_eq!(tp.response_sid, 0x7E);

    // ReadDataByIdentifier 0x22: a single-frame demo DID and a 23-byte multi-frame DID.
    let (did, value) = s.read_did(0x002F).expect("read DID 002F");
    assert_eq!(did, 0x002F);
    assert_eq!(value, vec![0x6C]);
    let (long_did, long) = s.read_did(0x90FB).expect("read multi-frame DID 90FB");
    assert_eq!(long_did, 0x90FB);
    assert_eq!(
        long.len(),
        23,
        "90FB is documented as a 23-byte multi-frame answer"
    );

    // ReadDTCInformation 0x19 02: the two DTCs the profile reports, named via gmdtcdb when known.
    let dtcs = s.read_dtcs(0xFF).expect("read DTCs");
    let codes: Vec<&str> = dtcs.iter().map(|d| d.code.as_str()).collect();
    assert!(codes.contains(&"P0A7E"), "got {codes:?}");
    assert!(codes.contains(&"P0AE3"), "got {codes:?}");

    // Mode $06 OBDMID 0x00: the supported-monitor bitmap, response SID 0x46.
    let (bytes, _labels) = s.mode06(0x00).expect("mode06 bitmap");
    assert_eq!(bytes.first(), Some(&0x46));
}

#[test]
fn security_access_seed_is_refused_and_no_key_is_derived() {
    let Some(prog) = fakeobd_program() else {
        eprintln!("SKIP security_access_seed_is_refused: fakeobd binary not found");
        return;
    };
    let (_peer, mut s) = session_on_hpcm2(&prog);
    // The simulator refuses SecurityAccess under every configuration (NRC 0x33). gmdiag reads the
    // negative response; it never derives a key to get past it.
    match s.security_request_seed(0x01) {
        Err(Error::Negative(msg)) => {
            assert!(msg.contains("0x33") || msg.contains("rejected"), "{msg}");
        }
        other => panic!("expected a negative response, got {other:?}"),
    }
}

#[test]
fn writes_are_gated_locally_then_refused_by_the_simulator() {
    let Some(prog) = fakeobd_program() else {
        eprintln!("SKIP writes_are_gated: fakeobd binary not found");
        return;
    };
    let (_peer, mut s) = session_on_hpcm2(&prog);

    // Read-only by default: a write is refused before any byte reaches the socket.
    match s.write_did(0x002F, &[0x00]) {
        Err(Error::Refused(_)) => {}
        other => panic!("read-only session must refuse a write locally, got {other:?}"),
    }

    // Armed to write: the PDU is sent, and the simulator's policy refuses it with a negative.
    s.set_arm(Arm::Write);
    match s.write_did(0x002F, &[0x00]) {
        // Any non-panic, non-positive outcome proves the armed path actually sends: the sim's
        // policy answers a write with a negative (or an adapter status). A positive would mean the
        // sim accepted a write, which this default profile never does.
        Err(Error::Negative(_) | Error::Adapter(_)) => {}
        other => panic!("armed write should draw a negative/adapter refusal, got {other:?}"),
    }
}

#[test]
fn cli_scan_against_the_simulator_names_dtcs() {
    let Some(prog) = fakeobd_program() else {
        eprintln!("SKIP cli_scan_against_the_simulator: fakeobd binary not found");
        return;
    };
    let addr = spawn::free_loopback_addr().expect("free port");
    let _peer = FakeObd::spawn(&prog, &addr, &[]).expect("fakeobd should start");

    let mut deny = |_: &str| false; // no write is attempted by `scan`, so this is never called
    let args = vec!["scan".to_string(), "--target".to_string(), addr];
    let (code, text) = cli::run(&args, &mut deny);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("P0A7E"), "{text}");
}

#[test]
fn cli_write_declined_at_confirmation_is_not_sent() {
    let Some(prog) = fakeobd_program() else {
        eprintln!("SKIP cli_write_declined: fakeobd binary not found");
        return;
    };
    let addr = spawn::free_loopback_addr().expect("free port");
    let _peer = FakeObd::spawn(&prog, &addr, &[]).expect("fakeobd should start");

    // --write arms the session, but the confirmation callback says no: the write must abort
    // before any byte is sent, with a "not confirmed" refusal.
    let mut deny = |_: &str| false;
    let args = vec![
        "--write".to_string(),
        "--target".to_string(),
        addr,
        "write".to_string(),
        "002F".to_string(),
        "00".to_string(),
    ];
    let (code, text) = cli::run(&args, &mut deny);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("not confirmed"), "{text}");
}

#[test]
fn cli_dry_run_spawns_fakeobd_when_the_binary_is_on_path_or_env() {
    // The --dry-run path resolves the binary through GMDIAG_FAKEOBD / PATH (not the sibling-build
    // fallback above), so it runs only when CI or the operator has set that up.
    if std::env::var_os(spawn::PROGRAM_ENV).is_none() {
        eprintln!("SKIP cli_dry_run: set GMDIAG_FAKEOBD to exercise --dry-run");
        return;
    }
    let mut deny = |_: &str| false;
    let args = vec!["scan".to_string(), "--dry-run".to_string()];
    let (code, text) = cli::run(&args, &mut deny);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("P0A7E"), "{text}");
}
