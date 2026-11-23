//! `vcx-reset`: reset the VCX-NANO dongle (the `VCX_DEV_Reset` command, header
//! `0x8D`, empty payload). The dongle reboots, which clears its session state —
//! including the firmware unlock, which otherwise persists until the device is
//! power-cycled. After a reset the next read re-runs the unlock automatically.
//!
//! The device may reset without sending a reply, so a read timeout here is reported,
//! not treated as a failure. This touches no vehicle and sends no diagnostic frame.

/// Parse `--port <N>` or a bare `COM4`/`4`; default COM4.
fn parse_port(args: &[String]) -> u32 {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let value = if arg == "--port" {
            it.next().map(String::as_str)
        } else {
            Some(arg.as_str())
        };
        if let Some(value) = value {
            let digits = value.trim_start_matches(['C', 'O', 'M', 'c', 'o', 'm']);
            if let Ok(port) = digits.parse::<u32>() {
                return port;
            }
        }
    }
    4
}

/// Run `vcx-reset`. Returns `(exit_code, text)`, like [`crate::cli::run`].
#[cfg(windows)]
#[must_use]
pub fn run(args: &[String]) -> (i32, String) {
    use std::fmt::Write as _;
    use std::time::Duration;

    let port = parse_port(args);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "gmdiag vcx-reset — reset the VCX-NANO (VCX_DEV_Reset, header 0x8D)\n  port COM{port}"
    );

    let serial = match vcxtoolkit::open_usb(port, 0) {
        Ok(serial) => serial,
        Err(error) => {
            let _ = writeln!(out, "  !! could not open the dongle: {error}");
            return (1, out);
        }
    };
    // Settle after open, then drain boot bytes, as the other device commands do.
    std::thread::sleep(Duration::from_millis(400));
    let mut scratch = [0_u8; 256];
    for _ in 0..64 {
        match serial.read(&mut scratch) {
            Ok(n) if n > 0 => {}
            _ => break,
        }
    }
    match vcxtoolkit::exchange(
        &serial,
        vcxtoolkit::Command::Reset.header(0),
        &vcxtoolkit::reset_payload(),
        Duration::from_secs(2),
    ) {
        Ok(frame) => {
            let _ = writeln!(
                out,
                "  reset acknowledged: header {:02X?} payload {:02X?}",
                frame.header, frame.payload
            );
            (0, out)
        }
        Err(error) => {
            // The dongle commonly resets without replying; report, do not fail hard.
            let _ = writeln!(
                out,
                "  reset sent; no reply before timeout ({error}). The dongle typically reboots \
                 without answering — unplug/replug or re-run a read, which re-unlocks."
            );
            (0, out)
        }
    }
}

/// Non-Windows stub: the reset opens a COM port.
#[cfg(not(windows))]
#[must_use]
pub fn run(_args: &[String]) -> (i32, String) {
    (
        1,
        "vcx-reset runs on Windows only (it opens a COM port)\n".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::parse_port;

    #[test]
    fn port_parses_flag_bare_and_com_forms_with_default_4() {
        assert_eq!(parse_port(&["--port".into(), "3".into()]), 3);
        assert_eq!(parse_port(&["COM7".into()]), 7);
        assert_eq!(parse_port(&[]), 4);
    }
}
