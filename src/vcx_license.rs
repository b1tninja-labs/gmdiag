//! `vcx-license`: read and print the on-device VCX licence natively.
//!
//! This is the device **hello** our native stack already performs before a channel
//! bring-up, exposed as a standalone read: `GetInfo` + the `80 00 A0` licence
//! challenge (Diffie-Hellman, generator 5) + `GetLicense`, XXTEA-decoded by
//! [`vcxtoolkit::read_license`]. It opens the COM port, waits for the dongle to
//! settle, drains boot bytes, runs the challenge, and prints the licence. It sends
//! no diagnostic frame and touches no vehicle — purely a device identity read.

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

/// Run `vcx-license`. Returns `(exit_code, text)`, like [`crate::cli::run`].
#[cfg(windows)]
#[must_use]
pub fn run(args: &[String]) -> (i32, String) {
    use std::fmt::Write as _;
    use std::time::Duration;

    let port = parse_port(args);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "gmdiag vcx-license — on-device licence read (hello: GetInfo + 80 00 A0 challenge, \
         READ-ONLY)\n  port COM{port}"
    );

    let serial = match vcxtoolkit::open_usb(port, 0) {
        Ok(serial) => serial,
        Err(error) => {
            let _ = writeln!(out, "  !! could not open the dongle: {error}");
            return (1, out);
        }
    };
    // Settle after open, then drain boot bytes (same as the bring-up hello).
    std::thread::sleep(Duration::from_millis(400));
    let mut scratch = [0_u8; 256];
    for _ in 0..64 {
        match serial.read(&mut scratch) {
            Ok(n) if n > 0 => {}
            _ => break,
        }
    }
    match vcxtoolkit::read_license(&serial, Duration::from_secs(3)) {
        Ok(info) => {
            let _ = writeln!(out, "  serial         : {:02X?}", info.serial);
            let _ = writeln!(out, "  issued         : {}", info.issued);
            let _ = writeln!(out, "  updated        : {}", info.updated);
            let _ = writeln!(out, "  period_seconds : {}", info.period_seconds);
            for product in &info.products {
                let _ = writeln!(
                    out,
                    "  product        : {} ({})",
                    product.name, product.date
                );
            }
            (0, out)
        }
        Err(error) => {
            let _ = writeln!(out, "  licence read failed: {error}");
            (1, out)
        }
    }
}

/// Non-Windows stub: the licence read opens a COM port.
#[cfg(not(windows))]
#[must_use]
pub fn run(_args: &[String]) -> (i32, String) {
    (
        1,
        "vcx-license runs on Windows only (it opens a COM port)\n".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::parse_port;

    #[test]
    fn port_parses_flag_bare_and_com_forms_with_default_4() {
        assert_eq!(parse_port(&["--port".into(), "3".into()]), 3);
        assert_eq!(parse_port(&["COM7".into()]), 7);
        assert_eq!(parse_port(&["5".into()]), 5);
        assert_eq!(parse_port(&[]), 4);
    }
}
