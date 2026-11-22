//! The **real** hardware [`ByteSource`] for the VCX adapter.
//!
//! [`crate::vcx`] ships only an in-process [`FakeByteSource`](crate::vcx::FakeByteSource):
//! its byte seam was injected precisely so the concrete hardware implementation
//! could live apart from the offline assembly logic. This module is that
//! implementation. It satisfies the injected seam by driving vcxtoolkit's
//! recovered channel-open plus `VCX_PRO_Send`/`VCX_PRO_Recv` exchange
//! ([`vcxtoolkit::Channel`]) over a real USB serial `vcxtoolkit::Port`, so the
//! same [`VcxTransport`](crate::vcx::VcxTransport) that a test drives over canned
//! frames runs against a VCX-NANO dongle.
//!
//! # The port is the doctor's, never hardcoded
//!
//! The COM port is chosen by the detection layer — `voltkit`'s wizard surfaces the
//! VCX-NANO as a detected COM number, and `vcxtoolkit`'s `doctor` identifies on any
//! port. So `VcxByteSource::open` takes the port number as a parameter and opens
//! it with `vcxtoolkit::open_usb`; it assumes no fixed COM. [`DEFAULT_DOCTOR_PORT`]
//! exists only as the doctor's default convenience and stays overridable.
//!
//! # The logic is generic over the serial seam; only opening the port is hardware
//!
//! [`VcxByteSource`] is generic over [`vcxtoolkit::SerialPort`]. The construct →
//! exchange → return-payload logic is therefore exercised in tests by an in-process
//! fake serial, exactly as `vcxtoolkit`'s own `device` tests drive the channel over
//! canned bytes. The only hardware-specific part — opening the real
//! `Port` — is isolated in the Windows-only `VcxByteSource::open`
//! constructor, so the seam logic is tested without hardware.
//!
//! # The live vehicle read stays gated and ignored
//!
//! Constructing a [`VcxByteSource`] opens the serial port but sends nothing: the
//! ISO 15765 channel is opened and the request transmitted only when
//! [`ByteSource::exchange`] runs. The live vehicle
//! read stays held behind `vcxtoolkit`'s own gate
//! ([`vcxtoolkit::collect::vehicle_read_gate`],
//! [`READ_LAYOUT_RECOVERED`](vcxtoolkit::collect::READ_LAYOUT_RECOVERED) is `false`),
//! because the vehicle-facing request content is unrecovered. Nothing here flips that
//! gate, and no CLI path reaches this byte seam. The one real-hardware entry point is
//! an `#[ignore]`d, owner-gated test that opens the dongle and asserts the gate stays
//! closed; it performs no vehicle read.

use std::time::Duration;

use vcxtoolkit::collect::ISO15765_PROTOCOL;
use vcxtoolkit::{Channel, SerialPort};

use crate::error::{Error, Result};
use crate::vcx::ByteSource;

/// The exchange timeout the real path paces each channel step with.
///
/// `vcxtoolkit`'s own hardware round-trips use a two-second deadline (the dongle
/// answers `GetInfo` and a channel open well within it); the identity read reuses
/// that budget. Overridable through `VcxByteSource::open_with_params`.
pub const DEFAULT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// The default pass-through channel byte (`VCX_PRO_Open`/`VCX_PRO_Send` header byte
/// 3). This is the caller's channel, not a value recovered from the VXDIAG binaries
/// (`vcxtoolkit::pro_send_header` documents bytes 1 and 3 as the caller's arguments),
/// so it defaults to `0` and is overridable through `VcxByteSource::open_with_params`.
pub const DEFAULT_CHANNEL: u8 = 0;

/// The default caller byte (`VCX_PRO_Send` header byte 1). Like [`DEFAULT_CHANNEL`]
/// this is caller-supplied, not recovered, so it defaults to `0` and is overridable.
pub const DEFAULT_CALLER: u8 = 0;

/// The COM port the doctor defaults to when detection has not named one.
///
/// This is only the convenience default (the VCX-NANO commonly enumerates on COM4,
/// which is also `vcxtoolkit`'s ignored-test port); the detection layer supplies the
/// real number, and every constructor takes the port as a parameter. Nothing in this
/// crate opens this port on its own.
pub const DEFAULT_DOCTOR_PORT: u32 = 4;

/// The HS-GMLAN / diagnostic CAN baud the channel is configured for: the J2534
/// `PassThruConnect` baud the recovered connect passes in its one `SetComParam`
/// record (`VCX_PRO_SetComParam`, key `3`). GM diagnostic CAN is 500 kbit/s.
pub const DEFAULT_CAN_BAUD: u32 = 500_000;

/// A [`ByteSource`] that drives `vcxtoolkit`'s channel-open plus Send/Recv exchange
/// over a [`SerialPort`].
///
/// It is generic over the serial seam so an in-process fake drives the whole
/// construct → exchange → return-payload path in tests, while the real path opens a
/// USB `Port`. Each [`exchange`](ByteSource::exchange) opens the
/// ISO 15765 channel and writes the caller's already-framed `VCX_PRO_Send` request
/// (the output of [`vcxtoolkit::collect::frame_identity_request`], which the
/// [`VcxTransport`](crate::vcx::VcxTransport) produced), then returns the reply
/// frame's payload — the recovered `VCX_PRO_Recv` envelope that
/// [`vcxtoolkit::collect::reply_application_bytes`] consumes. It synthesizes no
/// request content of its own.
#[derive(Debug)]
pub struct VcxByteSource<S: SerialPort> {
    port: S,
    channel: Channel,
    timeout: Duration,
    /// The request/response arbitration ids the ISO 15765 flow-control filter is
    /// built from (`AddFilter`: mask `FF..`, pattern = response id, flow = request
    /// id). `0`/`0` adds no filter — the bare open+send path the offline tests drive.
    req_id: u16,
    resp_id: u16,
    /// Whether the ISO 15765 channel has already been brought up on this port
    /// (open → SetComParam → AddFilter → Start). The bring-up runs once; every
    /// later exchange reuses the open channel and only does Send + the pushed read.
    connected: bool,
}

impl<S: SerialPort> VcxByteSource<S> {
    /// Build a byte seam over an already-open serial `port`.
    ///
    /// This is the seam-generic constructor the fake serial uses in tests and the
    /// Windows-only `VcxByteSource::open` builds on. It opens no channel and sends
    /// nothing; it only validates that the ISO 15765 open dword resolves.
    ///
    /// `channel` and `caller` are the caller-supplied VCX framing bytes
    /// ([`DEFAULT_CHANNEL`], [`DEFAULT_CALLER`]); `timeout` paces each channel step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the ISO 15765 protocol has no `VCX_PRO_Open`
    /// dword (a regression in `vcxtoolkit::open_code`).
    pub fn with_port(port: S, channel: u8, caller: u8, timeout: Duration) -> Result<Self> {
        let channel = Channel::new(ISO15765_PROTOCOL, channel, caller)?;
        Ok(Self {
            port,
            channel,
            timeout,
            req_id: 0,
            resp_id: 0,
            connected: false,
        })
    }

    /// Set the request/response CAN ids the ISO 15765 flow-control filter is built
    /// from, so the dongle forwards the request and delivers the ECU's pushed reply.
    ///
    /// Without a filter the dongle accepts the Send but returns only its 1-byte
    /// status ack (`0x9B`) and never forwards to the bus. With `7E0`/`7E8` set, the
    /// connect installs the flow-control filter before `Start`.
    #[must_use]
    pub fn with_can_ids(mut self, req_id: u16, resp_id: u16) -> Self {
        self.req_id = req_id;
        self.resp_id = resp_id;
        self
    }

    /// The channel this seam opens for each exchange.
    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Borrow the underlying serial port (to inspect a fake in tests).
    #[must_use]
    pub fn port(&self) -> &S {
        &self.port
    }
}

#[cfg(windows)]
impl VcxByteSource<vcxtoolkit::Port> {
    /// Open the VCX-NANO on the detection-selected `port` with the documented
    /// defaults ([`DEFAULT_CHANNEL`], [`DEFAULT_CALLER`], [`DEFAULT_EXCHANGE_TIMEOUT`]).
    ///
    /// `port` is the COM number the doctor/detection layer chose; this opens it with
    /// [`vcxtoolkit::open_usb`] at the USB profile baud. It assumes no fixed COM — see
    /// [`DEFAULT_DOCTOR_PORT`] for the convenience default the detection layer may pass.
    /// Opening the port sends nothing to a vehicle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the port cannot be opened, or [`Error::Protocol`]
    /// from [`VcxByteSource::with_port`].
    pub fn open(port: u32) -> Result<Self> {
        Self::open_with_params(
            port,
            DEFAULT_CHANNEL,
            DEFAULT_CALLER,
            DEFAULT_EXCHANGE_TIMEOUT,
        )
    }

    /// Open the VCX-NANO on `port`, overriding the framing bytes and the timeout.
    ///
    /// `port` is the detection-selected COM number (never hardcoded here). `baud` is
    /// the profile baud passed straight to [`vcxtoolkit::open_usb`]; `0` selects the
    /// USB default ([`vcxtoolkit::USB_BAUD`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the port cannot be opened, or [`Error::Protocol`]
    /// from [`VcxByteSource::with_port`].
    pub fn open_with_params(port: u32, channel: u8, caller: u8, timeout: Duration) -> Result<Self> {
        let serial = vcxtoolkit::open_usb(port, 0)
            .map_err(|error| Error::Io(std::io::Error::other(error.to_string())))?;
        Self::with_port(serial, channel, caller, timeout)
    }
}

/// Map a `forward` builder refusal (a payload that could not be built) into the
/// crate error. These are construction errors, not link failures, so they are a
/// [`Error::Protocol`].
fn forward_err(error: vcxtoolkit::ForwardError) -> Error {
    Error::Protocol(format!("vcx connect: {error}"))
}

/// Write one VCX command (`label` names it for diagnostics), then read the dongle's
/// reply frame and return its payload.
///
/// Unlike a plain `exchange_with`, a timeout here reports **which** command had no
/// reply and dumps the raw bytes the dongle sent (if any), so an on-car bring-up
/// failure pins the exact step instead of a bare "no complete frame".
fn write_frame<S: SerialPort>(port: &S, label: &str, header: [u8; 4], payload: &[u8]) -> Result<()>
where
    S::Error: std::fmt::Display,
{
    let frame = vcxtoolkit::pack(header, payload)
        .map_err(|error| Error::Protocol(format!("{label}: pack: {error}")))?;
    let mut written = 0;
    while written < frame.len() {
        match port.write(&frame[written..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "{label}: write stalled at {written}/{}",
                    frame.len()
                ))));
            }
            Ok(n) => written += n,
            Err(error) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "{label}: write: {error}"
                ))));
            }
        }
    }
    Ok(())
}

/// Write one VCX command (`label` names it for diagnostics), then read the dongle's
/// reply frame and return it (header + payload).
///
/// A timeout reports **which** command had no reply and dumps the raw bytes the
/// dongle sent, so an on-car bring-up failure pins the exact step.
fn command_step<S: SerialPort>(
    port: &S,
    label: &str,
    header: [u8; 4],
    payload: &[u8],
    timeout: Duration,
) -> Result<vcxtoolkit::Frame>
where
    S::Error: std::fmt::Display,
{
    write_frame(port, label, header, payload)?;
    let deadline = std::time::Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        match port.read(&mut chunk) {
            Ok(0) => {}
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(frame) = first_complete_frame(&buf) {
                    return Ok(frame);
                }
            }
            Err(error) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "{label}: read: {error}"
                ))));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::Protocol(format!(
                "{label}: no reply frame in {} ms (raw bytes from dongle: {buf:02X?})",
                timeout.as_millis(),
            )));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// One diagnostic line summarising a reply frame: its command byte and payload.
fn frame_line(label: &str, frame: &vcxtoolkit::Frame) -> String {
    format!(
        "  {label}: reply cmd {:#04X}, payload {:02X?}\n",
        frame.header[2], frame.payload
    )
}

/// Prepend the bring-up `trace` to an error while keeping its kind (a link failure
/// stays [`Error::Io`]; a protocol refusal stays [`Error::Protocol`]).
fn prepend_trace(trace: &str, error: Error) -> Error {
    match error {
        Error::Io(inner) => Error::Io(std::io::Error::other(format!("{trace}  {inner}"))),
        Error::Protocol(message) => Error::Protocol(format!("{trace}  {message}")),
        other => other,
    }
}

/// Bring the ISO 15765 channel up on the dongle: the recovered `PassThruConnect`
/// sequence `VCX_PRO_Open` → `SetComParam(baud)` → `AddFilter(flow control)` →
/// `ProStart`. Runs once per [`VcxByteSource`]; later exchanges reuse the channel.
///
/// Without this a `VCX_PRO_Send` gets only the dongle's 1-byte status ack (`0x9B`)
/// because the channel is never configured or forwarded. The flow-control filter
/// (mask `FF..`, pattern = the response id, flow = the request id) is what makes the
/// dongle forward the request and push the ECU reply back.
fn bring_up_channel<S: SerialPort>(
    port: &S,
    channel: Channel,
    req_id: u16,
    resp_id: u16,
    timeout: Duration,
    trace: &mut String,
) -> Result<()>
where
    S::Error: std::fmt::Display,
{
    use vcxtoolkit::{
        Command, FilterCopy, add_filter, baud_record, set_com_param, start_filter, start_payload,
    };
    let ch = channel.channel;

    // 1. Open the ISO 15765 data channel (the reply must echo VCX_PRO_Open). A
    //    failure here is labelled so the step is unambiguous on hardware.
    let open = channel.open(port, timeout).map_err(|error| match &error {
        // A link timeout/port failure stays Io; a wrong echo or refusal is Protocol.
        vcxtoolkit::DeviceError::Open(_) | vcxtoolkit::DeviceError::Send(_) => Error::Io(
            std::io::Error::other(format!("bring-up VCX_PRO_Open (0x40): {error}")),
        ),
        _ => Error::Protocol(format!("bring-up VCX_PRO_Open (0x40): {error}")),
    })?;
    trace.push_str(&frame_line("open (0x40)", &open));

    // 2. SetComParam: the CAN baud, the recovered PassThruConnect SetComParam record.
    let com = set_com_param(&[baud_record(DEFAULT_CAN_BAUD)]).map_err(forward_err)?;
    let reply = command_step(
        port,
        "bring-up SetComParam (0x45)",
        Command::ProSetComParam.header(ch),
        &com,
        timeout,
    )?;
    trace.push_str(&frame_line("SetComParam (0x45)", &reply));

    // 3. AddFilter: the ISO 15765 flow-control filter. Skipped when no ids are set
    //    (the bare open+send path the offline tests drive).
    if resp_id != 0 {
        let pattern = u32::from(resp_id).to_be_bytes();
        let mask = [0xFF_u8; 4];
        let flow = u32::from(req_id).to_be_bytes();
        let filter = start_filter(&FilterCopy {
            slot: 0,
            kind: 3,
            pattern: &pattern,
            mask: &mask,
            flow: &flow,
            extend_first: false,
        })
        .map_err(forward_err)?;
        let payload = add_filter(&[filter]).map_err(forward_err)?;
        let reply = command_step(
            port,
            "bring-up AddFilter (0x48)",
            Command::ProAddFilter.header(ch),
            &payload,
            timeout,
        )?;
        trace.push_str(&frame_line("AddFilter (0x48)", &reply));
    }

    // 4. Start the channel.
    let reply = command_step(
        port,
        "bring-up ProStart (0x42)",
        Command::ProStart.header(ch),
        &start_payload(),
        timeout,
    )?;
    trace.push_str(&frame_line("ProStart (0x42)", &reply));
    Ok(())
}

/// The first complete `0xBB`…`0xBB` frame in `buf`, if one is buffered.
///
/// Mirrors `vcxtoolkit`'s own frame scan: the first `0xBB` opens, and the first
/// later `0xBB` that makes [`vcxtoolkit::unpack`] accept the slice closes it.
fn first_complete_frame(buf: &[u8]) -> Option<vcxtoolkit::Frame> {
    let open = buf.iter().position(|&b| b == 0xBB)?;
    for (close, _) in buf
        .iter()
        .enumerate()
        .skip(open + 1)
        .filter(|&(_, &b)| b == 0xBB)
    {
        if let Ok(frame) = vcxtoolkit::unpack(&buf[open..=close]) {
            return Some(frame);
        }
    }
    None
}

/// The smallest `VCX_PRO_Recv` envelope that can carry an application reply: the
/// 4-byte flags dword plus the 2-byte length. A shorter frame payload (e.g. the
/// 1-byte `0x9B` status ack) is not an ECU reply and is logged, not returned.
const MIN_RECV_ENVELOPE: usize = 6;

/// Every complete `0xBB`…`0xBB` frame in `buf`, in order.
fn all_frames(buf: &[u8]) -> Vec<vcxtoolkit::Frame> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] != 0xBB {
            i += 1;
            continue;
        }
        let mut advanced = false;
        for close in (i + 1)..buf.len() {
            if buf[close] == 0xBB {
                if let Ok(frame) = vcxtoolkit::unpack(&buf[i..=close]) {
                    out.push(frame);
                    i = close + 1;
                    advanced = true;
                    break;
                }
            }
        }
        if !advanced {
            i += 1;
        }
    }
    out
}

/// Read what the dongle returns after a `VCX_PRO_Send`, returning the first
/// envelope-shaped reply frame's payload.
///
/// After `ProStart` the Send is not answered by a synchronous reply frame; the ECU
/// reply arrives as its own pushed `0xBB` frame (and the dongle may also emit a short
/// status frame). This returns the first frame whose payload is at least a
/// `VCX_PRO_Recv` envelope ([`MIN_RECV_ENVELOPE`]). If none arrives within `timeout`,
/// the error carries the full bring-up trace, every frame seen, and the raw bytes, so
/// an on-car run that does not match this model is fully diagnosable.
fn read_reply_after_send<S: SerialPort>(
    port: &S,
    timeout: Duration,
    trace: &mut String,
) -> Result<Vec<u8>>
where
    S::Error: std::fmt::Display,
{
    let deadline = std::time::Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        match port.read(&mut chunk) {
            Ok(0) => {}
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(error) => return Err(Error::Io(std::io::Error::other(error.to_string()))),
        }
        if let Some(frame) = all_frames(&buf)
            .into_iter()
            .find(|frame| frame.payload.len() >= MIN_RECV_ENVELOPE)
        {
            return Ok(frame.payload);
        }
        if std::time::Instant::now() >= deadline {
            for frame in &all_frames(&buf) {
                trace.push_str(&frame_line("after Send", frame));
            }
            return Err(Error::Protocol(format!(
                "{trace}  VCX_PRO_Send: no ECU reply frame (>= {MIN_RECV_ENVELOPE} payload bytes) \
                 within {} ms; raw bytes from dongle: {buf:02X?}",
                timeout.as_millis(),
            )));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

impl<S: SerialPort> ByteSource for VcxByteSource<S>
where
    S::Error: std::fmt::Display,
{
    fn exchange(&mut self, framed_request: &[u8]) -> Result<Vec<u8>> {
        let mut trace = String::from("\n  channel bring-up / reply trace:\n");
        // Bring the ISO 15765 channel up once; every later exchange reuses it.
        if !self.connected {
            if let Err(error) = bring_up_channel(
                &self.port,
                self.channel,
                self.req_id,
                self.resp_id,
                self.timeout,
                &mut trace,
            ) {
                return Err(prepend_trace(&trace, error));
            }
            self.connected = true;
        }

        // Write the caller's already-framed VCX_PRO_Send. After ProStart the Send is
        // not answered synchronously; the ECU reply is pushed as its own frame.
        write_frame(
            &self.port,
            "VCX_PRO_Send",
            vcxtoolkit::pro_send_header(self.channel.caller, self.channel.channel),
            framed_request,
        )?;

        // Read the pushed reply; its payload is the VCX_PRO_Recv envelope.
        read_reply_after_send(&self.port, self.timeout, &mut trace)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use vcxtoolkit::collect::{IDENTITY_POSITIVE_SID, reply_application_bytes};
    use vcxtoolkit::{SerialPort, pack, pro_send_header};

    use super::{DEFAULT_CALLER, DEFAULT_CHANNEL, VcxByteSource};
    use crate::vcx::{ByteSource, VcxTransport, build_identity_request, read_identity};
    use vcxtoolkit::modread::IdentifierRead;

    // The recovered VCX_PRO_Open command byte the open reply echoes in header byte 2.
    const PRO_OPEN_ECHO: u8 = 0x40;

    // An in-process serial port: writes are recorded; each read delivers the next
    // queued chunk (bounded by the caller's buffer), and an empty queue reads zero.
    // This stands in for vcxtoolkit's own cfg(test) FakeSerial, which is not public.
    struct FakeSerial {
        writes: RefCell<Vec<Vec<u8>>>,
        reads: RefCell<VecDeque<Vec<u8>>>,
    }

    impl FakeSerial {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                reads: RefCell::new(chunks.into_iter().collect()),
            }
        }
    }

    #[derive(Debug)]
    struct FakeError;

    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fake serial failure")
        }
    }

    impl SerialPort for FakeSerial {
        type Error = FakeError;

        fn write(&self, buf: &[u8]) -> Result<usize, FakeError> {
            self.writes.borrow_mut().push(buf.to_vec());
            Ok(buf.len())
        }

        fn read(&self, buf: &mut [u8]) -> Result<usize, FakeError> {
            let mut reads = self.reads.borrow_mut();
            match reads.front_mut() {
                None => Ok(0),
                Some(chunk) => {
                    let n = buf.len().min(chunk.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    if n == chunk.len() {
                        reads.pop_front();
                    } else {
                        chunk.drain(..n);
                    }
                    Ok(n)
                }
            }
        }
    }

    // A valid open reply: a frame echoing VCX_PRO_Open (0x40) in header byte 2.
    fn open_ack() -> Vec<u8> {
        pack([0x80, 0x00, PRO_OPEN_ECHO, DEFAULT_CHANNEL], &[]).unwrap()
    }

    // A send reply frame whose payload is the recovered VCX_PRO_Recv envelope:
    // flags u32 LE, len u16 LE, then the application bytes.
    fn recv_envelope(app: &[u8]) -> Vec<u8> {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&0_u32.to_le_bytes());
        pdu.extend_from_slice(&u16::try_from(app.len()).unwrap().to_le_bytes());
        pdu.extend_from_slice(app);
        pdu
    }

    // The dongle's ack for a config command (SetComParam/Start): a frame echoing the
    // command byte, empty payload. send_command only reads it; the content is ignored.
    fn cmd_ack(cmd: u8) -> Vec<u8> {
        pack([0x80, 0x00, cmd, DEFAULT_CHANNEL], &[]).unwrap()
    }

    // The ECU reply frame the dongle pushes after the Send. Its payload is the
    // recovered VCX_PRO_Recv envelope (>= 6 bytes) the adapter unwraps.
    fn pushed(app: &[u8]) -> Vec<u8> {
        pack([0x80, 0x00, 0x00, DEFAULT_CHANNEL], &recv_envelope(app)).unwrap()
    }

    // Every frame one full exchange consumes with no filter (req/resp ids 0): the
    // open, SetComParam and Start acks, then the pushed ECU reply (the Send is
    // write-only — no synchronous ack is read).
    const PRO_SETCOMPARAM: u8 = 0x45;
    const PRO_START: u8 = 0x42;
    fn connected_reads(app: &[u8]) -> Vec<Vec<u8>> {
        vec![
            open_ack(),
            cmd_ack(PRO_SETCOMPARAM),
            cmd_ack(PRO_START),
            pushed(app),
        ]
    }

    fn source(chunks: Vec<Vec<u8>>) -> VcxByteSource<FakeSerial> {
        VcxByteSource::with_port(
            FakeSerial::new(chunks),
            DEFAULT_CHANNEL,
            DEFAULT_CALLER,
            Duration::from_secs(1),
        )
        .unwrap()
    }

    #[test]
    fn exchange_opens_the_channel_and_returns_the_recv_envelope() {
        // The seam drives open → send and hands back the reply frame's payload: the
        // recovered Recv envelope the gmdiag adapter unwraps. The request it is given
        // is already framed (flags BE + len BE + `1A C1`), as the adapter supplies it.
        let app = [IDENTITY_POSITIVE_SID, 0xC1, 0x31, 0x32];
        let mut seam = source(connected_reads(&app));
        let framed_request = vec![0, 0, 0, 0, 0, 2, 0x1A, 0xC1];

        let payload = seam.exchange(&framed_request).unwrap();

        // The returned payload is the pushed ECU frame's envelope, exactly what
        // reply_application_bytes consumes.
        assert_eq!(payload, recv_envelope(&app));
        assert_eq!(reply_application_bytes(&payload).unwrap(), &app);

        // Four frames went out: the channel bring-up (open, SetComParam, Start), then
        // the caller's framed request wrapped in the VCX_PRO_Send header. No request
        // content was synthesized.
        let writes = seam.port().writes.borrow();
        assert_eq!(writes.len(), 4);
        assert_eq!(
            writes[3],
            pack(
                pro_send_header(DEFAULT_CALLER, DEFAULT_CHANNEL),
                &framed_request
            )
            .unwrap(),
        );
    }

    #[test]
    fn the_real_seam_drives_the_offline_adapter_end_to_end() {
        // Dropping the real byte source into the adapter's VcxTransport proves it
        // satisfies the injected ByteSource seam: udskit builds `1A C1`, the transport
        // frames it, this seam drives the fake dongle, and udskit parses the reply.
        let app = [IDENTITY_POSITIVE_SID, 0xC1, 0x2A];
        let seam = source(connected_reads(&app));
        let mut transport = VcxTransport::new(seam);

        let read = read_identity(&mut transport, 0xC1).unwrap();
        assert_eq!(read, IdentifierRead::lid(0xC1, vec![0x2A]));

        // The bytes that reached the seam are the udskit-built, vcx-framed request.
        let seam = transport.into_source();
        let writes = seam.port().writes.borrow();
        assert_eq!(writes.len(), 4);
        let expected_request = vcxtoolkit::collect::frame_identity_request_with_flags(
            vcxtoolkit::collect::ISO15765_FRAME_PAD,
            &build_identity_request(0xC1),
        )
        .unwrap();
        assert_eq!(
            writes[3],
            pack(
                pro_send_header(DEFAULT_CALLER, DEFAULT_CHANNEL),
                &expected_request
            )
            .unwrap(),
        );
    }

    #[test]
    fn a_negative_reply_round_trips_to_a_negative_error() {
        // A negative $1A is not a device error: it rides the recovered envelope and
        // surfaces only when the adapter parses the application PDU.
        let app = [0x7F, 0x1A, 0x31]; // requestOutOfRange
        let seam = source(connected_reads(&app));
        let mut transport = VcxTransport::new(seam);
        let error = read_identity(&mut transport, 0xC1).unwrap_err();
        assert!(matches!(error, crate::Error::Negative(_)), "{error:?}");
        assert!(error.to_string().contains("requestOutOfRange"), "{error}");
    }

    #[test]
    fn a_wrong_open_echo_is_a_protocol_error() {
        // The open reply echoes GetInfo (0x8C), not VCX_PRO_Open: the device answered
        // wrongly, so the seam refuses before any request goes out.
        let mut seam = source(vec![
            pack([0x80, 0x00, 0x8C, DEFAULT_CHANNEL], &[]).unwrap(),
        ]);
        let error = seam.exchange(&[0, 0, 0, 0, 0, 2, 0x1A, 0xC1]).unwrap_err();
        assert!(matches!(error, crate::Error::Protocol(_)), "{error:?}");
        assert!(error.to_string().contains("VCX_PRO_Open"), "{error}");
        // Only the open was written; no config or request frame followed the refusal.
        assert_eq!(seam.port().writes.borrow().len(), 1);
    }

    #[test]
    fn a_closed_port_is_an_io_error() {
        // The queue is empty, so the first read yields nothing and the short deadline
        // lapses: a link failure, reported as Io, not Protocol.
        let mut seam = VcxByteSource::with_port(
            FakeSerial::new(Vec::new()),
            DEFAULT_CHANNEL,
            DEFAULT_CALLER,
            Duration::from_millis(20),
        )
        .unwrap();
        let error = seam.exchange(&[0, 0, 0, 0, 0, 2, 0x1A, 0xC1]).unwrap_err();
        assert!(matches!(error, crate::Error::Io(_)), "{error:?}");
    }

    #[test]
    fn the_channel_opens_on_the_iso15765_protocol() {
        let seam = source(Vec::new());
        assert_eq!(
            seam.channel().protocol,
            vcxtoolkit::collect::ISO15765_PROTOCOL
        );
        assert_eq!(seam.channel().channel, DEFAULT_CHANNEL);
        assert_eq!(seam.channel().caller, DEFAULT_CALLER);
    }

    // The one real-hardware entry point: open the VCX-NANO on the detection-selected
    // port and assert the live vehicle read stays HELD behind vcxtoolkit's owner gate.
    // It opens the serial port only (no ISO 15765 channel open, no VCX_PRO_Send), so it
    // transmits nothing to a vehicle. The port is read from GMDIAG_VCX_PORT, defaulting
    // to the doctor's DEFAULT_DOCTOR_PORT — never a value hardcoded in the exchange path.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs the VCX-NANO dongle; opens the detected serial port, sends no vehicle request"]
    fn detected_port_opens_but_the_vehicle_read_stays_gated() {
        use vcxtoolkit::collect::{READ_LAYOUT_RECOVERED, vehicle_read_gate};

        // Even with an owner opt-in, the shipped layout flag keeps the gate closed:
        // this stack never performs the live vehicle send until the layout is recovered.
        assert!(vehicle_read_gate(READ_LAYOUT_RECOVERED, true).is_err());

        let port = std::env::var("GMDIAG_VCX_PORT")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(super::DEFAULT_DOCTOR_PORT);
        // Constructing the byte source opens the USB port; it opens no channel and
        // sends nothing. The gate above is what forbids the exchange() that would.
        let seam = VcxByteSource::open(port).expect("open VCX-NANO");
        assert_eq!(
            seam.channel().protocol,
            vcxtoolkit::collect::ISO15765_PROTOCOL
        );
    }
}
