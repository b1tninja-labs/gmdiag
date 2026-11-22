//! A raw-CAN [`Transport`] that runs ISO-TP (ISO 15765-2) itself over a [`CanLink`] seam.
//!
//! The [`Elm327Tcp`](super::elm327::Elm327Tcp) transport leans on the adapter to run ISO-TP.
//! A raw-CAN link (SocketCAN, an SLCAN serial dongle, a J2534/VCX interface) has no such adapter,
//! so gmdiag must run the transport/network layer itself: `isotpkit` (ISO 15765-2:2016) does the
//! segmentation and reassembly, and this module paces the exchange with flow control.
//!
//! The one testable boundary is [`CanLink`] — `send_frame` / `recv_frame` over raw CAN — mirroring
//! the way `Elm327Tcp` wraps a `TcpStream`. [`IsoTpCan`] is written against that trait, so the
//! whole transmit → flow-control → reassembly path is exercised against a scripted
//! `MockCanLink` with no hardware. The concrete links ([`SlcanTcp`], a future SocketCAN) only move
//! raw frames; on-vehicle validation of either is still a planned row.
//!
//! Like `Elm327Tcp`, this transport is **neutral**: it sends whatever PDU it is handed and returns
//! whatever PDU comes back, negative responses included. The read-first policy and the
//! write/actuation gating live one layer up, in the session and the CLI.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use isotpkit::flowcontrol::{FlowStatus, SeparationTime};
use isotpkit::pci::{FlowControl, NPdu, decode_frame};
use isotpkit::segment::{Reassembler, SegmentPdu, segment as isotp_segment};

use crate::error::{Error, Result};
use crate::transport::{Target, Transport};

/// How long a single frame read waits before the exchange is declared timed out
/// (`N_Bs` / `N_Cr`, ISO 15765-2:2016 §9.8.2). Overridable per instance.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum FlowControl `WAIT` frames tolerated in a row before aborting (`N_WFTmax`,
/// ISO 15765-2:2016 §9.7). A receiver that keeps asking us to wait past this is giving up.
pub const N_WFT_MAX: usize = 16;

/// A raw CAN link: the single testable seam under the ISO-TP transport.
///
/// An implementation moves one classic-CAN frame at a time — an 11-bit arbitration id and up to 8
/// data bytes — and nothing more. All of ISO-TP (segmentation, flow control, reassembly) lives in
/// [`IsoTpCan`] above this trait, so the protocol is proved against a mock link rather than
/// hardware.
pub trait CanLink {
    /// Transmit one CAN frame: an 11-bit arbitration `id` and its data bytes (0..=8).
    ///
    /// # Errors
    /// Returns an error on a link failure, or when `id` or `data` is out of range for the link.
    fn send_frame(&mut self, id: u16, data: &[u8]) -> Result<()>;

    /// Receive the next CAN frame, waiting at most `timeout`.
    ///
    /// # Errors
    /// Returns [`Error::Io`] (kind `TimedOut`/`WouldBlock`) when no frame arrives within `timeout`,
    /// or another error on a link failure.
    fn recv_frame(&mut self, timeout: Duration) -> Result<(u16, Vec<u8>)>;
}

/// A raw-CAN transport that runs ISO-TP over a [`CanLink`].
///
/// `set_target` records the request / response / flow-control arbitration ids; `request` segments
/// the PDU with `isotpkit`, paces the ConsecutiveFrames by the receiver's FlowControl, then
/// reassembles the response (granting the sender a FlowControl of its own when the response is
/// multi-frame).
pub struct IsoTpCan<L: CanLink> {
    link: L,
    target: Option<Target>,
    timeout: Duration,
}

impl<L: CanLink> IsoTpCan<L> {
    /// A new raw-CAN transport over `link`, with the default per-frame timeout and no target set.
    #[must_use]
    pub fn new(link: L) -> Self {
        Self {
            link,
            target: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// A new raw-CAN transport over `link` with an explicit per-frame read timeout.
    #[must_use]
    pub fn with_timeout(link: L, timeout: Duration) -> Self {
        Self {
            link,
            target: None,
            timeout,
        }
    }

    /// Set the per-frame read timeout (`N_Bs` / `N_Cr`).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// The configured target, or a refusal when `set_target` has not been called.
    fn require_target(&self) -> Result<Target> {
        self.target
            .ok_or_else(|| Error::Refused("no target set; call set_target before request".into()))
    }

    /// Transmit `pdu` as an ISO-TP message, pacing ConsecutiveFrames by the receiver's FlowControl.
    ///
    /// A short PDU is one SingleFrame and needs no flow control. A longer PDU is a FirstFrame
    /// followed by ConsecutiveFrames; after the FirstFrame the sender waits for a FlowControl and
    /// then sends CFs up to `BlockSize` at a time, honouring `STmin` (ISO 15765-2:2016 §9.3).
    fn send_pdu(&mut self, target: Target, pdu: &[u8]) -> Result<()> {
        let segments =
            isotp_segment(pdu).map_err(|e| Error::Protocol(format!("isotp segment: {e}")))?;
        // segments[0] is always an SF or FF; the rest (if any) are CFs.
        self.link
            .send_frame(target.request_id, &segments[0].encode())?;
        if matches!(segments[0], SegmentPdu::Single(_)) {
            return Ok(());
        }

        let consecutive = &segments[1..];
        let mut sent = 0usize;
        let mut fc = self.await_continue(target)?;
        while sent < consecutive.len() {
            let block_end = if fc.block_size == 0 {
                consecutive.len()
            } else {
                sent.saturating_add(usize::from(fc.block_size))
                    .min(consecutive.len())
            };
            let stmin = SeparationTime::from_byte(fc.stmin).microseconds();
            for cf in &consecutive[sent..block_end] {
                self.link.send_frame(target.request_id, &cf.encode())?;
                sleep_micros(stmin);
            }
            sent = block_end;
            if sent < consecutive.len() {
                // BlockSize was non-zero: the receiver meters each block with a fresh FlowControl.
                fc = self.await_continue(target)?;
            }
        }
        Ok(())
    }

    /// Wait for a FlowControl ContinueToSend, tolerating up to `N_WFT_MAX` WAIT frames.
    ///
    /// OVFLW aborts (the receiver cannot hold `FF_DL`); a non-FC N_PDU where an FC is due is a
    /// protocol error (ISO 15765-2:2016 §9.6.5).
    fn await_continue(&mut self, target: Target) -> Result<FlowControl> {
        for _ in 0..N_WFT_MAX {
            let data = self.recv_matching(target.response_id)?;
            match decode_frame(&data).map_err(|e| Error::Protocol(format!("isotp decode: {e}")))? {
                NPdu::Flow(fc) => match fc.flow_status {
                    FlowStatus::ContinueToSend => return Ok(fc),
                    FlowStatus::Wait => {}
                    FlowStatus::Overflow => {
                        return Err(Error::Adapter(
                            "receiver FlowControl OVFLW: buffer too small for the message".into(),
                        ));
                    }
                },
                other => {
                    return Err(Error::Protocol(format!(
                        "expected a FlowControl after the FirstFrame, got {other:?}"
                    )));
                }
            }
        }
        Err(Error::Adapter(
            "too many FlowControl WAIT frames in a row (N_WFTmax)".into(),
        ))
    }

    /// Receive one ISO-TP message, granting the sender a FlowControl if the response is multi-frame.
    ///
    /// A SingleFrame response completes at once. A multi-frame response arrives as a FirstFrame —
    /// which we answer with a FlowControl ContinueToSend on the flow-control id — then
    /// ConsecutiveFrames until the message is whole.
    fn recv_pdu(&mut self, target: Target) -> Result<Vec<u8>> {
        let mut reassembler = Reassembler::new();
        loop {
            let data = self.recv_matching(target.response_id)?;
            let npdu =
                decode_frame(&data).map_err(|e| Error::Protocol(format!("isotp decode: {e}")))?;
            let segment = match npdu {
                NPdu::Single(sf) => SegmentPdu::Single(sf),
                NPdu::First(ff) => {
                    let opened = reassembler
                        .feed(&SegmentPdu::First(ff))
                        .map_err(|e| reassemble_error(&e))?;
                    debug_assert!(opened.is_none(), "a FirstFrame never completes a message");
                    // Grant the sender: the tester's FlowControl goes out on the flow-control id.
                    self.link.send_frame(
                        target.flow_control_id,
                        &FlowControl::continue_to_send().encode(),
                    )?;
                    continue;
                }
                NPdu::Consecutive(cf) => SegmentPdu::Consecutive(cf),
                NPdu::Flow(_) => {
                    return Err(Error::Protocol(
                        "unexpected FlowControl while awaiting a response".into(),
                    ));
                }
            };
            if let Some(message) = reassembler
                .feed(&segment)
                .map_err(|e| reassemble_error(&e))?
            {
                return Ok(message);
            }
        }
    }

    /// Read frames until one carries the expected arbitration id, dropping foreign-id traffic.
    ///
    /// A raw CAN link with no hardware filter delivers every frame on the bus; the response filter
    /// is ours to apply. Each read is bounded by `timeout`, so a bus with no matching frame times
    /// out rather than spins.
    fn recv_matching(&mut self, id: u16) -> Result<Vec<u8>> {
        loop {
            let (rid, data) = self.link.recv_frame(self.timeout)?;
            if rid == id {
                return Ok(data);
            }
        }
    }
}

impl<L: CanLink> Transport for IsoTpCan<L> {
    fn set_target(&mut self, target: Target) -> Result<()> {
        self.target = Some(target);
        Ok(())
    }

    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        if pdu.is_empty() {
            return Err(Error::Protocol("empty request pdu".into()));
        }
        let target = self.require_target()?;
        self.send_pdu(target, pdu)?;
        self.recv_pdu(target)
    }

    fn read_more(&mut self) -> Result<Vec<u8>> {
        // The response-pending (0x78) follow-up is a later ISO-TP message on the same ids; read it
        // without sending a new request.
        let target = self.require_target()?;
        self.recv_pdu(target)
    }
}

/// Segment an application PDU into ISO-TP N_PDUs with `isotpkit` (the transmit framing).
///
/// Exposed so the framing is checkable on its own, independent of a link.
///
/// # Errors
/// Returns [`Error::Protocol`] when the message exceeds what ISO-TP can carry
/// (see `isotpkit::segment`).
pub fn segment(pdu: &[u8]) -> Result<Vec<SegmentPdu>> {
    isotp_segment(pdu).map_err(|e| Error::Protocol(format!("isotp segment: {e}")))
}

fn reassemble_error(e: &isotpkit::Error) -> Error {
    Error::Protocol(format!("isotp reassemble: {e}"))
}

fn sleep_micros(micros: u32) {
    if micros > 0 {
        std::thread::sleep(Duration::from_micros(u64::from(micros)));
    }
}

/// An SLCAN (LAWICEL) raw-CAN link over TCP: a pure-safe concrete [`CanLink`].
///
/// SLCAN is the ASCII serial protocol a USB/serial CAN dongle speaks; bridged over TCP it needs no
/// `unsafe` and no OS CAN API, so it builds and lints on every platform. A standard (11-bit) data
/// frame is `t<iii><l><dd..>\r`. SocketCAN (Linux `AF_CAN`) would be the native alternative but
/// needs `unsafe`/`libc`, which this crate forbids, so it remains a planned row. Opening a real bus
/// is not exercised by the test gate — only the frame codec is — so on-vehicle use is still `[open]`.
pub struct SlcanTcp {
    stream: TcpStream,
    rx: Vec<u8>,
}

impl SlcanTcp {
    /// Connect to an SLCAN-over-TCP bridge and open the channel at 500 kbit/s (ISO 15765-4).
    ///
    /// Sends the LAWICEL open sequence `C` (close), `S6` (500 kbit/s), `O` (open). The ack bytes a
    /// bridge returns are drained and ignored.
    ///
    /// # Errors
    /// Returns [`Error::Io`] when the connection or the open sequence fails.
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
        let mut link = Self {
            stream,
            rx: Vec::new(),
        };
        for command in [b"C\r".as_slice(), b"S6\r", b"O\r"] {
            link.stream.write_all(command)?;
        }
        link.drain_acks();
        Ok(link)
    }

    /// Read and discard any immediately available ack bytes from the open sequence.
    fn drain_acks(&mut self) {
        let mut scratch = [0u8; 64];
        // One short read; a bridge that sends nothing back just leaves this empty.
        if self.stream.read(&mut scratch).is_ok() {
            self.rx.clear();
        }
    }
}

impl CanLink for SlcanTcp {
    fn send_frame(&mut self, id: u16, data: &[u8]) -> Result<()> {
        let line = encode_slcan_tx(id, data)?;
        self.stream.write_all(&line)?;
        Ok(())
    }

    fn recv_frame(&mut self, timeout: Duration) -> Result<(u16, Vec<u8>)> {
        self.stream.set_read_timeout(Some(timeout))?;
        loop {
            if let Some(pos) = self.rx.iter().position(|&b| b == b'\r') {
                let line: Vec<u8> = self.rx.drain(..=pos).collect();
                if let Some(frame) = parse_slcan_rx(&line[..line.len() - 1])? {
                    return Ok(frame);
                }
                continue;
            }
            let mut scratch = [0u8; 256];
            let n = self.stream.read(&mut scratch)?;
            if n == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "SLCAN link closed",
                )));
            }
            self.rx.extend_from_slice(&scratch[..n]);
        }
    }
}

/// Encode a standard (11-bit) SLCAN transmit line: `t<iii><l><dd..>\r`.
///
/// # Errors
/// Returns [`Error::Protocol`] when `id` exceeds 11 bits or `data` exceeds 8 bytes.
pub fn encode_slcan_tx(id: u16, data: &[u8]) -> Result<Vec<u8>> {
    use std::fmt::Write as _;
    if id > 0x7FF {
        return Err(Error::Protocol(format!("CAN id {id:#X} exceeds 11 bits")));
    }
    if data.len() > 8 {
        return Err(Error::Protocol(format!(
            "CAN frame has {} bytes (max 8)",
            data.len()
        )));
    }
    let mut line = String::with_capacity(5 + data.len() * 2);
    let _ = write!(line, "t{id:03X}{}", data.len());
    for byte in data {
        let _ = write!(line, "{byte:02X}");
    }
    line.push('\r');
    Ok(line.into_bytes())
}

/// Parse one SLCAN line (CR already stripped). A standard data frame `t<iii><l><dd..>` yields
/// `Some((id, data))`; any other line (an ack, an extended frame, a status reply) yields `None`.
///
/// # Errors
/// Returns [`Error::Protocol`] when a `t` line is malformed (short, non-hex, or a length that does
/// not match the data).
pub fn parse_slcan_rx(line: &[u8]) -> Result<Option<(u16, Vec<u8>)>> {
    if line.first() != Some(&b't') {
        return Ok(None);
    }
    if line.len() < 5 {
        return Err(Error::Protocol("SLCAN 't' frame too short".into()));
    }
    let id = u16::from(hex_val(line[1])?) << 8
        | u16::from(hex_val(line[2])?) << 4
        | u16::from(hex_val(line[3])?);
    let dlc = usize::from(hex_val(line[4])?);
    if dlc > 8 {
        return Err(Error::Protocol(format!("SLCAN DLC {dlc} exceeds 8")));
    }
    let body = &line[5..];
    if body.len() != dlc * 2 {
        return Err(Error::Protocol(format!(
            "SLCAN frame says {dlc} bytes but carries {} hex chars",
            body.len()
        )));
    }
    let mut data = Vec::with_capacity(dlc);
    for pair in body.chunks_exact(2) {
        data.push(hex_val(pair[0])? << 4 | hex_val(pair[1])?);
    }
    Ok(Some((id, data)))
}

fn hex_val(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        other => Err(Error::Protocol(format!(
            "not a hex digit: {:?}",
            char::from(other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A scripted [`CanLink`]: records every frame sent, and returns queued frames from `recv`.
    ///
    /// The queue is pre-loaded with exactly what a receiver would put on the bus — a FlowControl
    /// to meter our request, then the response frames — so a whole ISO-TP exchange runs with no
    /// hardware and no timers.
    #[derive(Default)]
    struct MockCanLink {
        sent: Vec<(u16, Vec<u8>)>,
        inbound: VecDeque<(u16, Vec<u8>)>,
    }

    impl MockCanLink {
        fn queue(&mut self, id: u16, data: Vec<u8>) {
            self.inbound.push_back((id, data));
        }
    }

    impl CanLink for MockCanLink {
        fn send_frame(&mut self, id: u16, data: &[u8]) -> Result<()> {
            self.sent.push((id, data.to_vec()));
            Ok(())
        }

        fn recv_frame(&mut self, _timeout: Duration) -> Result<(u16, Vec<u8>)> {
            self.inbound.pop_front().ok_or_else(|| {
                Error::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mock link: no more scripted frames",
                ))
            })
        }
    }

    /// Encode an application message to its ISO-TP frames (padded, on-wire), as a receiver sends.
    fn frames_of(message: &[u8]) -> Vec<Vec<u8>> {
        segment(message)
            .unwrap()
            .iter()
            .map(SegmentPdu::encode)
            .collect()
    }

    const REQ: u16 = 0x7E0;
    const RESP: u16 = 0x7E8;

    #[test]
    fn a_short_pdu_segments_into_one_frame() {
        let frames = segment(&[0x22, 0x00, 0x2F]).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], SegmentPdu::Single(_)));
    }

    #[test]
    fn request_is_refused_until_a_target_is_set() {
        let mut t = IsoTpCan::new(MockCanLink::default());
        let err = t.request(&[0x22, 0x00, 0x2F]).unwrap_err();
        assert!(matches!(err, Error::Refused(_)));
    }

    #[test]
    fn a_multi_frame_request_round_trips_over_the_can_seam() {
        // Request that needs a FirstFrame + one ConsecutiveFrame (10 bytes > 7).
        let request: Vec<u8> = (0x10..0x1A).collect();
        assert_eq!(request.len(), 10);
        // A 12-byte response: also multi-frame, so the tester must grant the sender a FlowControl.
        let response: Vec<u8> = (0x50..0x5C).collect();
        assert_eq!(response.len(), 12);

        let mut link = MockCanLink::default();
        // The receiver's FlowControl that meters our request transmission (CTS, BS 0, STmin 0).
        link.queue(RESP, FlowControl::continue_to_send().encode());
        // The receiver's multi-frame response (FF then CF) on the response id.
        for frame in frames_of(&response) {
            link.queue(RESP, frame);
        }

        let mut transport = IsoTpCan::new(link);
        transport.set_target(Target::new(REQ, RESP)).unwrap();
        let got = transport.request(&request).unwrap();

        // Reassembly in: the whole response PDU came back, unchanged.
        assert_eq!(got, response);

        // Segmentation out: the request went out as its FirstFrame then ConsecutiveFrame on REQ.
        // (The tester's own FlowControl for the response also rides REQ, since flow_control_id
        // defaults to the request id — exclude it here; it is checked separately below.)
        let outbound = &transport.link.sent;
        let request_frames: Vec<&Vec<u8>> = outbound
            .iter()
            .filter(|(id, _)| *id == REQ)
            .map(|(_, data)| data)
            .filter(|data| !matches!(decode_frame(data), Ok(NPdu::Flow(_))))
            .collect();
        let expected_request = frames_of(&request);
        assert_eq!(request_frames.len(), expected_request.len());
        assert_eq!(request_frames.len(), 2, "FirstFrame + one ConsecutiveFrame");
        for (got, want) in request_frames.iter().zip(&expected_request) {
            assert_eq!(*got, want);
        }

        // Flow control out: we granted the sender exactly one ContinueToSend, on the FC id.
        let fc_id = Target::new(REQ, RESP).flow_control_id;
        let fc_out: Vec<&(u16, Vec<u8>)> = outbound
            .iter()
            .filter(|(id, _)| *id == fc_id)
            .filter(|(_, data)| matches!(decode_frame(data), Ok(NPdu::Flow(_))))
            .collect();
        assert_eq!(
            fc_out.len(),
            1,
            "one tester FlowControl for the multi-frame response"
        );
        match decode_frame(&fc_out[0].1).unwrap() {
            NPdu::Flow(fc) => assert_eq!(fc.flow_status, FlowStatus::ContinueToSend),
            other => panic!("expected a FlowControl, got {other:?}"),
        }
    }

    #[test]
    fn a_negative_response_is_surfaced_not_swallowed() {
        // 7F 22 31 (requestOutOfRange for service 0x22) is a single-frame negative response.
        let negative = vec![0x7F, 0x22, 0x31];
        let mut link = MockCanLink::default();
        link.queue(RESP, frames_of(&negative).into_iter().next().unwrap());

        let mut transport = IsoTpCan::new(link);
        transport.set_target(Target::new(REQ, RESP)).unwrap();
        // A short request is a SingleFrame: no FlowControl needed before the response.
        let got = transport.request(&[0x22, 0x00, 0x2F]).unwrap();
        assert_eq!(
            got, negative,
            "the transport is neutral: the NRC passes through"
        );
    }

    #[test]
    fn a_flow_control_overflow_aborts_the_request() {
        let request: Vec<u8> = (0x10..0x1A).collect(); // multi-frame, so a FC is awaited
        let mut link = MockCanLink::default();
        link.queue(RESP, FlowControl::new(FlowStatus::Overflow, 0, 0).encode());

        let mut transport = IsoTpCan::new(link);
        transport.set_target(Target::new(REQ, RESP)).unwrap();
        let err = transport.request(&request).unwrap_err();
        assert!(matches!(err, Error::Adapter(_)), "OVFLW aborts: {err:?}");
    }

    #[test]
    fn slcan_tx_encodes_a_standard_frame() {
        assert_eq!(
            encode_slcan_tx(0x7E0, &[0x02, 0x10, 0x03]).unwrap(),
            b"t7E03021003\r".to_vec()
        );
        assert!(encode_slcan_tx(0x800, &[]).is_err(), "id over 11 bits");
        assert!(
            encode_slcan_tx(0x7E0, &[0; 9]).is_err(),
            "over 8 data bytes"
        );
    }

    #[test]
    fn slcan_rx_parses_a_standard_frame_and_ignores_acks() {
        assert_eq!(
            parse_slcan_rx(b"t7E850622112233").unwrap(),
            Some((0x7E8, vec![0x06, 0x22, 0x11, 0x22, 0x33]))
        );
        // A bare CR ack and a status byte are not data frames.
        assert_eq!(parse_slcan_rx(b"").unwrap(), None);
        assert_eq!(parse_slcan_rx(b"z").unwrap(), None);
        // A length that does not match the hex body is a protocol error.
        assert!(parse_slcan_rx(b"t7E8308").is_err());
    }
}
