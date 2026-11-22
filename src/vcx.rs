//! An **offline** VCX identity-collection adapter: GMLAN `$1A` reads carried over
//! the recovered VCX frame codecs, assembled into a saved module read.
//!
//! This is glue, not a bus. It composes bytes that other crates already own:
//!
//! - `udskit` builds the vehicle-facing request content (`1A <lid>`) and classifies
//!   the response. vcxtoolkit's tool boundary (`docs/tool-boundary.md`) is that
//!   vcxtoolkit *frames* caller bytes and never synthesizes a `$1A` request itself.
//! - `vcxtoolkit::collect` supplies the two recovered frame codecs:
//!   [`frame_identity_request`](vcxtoolkit::collect::frame_identity_request) wraps a
//!   request in the `VCX_PRO_Send` PDU, and
//!   [`reply_application_bytes`](vcxtoolkit::collect::reply_application_bytes) reads
//!   the application bytes back out of a `VCX_PRO_Recv` reply envelope.
//! - `vcxtoolkit::modread` serializes the collected identities as the saved
//!   "module read" that `spskit-vit1 --read` consumes.
//!
//! # The byte seam is injected, and the hardware half is out of scope
//!
//! The adapter never opens a device. It drives a [`ByteSource`] the caller injects:
//! a trait that takes a fully framed request PDU and returns a framed reply PDU.
//! The **real** hardware `ByteSource` — `VCX_PRO_Send`/`VCX_PRO_Recv` over the
//! VCX-NANO — is deliberately **not** built here: vcxtoolkit's live vehicle read
//! stays held and gated (`vcxtoolkit::collect::vehicle_read_gate`,
//! `READ_LAYOUT_RECOVERED == false`), because the vehicle-facing request content is
//! unrecovered. This module ships only an in-process [`FakeByteSource`] that replays
//! canned frames, exactly like the session core's own scripted transport. A future
//! task would add the gated hardware `ByteSource` behind that recovery; nothing here
//! sends a byte to a vehicle.

use std::collections::VecDeque;

use vcxtoolkit::ForwardError;
use vcxtoolkit::collect::{self, ReplyError};
use vcxtoolkit::modread::{IdentifierRead, ModuleRead, ModuleReadError, clone_profile};

use crate::error::{Error, Result};
use crate::transport::{Target, Transport};

/// The GMLAN ReadDataByIdentifier service id (`$1A`), whose positive response is
/// `$5A` (`vcxtoolkit::collect::IDENTITY_POSITIVE_SID`). This is the GM read, not
/// the UDS `$22` (`udskit::did::READ_DATA_BY_IDENTIFIER`).
pub const GM_READ_DATA_BY_IDENTIFIER: u8 = 0x1A;

/// The positive-response id for `$1A` (request id raised by `0x40`).
pub const GM_IDENTITY_POSITIVE_SID: u8 = collect::IDENTITY_POSITIVE_SID;

/// The common `$1A` identity slice a VIT1 clone reads: `C1`..`CA` (ten part
/// numbers) plus `CB`/`CC` (hardware). Re-exported from
/// `vcxtoolkit::collect::DEFAULT_IDENTITY_LIDS` so a caller names one set.
pub const DEFAULT_IDENTITY_LIDS: [u8; 12] = collect::DEFAULT_IDENTITY_LIDS;

impl From<ForwardError> for Error {
    fn from(value: ForwardError) -> Self {
        Error::Protocol(format!("vcx send framing: {value}"))
    }
}

impl From<ReplyError> for Error {
    fn from(value: ReplyError) -> Self {
        match value {
            ReplyError::Negative { .. } => Error::Negative(value.to_string()),
            _ => Error::Protocol(format!("vcx reply envelope: {value}")),
        }
    }
}

impl From<ModuleReadError> for Error {
    fn from(value: ModuleReadError) -> Self {
        Error::Model(format!("saved module read: {value}"))
    }
}

/// The injected byte seam the adapter drives.
///
/// An implementation takes a fully framed VCX request PDU (the output of
/// [`frame_identity_request`](vcxtoolkit::collect::frame_identity_request)) and
/// returns the framed VCX reply PDU (the input to
/// [`reply_application_bytes`](vcxtoolkit::collect::reply_application_bytes)).
/// Everything below the seam — a serial port, a socket, the dongle — is the
/// implementation's concern. The only implementation this crate ships is the
/// in-process [`FakeByteSource`]; the hardware one is out of scope and gated.
pub trait ByteSource {
    /// Exchange one framed request PDU for one framed reply PDU.
    ///
    /// # Errors
    /// Returns an error when the seam cannot deliver a reply.
    fn exchange(&mut self, framed_request: &[u8]) -> Result<Vec<u8>>;
}

/// An in-process [`ByteSource`] that replays canned framed replies, in order.
///
/// Each [`exchange`](ByteSource::exchange) records the framed request it was handed
/// (so a test can assert what was sent) and pops the next canned framed reply,
/// ignoring the request bytes. It touches no hardware and performs no I/O; it is the
/// offline stand-in that the whole adapter is tested through, mirroring the session
/// core's scripted `MockTransport`.
#[derive(Debug, Default)]
pub struct FakeByteSource {
    replies: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl FakeByteSource {
    /// A fake seam that will hand back `replies` in order, one per exchange.
    #[must_use]
    pub fn new(replies: Vec<Vec<u8>>) -> Self {
        Self {
            replies: replies.into(),
            sent: Vec::new(),
        }
    }

    /// The framed request PDUs handed to [`exchange`](ByteSource::exchange) so far,
    /// in order.
    #[must_use]
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }
}

impl ByteSource for FakeByteSource {
    fn exchange(&mut self, framed_request: &[u8]) -> Result<Vec<u8>> {
        self.sent.push(framed_request.to_vec());
        self.replies
            .pop_front()
            .ok_or_else(|| Error::Protocol("fake byte source ran out of canned replies".into()))
    }
}

/// A [`Transport`] that moves application PDUs over the recovered VCX frame codecs
/// and an injected [`ByteSource`].
///
/// [`request`](Transport::request) frames the outbound PDU with
/// [`frame_identity_request`](vcxtoolkit::collect::frame_identity_request), hands it
/// to the byte seam, and unwraps the reply envelope with
/// [`reply_application_bytes`](vcxtoolkit::collect::reply_application_bytes),
/// returning the reassembled application PDU — exactly what
/// `udskit::message::decode_response` consumes. So a
/// [`Session`](crate::session::Session) drives this adapter unchanged, and the
/// vehicle-facing request content stays the caller's (built by `udskit`).
#[derive(Debug)]
pub struct VcxTransport<B: ByteSource> {
    source: B,
    target: Option<Target>,
}

impl<B: ByteSource> VcxTransport<B> {
    /// A transport over `source`, not yet pointed at a target.
    #[must_use]
    pub fn new(source: B) -> Self {
        Self {
            source,
            target: None,
        }
    }

    /// The target this transport was last pointed at, if any.
    #[must_use]
    pub fn target(&self) -> Option<Target> {
        self.target
    }

    /// Borrow the underlying byte seam (to read a [`FakeByteSource`]'s capture).
    #[must_use]
    pub fn source(&self) -> &B {
        &self.source
    }

    /// Consume the transport and return the byte seam.
    #[must_use]
    pub fn into_source(self) -> B {
        self.source
    }
}

impl<B: ByteSource> Transport for VcxTransport<B> {
    fn set_target(&mut self, target: Target) -> Result<()> {
        self.target = Some(target);
        Ok(())
    }

    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        // Pad the ISO 15765 single frame to 8 bytes (VCX PDU flag 0x200, the recovered
        // ISO15765_FRAME_PAD): GM ECUs ignore an unpadded single frame.
        let framed = collect::frame_identity_request_with_flags(collect::ISO15765_FRAME_PAD, pdu)?;
        let reply = self.source.exchange(&framed)?;
        let application = collect::reply_application_bytes(&reply)?;
        Ok(application.to_vec())
    }
}

/// Build the GMLAN `$1A` read request PDU for one identifier: `1A <lid>`.
///
/// This is `udskit`'s job: vcxtoolkit frames caller bytes and never builds a `$1A`
/// request itself. Feed the result to [`VcxTransport::request`] (or
/// [`frame_identity_request`](vcxtoolkit::collect::frame_identity_request) directly)
/// to put it on the wire framing.
#[must_use]
pub fn build_identity_request(identifier: u8) -> Vec<u8> {
    udskit::message::encode_request(GM_READ_DATA_BY_IDENTIFIER, &[identifier])
}

/// Parse a `$1A` identity response PDU for `identifier`, returning its value bytes.
///
/// `application` is the reassembled application PDU (what [`VcxTransport::request`]
/// returns). The classification is `udskit`'s response codec plus the `$1A` echo
/// rule: a positive response is `$5A`, the echoed identifier, then the value bytes
/// `spskit` stores.
///
/// # Errors
/// - [`Error::Negative`] when the controller answered `0x7F` (a negative response).
/// - [`Error::Protocol`] when the PDU is truncated (no response id, or a positive
///   response with no echoed identifier), when the response id is not `$5A`
///   (a different service answered), or when the echoed identifier is not
///   `identifier`.
pub fn parse_identity_reply(application: &[u8], identifier: u8) -> Result<Vec<u8>> {
    use udskit::message::{Response, decode_response};

    match decode_response(application)? {
        Response::Negative(negative) => Err(Error::Negative(negative.describe())),
        Response::Positive(positive) => {
            if positive.response_sid != GM_IDENTITY_POSITIVE_SID {
                return Err(Error::Protocol(format!(
                    "response id {:#04x} is not a $1A identity response ({:#04x})",
                    positive.response_sid, GM_IDENTITY_POSITIVE_SID
                )));
            }
            let Some((&echo, value)) = positive.data.split_first() else {
                return Err(Error::Protocol(
                    "$1A positive response carries no echoed identifier".into(),
                ));
            };
            if echo != identifier {
                return Err(Error::Protocol(format!(
                    "$1A response echoed identifier {echo:#04x}, not the {identifier:#04x} asked"
                )));
            }
            Ok(value.to_vec())
        }
    }
}

/// Read one `$1A` identity over the adapter: build the request (`udskit`), frame and
/// exchange it (`vcxtoolkit` + the seam), and parse the reply (`udskit`).
///
/// Returns the answered identifier as a [`IdentifierRead`] `lid` line, ready for
/// [`assemble_module_read`].
///
/// # Errors
/// Returns a transport error from the seam, or any error from
/// [`parse_identity_reply`].
pub fn read_identity<B: ByteSource>(
    transport: &mut VcxTransport<B>,
    identifier: u8,
) -> Result<IdentifierRead> {
    let request = build_identity_request(identifier);
    let application = transport.request(&request)?;
    let value = parse_identity_reply(&application, identifier)?;
    Ok(IdentifierRead::lid(identifier, value))
}

/// Read a set of `$1A` identities over the adapter and assemble them into one saved
/// module read.
///
/// The identities are read in `lids` order and filed under `ecu` with the given CAN
/// headers; `functional` records whether the request was functional. Drive this with
/// a [`FakeByteSource`] carrying one canned reply per lid.
///
/// # Errors
/// Returns the first error from [`read_identity`], or [`Error::Model`] when the ECU
/// name is unusable for the saved-read format.
pub fn collect_identities<B: ByteSource>(
    transport: &mut VcxTransport<B>,
    ecu: &str,
    request_header: u16,
    response_header: u16,
    functional: bool,
    lids: &[u8],
) -> Result<ModuleRead> {
    let mut reads = Vec::with_capacity(lids.len());
    for &lid in lids {
        reads.push(read_identity(transport, lid)?);
    }
    assemble_module_read(ecu, request_header, response_header, functional, reads)
}

/// Assemble parsed `$1A` identities into one saved-read [`ModuleRead`] block.
///
/// # Errors
/// Returns [`Error::Model`] when the ECU name is empty or carries whitespace (which
/// would split the `ecu` line of the saved-read format).
pub fn assemble_module_read(
    ecu: &str,
    request_header: u16,
    response_header: u16,
    functional: bool,
    reads: Vec<IdentifierRead>,
) -> Result<ModuleRead> {
    let mut block = ModuleRead::new(ecu, request_header, response_header, functional)?;
    for read in reads {
        block.push(read);
    }
    Ok(block)
}

/// Serialize saved-read blocks to the documented clone-profile text
/// `spskit-vit1 --read` consumes (`vcxtoolkit::modread::clone_profile`).
///
/// # Errors
/// Returns [`Error::Model`] when a `lid`/`did` line cannot be formatted (an
/// identifier too wide, or an unknown service).
pub fn serialize_saved_read(blocks: &[ModuleRead]) -> Result<String> {
    Ok(clone_profile(blocks)?)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_IDENTITY_LIDS, FakeByteSource, GM_IDENTITY_POSITIVE_SID, VcxTransport,
        assemble_module_read, build_identity_request, collect_identities, parse_identity_reply,
        read_identity, serialize_saved_read,
    };
    use crate::error::Error;
    use crate::transport::Target;
    use vcxtoolkit::collect::frame_identity_request;
    use vcxtoolkit::modread::IdentifierRead;

    /// A reply PDU in the recovered `VCX_PRO_Recv` envelope: flags u32 **LE**, len
    /// u16 **LE**, then the application bytes. Mirrors `ConvertVCXMsg`.
    fn reply_pdu(flags: u32, application: &[u8]) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(6 + application.len());
        pdu.extend_from_slice(&flags.to_le_bytes());
        pdu.extend_from_slice(&u16::try_from(application.len()).unwrap().to_le_bytes());
        pdu.extend_from_slice(application);
        pdu
    }

    /// A positive `$1A` reply for `identifier` carrying `value`.
    fn positive_reply(identifier: u8, value: &[u8]) -> Vec<u8> {
        let mut application = vec![GM_IDENTITY_POSITIVE_SID, identifier];
        application.extend_from_slice(value);
        reply_pdu(0, &application)
    }

    #[test]
    fn udskit_built_1a_request_frames_to_the_expected_bytes() {
        // udskit builds `1A <lid>` (application PDU, no ISO-TP PCI byte); the VCX
        // send framing prepends flags(u32 BE)=0 and len(u16 BE), copying the bytes
        // to offset 6 for ISO 15765.
        for (lid, expected) in [
            (0xC1_u8, vec![0, 0, 0, 0, 0, 2, 0x1A, 0xC1]),
            (0xCC_u8, vec![0, 0, 0, 0, 0, 2, 0x1A, 0xCC]),
        ] {
            let request = build_identity_request(lid);
            assert_eq!(request, vec![0x1A, lid], "udskit builds 1A <lid>");
            assert_eq!(frame_identity_request(&request).unwrap(), expected);
        }
    }

    #[test]
    fn the_fake_seam_captures_the_exact_framed_request() {
        // Driving a read through the fake proves the udskit-built, vcx-framed bytes
        // are what reaches the seam.
        let mut transport =
            VcxTransport::new(FakeByteSource::new(vec![positive_reply(0xC1, &[0x2A])]));
        let read = read_identity(&mut transport, 0xC1).unwrap();
        assert_eq!(read, IdentifierRead::lid(0xC1, vec![0x2A]));
        // Flags 0x200 (ISO15765_FRAME_PAD), len 2, then `1A C1`.
        assert_eq!(
            transport.source().sent(),
            &[vec![0, 0, 0x02, 0, 0, 2, 0x1A, 0xC1]],
        );
    }

    #[test]
    fn a_positive_canned_reply_unwraps_and_parses_to_its_value() {
        for (lid, value) in [
            (0xC1_u8, vec![0x31, 0x32, 0x33, 0x34]),
            (0xCC_u8, vec![0xAB]),
            (0xCB_u8, Vec::new()),
        ] {
            let mut transport =
                VcxTransport::new(FakeByteSource::new(vec![positive_reply(lid, &value)]));
            assert_eq!(
                read_identity(&mut transport, lid).unwrap(),
                IdentifierRead::lid(lid, value),
            );
        }
    }

    #[test]
    fn a_negative_canned_reply_is_a_negative_error() {
        // 0x7F, service $1A, code 0x31 (requestOutOfRange).
        let mut transport =
            VcxTransport::new(FakeByteSource::new(vec![reply_pdu(0, &[0x7F, 0x1A, 0x31])]));
        let error = read_identity(&mut transport, 0xC1).unwrap_err();
        assert!(matches!(error, Error::Negative(_)), "{error:?}");
        assert!(error.to_string().contains("requestOutOfRange"), "{error}");
    }

    #[test]
    fn a_truncated_envelope_is_a_protocol_error() {
        // Six bytes of envelope are the minimum; two bytes have none.
        let mut transport = VcxTransport::new(FakeByteSource::new(vec![vec![0x00, 0x00]]));
        assert!(matches!(
            read_identity(&mut transport, 0xC1),
            Err(Error::Protocol(_)),
        ));
        // A positive response with no echoed identifier is truncated at the app layer.
        let mut transport = VcxTransport::new(FakeByteSource::new(vec![reply_pdu(
            0,
            &[GM_IDENTITY_POSITIVE_SID],
        )]));
        let error = read_identity(&mut transport, 0xC1).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert!(error.to_string().contains("echoed identifier"), "{error}");
    }

    #[test]
    fn a_wrong_echo_is_refused() {
        // Right service $5A, wrong echoed identifier.
        let mut transport =
            VcxTransport::new(FakeByteSource::new(vec![positive_reply(0xC2, &[0x00])]));
        let error = read_identity(&mut transport, 0xC1).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert!(error.to_string().contains("echoed identifier"), "{error}");
    }

    #[test]
    fn a_wrong_service_reply_is_refused() {
        // 0x62 is the UDS $22 positive response, not the $1A ($5A) expected.
        let mut transport =
            VcxTransport::new(FakeByteSource::new(vec![reply_pdu(0, &[0x62, 0xC1, 0x00])]));
        let error = read_identity(&mut transport, 0xC1).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert!(error.to_string().contains("not a $1A"), "{error}");
    }

    #[test]
    fn parse_is_independent_of_the_seam() {
        // The application-layer parse stands alone over canned application bytes.
        assert_eq!(
            parse_identity_reply(&[GM_IDENTITY_POSITIVE_SID, 0xC1, 0xDE, 0xAD], 0xC1).unwrap(),
            vec![0xDE, 0xAD],
        );
        assert!(parse_identity_reply(&[], 0xC1).is_err());
    }

    #[test]
    fn collected_identities_serialize_to_the_expected_saved_read() {
        // Two canned positive replies, read in order, assembled and serialized.
        let mut transport = VcxTransport::new(FakeByteSource::new(vec![
            positive_reply(0xC1, &[0x00, 0x00, 0x00, 0x2A]),
            positive_reply(0xCC, &[0x56, 0x49, 0x4E]),
        ]));
        let block =
            collect_identities(&mut transport, "BECM", 0x7E4, 0x7EC, false, &[0xC1, 0xCC]).unwrap();
        let text = serialize_saved_read(&[block]).unwrap();

        let lines: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
        assert_eq!(lines[0], "s3 5000");
        assert_eq!(
            lines[1],
            "ecu BECM req=7E4 resp=7EC functional=no pad=00 latency=0",
        );
        assert_eq!(lines[2], "lid C1 0000002A");
        assert_eq!(lines[3], "lid CC 56494E");
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn assemble_rejects_a_bad_ecu_name() {
        let error = assemble_module_read("BE CM", 0x7E4, 0x7EC, false, Vec::new()).unwrap_err();
        assert!(matches!(error, Error::Model(_)), "{error:?}");
    }

    #[test]
    fn the_adapter_drives_the_session_core_as_a_transport() {
        // The Session's generic exchange decodes the application PDU this transport
        // returns — proof the adapter satisfies the Transport contract end to end.
        let transport = VcxTransport::new(FakeByteSource::new(vec![positive_reply(0xC1, &[0x2A])]));
        let mut session =
            crate::session::Session::new(transport, Target::new(0x7E0, 0x7E8)).unwrap();
        let positive = session
            .positive(super::GM_READ_DATA_BY_IDENTIFIER, &[0xC1])
            .unwrap();
        assert_eq!(positive.response_sid, GM_IDENTITY_POSITIVE_SID);
        assert_eq!(positive.data, vec![0xC1, 0x2A]);
    }

    #[test]
    fn the_default_identity_lids_are_the_vit1_slice() {
        assert_eq!(DEFAULT_IDENTITY_LIDS.len(), 12);
        assert_eq!(DEFAULT_IDENTITY_LIDS[0], 0xC1);
        assert_eq!(DEFAULT_IDENTITY_LIDS[11], 0xCC);
    }
}
