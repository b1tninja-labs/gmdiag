//! The one seam between the session core and a vehicle link.
//!
//! A [`Transport`] sends a UDS *application* PDU and returns the reassembled response PDU.
//! Everything below it — the ISO-TP segmentation, the adapter line protocol, the socket — is
//! the transport's concern; everything above it — building and decoding PDUs — is `udskit`'s.
//! The session core ([`crate::session`]) is written against this trait and never touches a
//! socket directly, so the same session drives an [`elm327::Elm327Tcp`] against a real adapter,
//! against `obd-bridge`, or against a spawned `fakeobd`.
//!
//! A transport is **neutral**: it sends whatever PDU it is handed. The read-first policy and the
//! write/actuation gating live one layer up, in the session and the CLI, so that a single place
//! owns the decision and the confirmation.

pub mod elm327;
pub mod isotp_can;
pub mod vci;

use crate::error::Result;

/// A diagnostic peer: the request arbitration id and the ids derived from it.
///
/// GMLAN and OBD both start from the physical *request* id. GMLAN responses are the request id
/// plus `0x400` (`udskit::gmlan::GMLAN_RESPONSE_OFFSET`); legacy-OBD 11-bit responses are the
/// request id plus `0x08` (`udskit::gmlan::OBD_PHYSICAL_RESPONSE_OFFSET`). The flow-control
/// header a tester sets is the physical request id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// The physical request (transmit) arbitration id.
    pub request_id: u16,
    /// The expected response (receive) arbitration id.
    pub response_id: u16,
    /// The flow-control header the tester sends (the physical request id).
    pub flow_control_id: u16,
}

impl Target {
    /// A target with an explicit request and response id.
    #[must_use]
    pub fn new(request_id: u16, response_id: u16) -> Self {
        Self {
            request_id,
            response_id,
            flow_control_id: request_id,
        }
    }

    /// A GMLAN target: the response id is the request id plus `0x400`.
    ///
    /// # Errors
    /// Returns an error when `request_id` plus the offset does not fit in 11 bits
    /// (see `udskit::gmlan::response_id`).
    pub fn gmlan(request_id: u16) -> Result<Self> {
        let response_id = udskit::gmlan::response_id(request_id)?;
        Ok(Self::new(request_id, response_id))
    }

    /// A legacy-OBD 11-bit target: the response id is the request id plus `0x08`
    /// (`7E0` → `7E8`).
    ///
    /// # Errors
    /// Returns an error when `request_id` is outside the OBD physical request range
    /// (see `udskit::gmlan::obd_response_id`).
    pub fn obd(request_id: u16) -> Result<Self> {
        let response_id = udskit::gmlan::obd_response_id(request_id)?;
        Ok(Self::new(request_id, response_id))
    }
}

/// A link that carries one UDS application PDU and returns the response PDU.
///
/// Implementations reassemble a multi-frame response into the single application PDU the
/// standard defines; the caller sees ISO-TP neither on the way out nor on the way back.
pub trait Transport {
    /// Point the link at a peer: set the transmit header, the receive filter, and the
    /// flow-control header.
    ///
    /// # Errors
    /// Returns an error when the link cannot be configured for `target`.
    fn set_target(&mut self, target: Target) -> Result<()>;

    /// Send `pdu` (a service SID and its data) and return the reassembled response PDU.
    ///
    /// The returned bytes are the application-layer response, ready for
    /// `udskit::message::decode_response`.
    ///
    /// # Errors
    /// Returns [`crate::Error::Io`] on a link failure, [`crate::Error::Adapter`] when the
    /// adapter reports a non-data status, and [`crate::Error::Protocol`] when the reply does
    /// not parse as a PDU.
    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>>;

    /// Read a follow-up response without sending a new request.
    ///
    /// After a server answers `0x78` (requestCorrectlyReceived-ResponsePending, ISO 14229-1
    /// §7.5.1), the final response arrives as a *later* message on the same exchange, not in
    /// answer to a resend. The session's response-pending loop calls this to collect it. The
    /// default is an error: a transport that cannot read a second time does not support the
    /// loop, and the session then surfaces the pending response as-is.
    ///
    /// # Errors
    /// Returns an error when the transport cannot read a follow-up, or on a link failure.
    fn read_more(&mut self) -> Result<Vec<u8>> {
        Err(crate::error::Error::Protocol(
            "this transport cannot read a response-pending follow-up".into(),
        ))
    }
}
