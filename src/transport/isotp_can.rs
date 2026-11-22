//! A planned raw-CAN [`Transport`] that frames PDUs with `isotpkit`.
//!
//! The [`Elm327Tcp`](super::elm327::Elm327Tcp) transport leans on the adapter to run ISO-TP.
//! A raw-CAN link (SocketCAN, a J2534/VCX interface) has no such adapter, so gmdiag must run the
//! transport layer itself — `isotpkit` (ISO 15765-2) does the segmentation and reassembly. That
//! link is a planned row: there is no CAN interface wired in here, so [`IsoTpCan::request`]
//! returns an error rather than guess at hardware. The segmentation path below is exercised and
//! real; only the frame send/receive is absent.

use crate::error::{Error, Result};
use crate::transport::{Target, Transport};

/// A raw-CAN transport that segments with `isotpkit`. **Not yet wired to a CAN interface.**
#[derive(Debug, Default)]
pub struct IsoTpCan {
    target: Option<Target>,
}

impl IsoTpCan {
    /// A new raw-CAN transport with no target set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Segment an application PDU into ISO-TP N_PDUs with `isotpkit`.
    ///
    /// This is the real transmit path a wired CAN link would put on the bus. It is public and
    /// tested so the framing is verified even before an interface exists.
    ///
    /// # Errors
    /// Returns [`Error::Protocol`] when the message exceeds what ISO-TP can carry
    /// (see `isotpkit::segment`).
    pub fn segment(pdu: &[u8]) -> Result<Vec<isotpkit::segment::SegmentPdu>> {
        isotpkit::segment::segment(pdu).map_err(|e| Error::Protocol(format!("isotp segment: {e}")))
    }
}

impl Transport for IsoTpCan {
    fn set_target(&mut self, target: Target) -> Result<()> {
        self.target = Some(target);
        Ok(())
    }

    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        // Prove the transmit framing even though no interface carries it yet.
        let _frames = Self::segment(pdu)?;
        Err(Error::Refused(
            "raw-CAN transport is a planned row: no CAN interface is wired in \
             (use the ELM327-over-TCP transport)"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_pdu_segments_into_one_frame() {
        let frames = IsoTpCan::segment(&[0x22, 0x00, 0x2F]).unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn request_is_refused_until_an_interface_exists() {
        let mut t = IsoTpCan::new();
        t.set_target(Target::new(0x7E0, 0x7E8)).unwrap();
        let err = t.request(&[0x22, 0x00, 0x2F]).unwrap_err();
        assert!(matches!(err, Error::Refused(_)));
    }
}
