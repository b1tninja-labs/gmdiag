//! A [`Transport`] over `vcikit`'s raw-mode VCI backend seam.
//!
//! This is the bridge that lets the session core drive a vehicle communication interface — a
//! native-VCX dongle or a registered SAE J2534 pass-through — through exactly the same
//! [`Transport`] trait that already backs [`Elm327Tcp`](super::elm327::Elm327Tcp). All the device
//! knowledge lives one layer down, in the sibling crate `vcikit` (the transport-agnostic raw-mode
//! abstraction) and its `vcikit-j2534` member (the registered-DLL FFI, with the `unsafe` isolated
//! there): gmdiag itself stays `unsafe`-free and simply hands whole UDS application PDUs to
//! [`vcikit::RawBackend`], which prepends and strips the raw-mode 4-byte CAN-id prefix.
//!
//! # Backend selection
//!
//! [`VciTransport`] is generic over the backend, so the same bridge drives any
//! [`vcikit::RawBackend`]. Two backends exist in the `vcikit` family, consumed identically:
//!
//! - **Native-VCX** — the first-party VCX protocol via `vcxtoolkit`. This is the **preferred**
//!   path, but `vcikit` does not yet expose it as a `RawBackend` (it is being brought up alongside
//!   `vcxtoolkit`'s raw-mode channel). When it lands, a `VciTransport` over that backend drives it
//!   with no change here — hence the generic. Tracked as an `[open]` row in `ROADMAP.md`.
//! - **J2534** — a registered SAE J2534 pass-through DLL, the **fallback**.
//!   [`VciTransport::open_j2534`] opens
//!   whatever pass-through is registered (`vcikit-j2534` discovers it under
//!   `HKLM\SOFTWARE\PassThruSupport.04.04`); off Windows, or with none registered, it reports a
//!   device error rather than guessing.
//!
//! The 4-byte CAN-id convention is ISO 22900-2:2009 §9.2.6.3.6 (owned and tested by `vcikit`); the
//! J2534 API is grounded in `sae:j2534-2002` (owned by `vcikit-j2534`). gmdiag re-derives neither.
//!
//! [`Transport`]: super::Transport

use std::time::Duration;

use vcikit::{CanId, LinkConfig, RawBackend};
use vcikit_j2534::J2534Backend;

use crate::error::{Error, Result};
use crate::transport::{Target, Transport};

/// The default time to wait for one response frame from the backend.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// A [`Transport`] over any `vcikit` [`RawBackend`].
///
/// It maps a [`Target`] onto a [`vcikit::LinkConfig`] (`set_target` → `connect`), sends a UDS
/// application PDU with `request` (`send` then `recv`), and reads a `0x78` response-pending
/// follow-up with `read_more` (another `recv`). It is **neutral**: it forwards whatever PDU it is
/// handed and returns whatever comes back — the read-first policy and the write/actuation gating
/// live in [`Session`](crate::session::Session), exactly as for the other transports.
pub struct VciTransport<B: RawBackend> {
    backend: B,
    timeout: Duration,
}

impl<B: RawBackend> VciTransport<B> {
    /// Wrap a backend, using a default per-response timeout of two seconds.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the per-response read timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The per-response read timeout currently in effect.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl VciTransport<J2534Backend> {
    /// Open the registered SAE J2534 pass-through device as the backend (the fallback link).
    ///
    /// `vcikit-j2534` discovers the pass-through DLL under `HKLM\SOFTWARE\PassThruSupport.04.04`
    /// (and the `WOW6432Node` view), loads it, and drives the J2534-1 ISO 15765 API. The native-VCX
    /// path is preferred; this is the registered-DLL fallback.
    ///
    /// # Errors
    /// Returns [`Error::Adapter`] when no pass-through is registered or it cannot be opened — in
    /// particular off Windows, where discovery is empty and `vcikit` reports no device.
    pub fn open_j2534() -> Result<Self> {
        let backend = J2534Backend::open_registered().map_err(|e| vci_error(&e))?;
        Ok(Self::new(backend))
    }
}

/// Fold a `vcikit` backend error into a gmdiag transport error.
///
/// `vcikit` distinguishes a recv timeout, a missing device, a DLL-load failure and a J2534
/// `PassThru*` status; at this seam they are all "the adapter/interface layer failed", so they
/// become [`Error::Adapter`] with the original detail preserved in the message.
fn vci_error(err: &vcikit::Error) -> Error {
    Error::Adapter(err.to_string())
}

impl<B: RawBackend> Transport for VciTransport<B> {
    fn set_target(&mut self, target: Target) -> Result<()> {
        let config = LinkConfig::iso15765(
            CanId::standard(target.request_id),
            CanId::standard(target.response_id),
        );
        self.backend.connect(&config).map_err(|e| vci_error(&e))
    }

    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        self.backend.send(pdu).map_err(|e| vci_error(&e))?;
        self.backend.recv(self.timeout).map_err(|e| vci_error(&e))
    }

    fn read_more(&mut self) -> Result<Vec<u8>> {
        self.backend.recv(self.timeout).map_err(|e| vci_error(&e))
    }
}

impl<B: RawBackend> Drop for VciTransport<B> {
    fn drop(&mut self) {
        // Best-effort teardown; a close failure on the way out is not actionable.
        let _ = self.backend.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    /// A scripted [`RawBackend`] that records what was sent and replays canned recv frames. No
    /// hardware, no DLL — the J2534 / native device behaviour it stands in for is `vcikit`'s to
    /// test; here we only prove the gmdiag bridge forwards PDUs and runs the loop.
    struct MockBackend {
        connected: bool,
        sent: Vec<Vec<u8>>,
        recvs: std::collections::VecDeque<Vec<u8>>,
    }

    impl MockBackend {
        fn new(recvs: Vec<Vec<u8>>) -> Self {
            Self {
                connected: false,
                sent: Vec::new(),
                recvs: recvs.into(),
            }
        }
    }

    impl RawBackend for MockBackend {
        fn connect(&mut self, _config: &LinkConfig) -> vcikit::Result<()> {
            self.connected = true;
            Ok(())
        }

        fn send(&mut self, app_pdu: &[u8]) -> vcikit::Result<()> {
            self.sent.push(app_pdu.to_vec());
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> vcikit::Result<Vec<u8>> {
            Ok(self
                .recvs
                .pop_front()
                .expect("mock backend ran out of scripted recv frames"))
        }

        fn close(&mut self) -> vcikit::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn set_target_brings_the_backend_up() {
        let mut t = VciTransport::new(MockBackend::new(vec![]));
        t.set_target(Target::obd(0x7E0).unwrap()).unwrap();
        assert!(t.backend.connected, "set_target must connect the backend");
    }

    #[test]
    fn request_sends_the_unframed_pdu_and_returns_the_response() {
        let mut t = VciTransport::new(MockBackend::new(vec![vec![0x62, 0x00, 0x2F, 0x6C]]));
        t.set_target(Target::obd(0x7E0).unwrap()).unwrap();
        let resp = t.request(&[0x22, 0x00, 0x2F]).unwrap();
        assert_eq!(resp, vec![0x62, 0x00, 0x2F, 0x6C]);
        // The backend receives the bare application PDU; the 4-byte CAN-id prefix is vcikit's job.
        assert_eq!(t.backend.sent, vec![vec![0x22, 0x00, 0x2F]]);
    }

    #[test]
    fn a_negative_response_passes_through_unchanged() {
        // Neutral transport: a 0x7F negative is returned as-is for the session to classify.
        let mut t = VciTransport::new(MockBackend::new(vec![vec![0x7F, 0x22, 0x31]]));
        t.set_target(Target::obd(0x7E0).unwrap()).unwrap();
        assert_eq!(
            t.request(&[0x22, 0x00, 0x2F]).unwrap(),
            vec![0x7F, 0x22, 0x31]
        );
    }

    #[test]
    fn read_more_reads_a_follow_up_without_sending() {
        let mut t = VciTransport::new(MockBackend::new(vec![
            vec![0x7F, 0x22, 0x78],
            vec![0x62, 0x00, 0x2F, 0x6C],
        ]));
        t.set_target(Target::obd(0x7E0).unwrap()).unwrap();
        assert_eq!(
            t.request(&[0x22, 0x00, 0x2F]).unwrap(),
            vec![0x7F, 0x22, 0x78]
        );
        assert_eq!(t.read_more().unwrap(), vec![0x62, 0x00, 0x2F, 0x6C]);
        assert_eq!(t.backend.sent.len(), 1, "read_more must not send a request");
    }

    #[test]
    fn the_0x78_loop_runs_through_a_session_over_this_transport() {
        // A pending 0x78 then the positive 0x50 session response: the session's response-pending
        // loop drives request + read_more over this transport and takes the final positive.
        let t = VciTransport::new(MockBackend::new(vec![
            vec![0x7F, 0x10, 0x78],
            vec![0x50, 0x01, 0x00, 0x32, 0x01, 0xF4],
        ]));
        let mut s = Session::new(t, Target::obd(0x7E0).unwrap()).unwrap();
        let p = s.enter_session(0x01).unwrap();
        assert_eq!(p.response_sid, 0x50);
    }
}
