//! The vendor-DLL read transport as a gmdiag [`ByteSource`].
//!
//! [`J2534ByteSource`] drives a registered/located J2534 pass-through DLL (VXDIAG
//! `VCXPT32.dll`) through `vcikit-j2534`, presenting the exact same [`ByteSource`] seam
//! the native [`VcxByteSource`](crate::vcx_device::VcxByteSource) does. So gmdiag's one
//! read loop runs over either transport and produces the identical saved-read — only the
//! carrier of the bytes differs. Windows-only (it loads a Windows DLL).

use std::path::Path;
use std::time::Duration;

use vcikit::backend::RawBackend;
use vcikit::link::{CanId, LinkConfig};
use vcikit_j2534::J2534Backend;

use crate::error::{Error, Result};
use crate::vcx::ByteSource;

/// A [`ByteSource`] backed by a vendor J2534 pass-through DLL.
pub struct J2534ByteSource {
    backend: J2534Backend,
    config: LinkConfig,
    /// The responder CAN id restored on each reply (vcikit strips it; gmdiag's
    /// `split_rx_id` expects it back as saved-read metadata).
    resp_id: u16,
    timeout: Duration,
    connected: bool,
}

impl J2534ByteSource {
    /// Load the pass-through DLL at `path` and prepare an ISO 15765 link for the given
    /// request/response CAN ids. The channel is brought up on the first exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the DLL cannot be loaded (including a 32/64-bit
    /// mismatch, reported clearly by `vcikit-j2534`).
    pub fn open(path: &Path, req_id: u16, resp_id: u16, timeout: Duration) -> Result<Self> {
        let backend = J2534Backend::open_library(path).map_err(map_err)?;
        Ok(Self {
            backend,
            config: LinkConfig::iso15765(CanId::standard(req_id), CanId::standard(resp_id)),
            resp_id,
            timeout,
            connected: false,
        })
    }

    /// The path of the loaded vendor DLL.
    #[must_use]
    pub fn library_path(&self) -> &str {
        self.backend.library_path()
    }
}

/// Map a `vcikit` transport error into the crate error (a link failure is [`Error::Io`]).
/// Taken by value so it can be used directly as a `Result::map_err` callback.
#[allow(clippy::needless_pass_by_value)]
fn map_err(error: vcikit::error::Error) -> Error {
    Error::Io(std::io::Error::other(format!("j2534: {error}")))
}

impl ByteSource for J2534ByteSource {
    fn exchange(&mut self, framed_request: &[u8]) -> Result<Vec<u8>> {
        // Bring the ISO 15765 link up once (PassThruOpen/Connect/StartMsgFilter).
        if !self.connected {
            self.backend.connect(&self.config).map_err(map_err)?;
            self.connected = true;
        }

        // The framed request is the VCX Send PDU: [flags u32 BE][len u16 BE][req-id 4 BE]
        // [uds]. vcikit takes the application PDU (the uds) and adds its own CAN-id prefix.
        let uds = framed_request.get(10..).unwrap_or(&[]);
        self.backend.send(uds).map_err(map_err)?;
        let app = self.backend.recv(self.timeout).map_err(map_err)?;

        // Rebuild the VCX_PRO_Recv envelope gmdiag's reply parser consumes: flags u32 LE,
        // len u16 LE, then [resp-id 4 BE][app]. vcikit stripped the responder id, so the
        // configured resp id is restored for split_rx_id.
        let mut data = u32::from(self.resp_id).to_be_bytes().to_vec();
        data.extend_from_slice(&app);
        let mut envelope = 0_u32.to_le_bytes().to_vec();
        envelope.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_le_bytes());
        envelope.extend_from_slice(&data);
        Ok(envelope)
    }
}
