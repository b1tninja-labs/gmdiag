//! `gmdiag`: the live, read/**write** GM diagnostic driver — the Techline / GDS2 side of the
//! end-to-end stack, beside the read-only owner dashboard `voltkit`.
//!
//! gmdiag is the one component that opens a link and exchanges bytes with a vehicle. The protocol
//! knowledge lives in the sibling libraries it drives — `udskit` (UDS / ISO 14229-1 and GMLAN
//! catalogs and the PDU codec), `gmdtcdb` (the 841-code GM DTC names), `mode06kit` (Mode $06
//! labels) and `isotpkit` (ISO-TP, for the planned raw-CAN link). Those libraries refuse, by
//! design, to touch a bus; gmdiag adds exactly that, and does it **read-first, with every write
//! and actuation behind an explicit flag and a confirmation**.
//!
//! # Shape
//!
//! - [`transport`] — the one seam. A [`Transport`](transport::Transport) sends a UDS application
//!   PDU and returns the reassembled response. [`Elm327Tcp`](transport::elm327::Elm327Tcp) is the
//!   primary impl (an ELM327 adapter that runs ISO-TP); [`IsoTpCan`](transport::isotp_can::IsoTpCan)
//!   is the planned raw-CAN impl over `isotpkit`.
//! - [`session`] — a [`Session`](session::Session) over a transport: session control,
//!   TesterPresent keep-alive, the `0x78` response-pending loop, and the UDS services, each
//!   write/actuation gated by an [`Arm`](session::Arm) level.
//! - [`spawn`] — spawns `fakeobd` for the fakeobd-first dry-run and the tests.
//! - [`vcx`] — an offline [`Transport`](transport::Transport) adapter that carries GMLAN `$1A`
//!   identity reads over `vcxtoolkit`'s recovered frame codecs and assembles them into a
//!   `vcxtoolkit::modread` saved read. Driven only by an in-process fake; the hardware byte
//!   seam is out of scope and stays gated (`vcxtoolkit::collect::vehicle_read_gate`).
//! - [`cli`] — the read-first command line.
//!
//! # Boundaries
//!
//! gmdiag derives **no** SecurityAccess key: it builds and reads a `requestSeed`, but a `sendKey`
//! carries only a key the operator supplies. It opens no bus beyond the ELM line protocol (raw
//! CAN and J2534/VCX are planned). It acts only on an owner-authorised vehicle, and its whole
//! stack runs against a spawned `fakeobd` simulator with no hardware.

pub mod cli;
pub mod error;
pub mod session;
pub mod spawn;
pub mod transport;
pub mod vcx;

pub use error::{Error, Result};

/// The name of this crate, as Cargo knows it.
#[must_use]
pub const fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    #[test]
    fn name_is_the_package_name() {
        assert_eq!(super::name(), "gmdiag");
    }
}
