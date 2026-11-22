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
//! - [`authorizer`] — the second gate. An [`Authorizer`](authorizer::Authorizer) is the external
//!   authorization consulted *on top of* the Arm level before an actuation-tier op unlocks. The
//!   default [`NoAuthorizer`](authorizer::NoAuthorizer) grants nothing;
//!   [`TechlinekitAuthorizer`](authorizer::TechlinekitAuthorizer) delegates to the authenticated
//!   techlinekit subscription over a process boundary.
//! - [`spawn`] — spawns `fakeobd` for the fakeobd-first dry-run and the tests.
//! - [`cli`] — the read-first command line.
//!
//! # Boundaries
//!
//! gmdiag derives **no** SecurityAccess key and holds **no** key material: it builds and reads a
//! `requestSeed`, but a `sendKey` carries only a key supplied from outside and proceeds only when
//! an [`Authorizer`](authorizer::Authorizer) grants. With the default
//! [`NoAuthorizer`](authorizer::NoAuthorizer) nothing that needs real authorization unlocks on its
//! own; the legitimate route is the operator's authenticated techlinekit subscription, invoked
//! over a process boundary, never key-cracking. gmdiag opens no bus beyond the ELM line protocol
//! (raw CAN and J2534/VCX are planned). It acts only on an owner-authorised vehicle, and its whole
//! stack runs against a spawned `fakeobd` simulator with no hardware.

pub mod authorizer;
pub mod cli;
pub mod error;
pub mod session;
pub mod spawn;
pub mod transport;

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
