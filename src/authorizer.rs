//! The authorization seam: the **legitimate** route by which a gated operation is unlocked.
//!
//! gmdiag's [`Arm`](crate::session::Arm) level is the operator's *local intent* — read-only until
//! the operator arms a write or an actuation and confirms it. It is a hard gate against sending a
//! write by mistake, but it is not *authorization*: a SecurityAccess `sendKey` carries a key, and
//! a programming step needs an entitlement, and gmdiag holds neither.
//!
//! An [`Authorizer`] is the second gate, *on top of* the Arm level: the external authority that
//! may actually unlock a key-bearing or programming operation. A governed operation proceeds only
//! when **both** gates allow it — the operator armed it *and* an authorizer granted it.
//!
//! The default is [`NoAuthorizer`], which grants nothing. Out of the box gmdiag unlocks nothing on
//! its own authority: it never derives a SecurityAccess key and holds no key material
//! (`docs/security-access.md`). The legitimate way to actually authorize a gated op is
//! [`TechlinekitAuthorizer`], which delegates to the operator's own authenticated techlinekit
//! subscription (ACDelco TDS / Techline Connect) over a **process boundary** — the same spirit as
//! [`crate::spawn`] driving the `fakeobd` binary over a socket, not FFI. techlinekit holds the
//! authenticated session and brokers authorization; gmdiag only asks, and forwards the answer.
//!
//! This keeps gmdiag's boundary intact while giving it a GDS2-equivalent route to authorization
//! from a real subscription, rather than reproducing a secret the manufacturer holds. The key a
//! client returns is, per ISO 14229-1:2013 §9.4.1, one "appropriate for the Seed received"; gmdiag
//! obtains that key from an authenticated source and never computes it.

use std::ffi::{OsStr, OsString};
use std::fmt;

/// What gated operation an [`Authorizer`] is being asked to authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthKind {
    /// A SecurityAccess (`0x27`) unlock: the requestSeed `level` and the `seed`/challenge the
    /// server returned (empty when the caller holds a key but not the live seed).
    ///
    /// A grant for this kind carries the `sendKey` key/response ([`AuthGrant::SecurityKey`]).
    /// ISO 14229-1:2013 §9.4.1: the client returns a key "appropriate for the Seed received";
    /// gmdiag must obtain that key from an authenticated source and never compute it.
    ///
    /// `vin` and `algorithm` are the broker inputs confirmed by the TDS RE: GM's server-side
    /// module-unlock service (`SgmUnlockModuleModel`: `seed`, `seedSize`, `algorithmNumber`, `vin`
    /// → `key`) computes the key from exactly these. They are optional here because the raw
    /// `sendKey` primitive may not have them in hand; the unlock flow that reads the seed also knows
    /// the vehicle's VIN and the module's `algorithmNumber` and fills them in.
    SecurityAccess {
        /// The requestSeed security level (an odd sub-function value).
        level: u8,
        /// The seed/challenge the server returned, when known; otherwise empty.
        seed: Vec<u8>,
        /// The vehicle VIN the broker ties the unlock to, when known.
        vin: Option<String>,
        /// The module's `algorithmNumber` (GM's `algo_id`-indexed seed/key regime), when known.
        algorithm: Option<u8>,
    },
    /// An SPS / programming or actuation step that needs a subscription entitlement: a
    /// RoutineControl start/stop, an InputOutputControl device-control, or a Service Programming
    /// System pass.
    ///
    /// A grant for this kind carries an entitlement token ([`AuthGrant::Entitlement`]).
    Programming {
        /// A short, human description of the step (e.g. `RoutineControl sub-function 01 routine 0203`).
        step: String,
    },
}

/// A request to authorize one gated operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    /// The operation to authorize.
    pub kind: AuthKind,
}

impl AuthRequest {
    /// A SecurityAccess unlock request for `level` with the `seed` the server returned (pass an
    /// empty slice when the live seed is not in hand). The broker inputs (`vin`, `algorithm`) are
    /// left unset; use [`AuthRequest::security_access_brokered`] when they are known.
    #[must_use]
    pub fn security_access(level: u8, seed: &[u8]) -> Self {
        Self {
            kind: AuthKind::SecurityAccess {
                level,
                seed: seed.to_vec(),
                vin: None,
                algorithm: None,
            },
        }
    }

    /// A SecurityAccess unlock request carrying the full broker inputs the GM module-unlock service
    /// needs: the requestSeed `level`, the `seed`, the vehicle `vin` and the module's `algorithm`
    /// (`algorithmNumber`). The grant is the key the server returns for this seed.
    #[must_use]
    pub fn security_access_brokered(
        level: u8,
        seed: &[u8],
        vin: impl Into<String>,
        algorithm: u8,
    ) -> Self {
        Self {
            kind: AuthKind::SecurityAccess {
                level,
                seed: seed.to_vec(),
                vin: Some(vin.into()),
                algorithm: Some(algorithm),
            },
        }
    }

    /// A programming/actuation entitlement request described by `step`.
    #[must_use]
    pub fn programming(step: impl Into<String>) -> Self {
        Self {
            kind: AuthKind::Programming { step: step.into() },
        }
    }

    /// A one-line description for a refusal message or an audit line.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.kind {
            AuthKind::SecurityAccess { level, .. } => {
                format!("SecurityAccess unlock level {level:02X}")
            }
            AuthKind::Programming { step } => format!("programming step ({step})"),
        }
    }
}

/// The material that authorizes proceeding with a gated operation.
///
/// gmdiag holds none of this itself; a grant is produced by an [`Authorizer`] that brokers real
/// authorization (the authenticated techlinekit subscription). The default [`NoAuthorizer`]
/// produces no grant, so a governed operation stays locked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthGrant {
    /// A SecurityAccess key/response to send as `sendKey` for the paired level (ISO 14229-1:2013
    /// §9.4.1). This is the key "appropriate for the Seed received", obtained from an authenticated
    /// source — gmdiag never computes it.
    SecurityKey(Vec<u8>),
    /// An entitlement token proving an SPS/programming or actuation step is authorized.
    Entitlement(Vec<u8>),
}

/// Why an [`Authorizer`] did not grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No authorizer is configured to grant this operation: it stays locked. This is what the
    /// default [`NoAuthorizer`] always returns — gmdiag unlocks nothing on its own authority.
    Unauthorized(String),
    /// The broker (techlinekit) could not be reached or failed to produce a grant.
    Broker(String),
    /// The broker returned a grant that does not fit the request (e.g. an entitlement where a
    /// SecurityAccess key was required).
    Mismatch(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            AuthError::Broker(m) => write!(f, "authorization broker: {m}"),
            AuthError::Mismatch(m) => write!(f, "authorization mismatch: {m}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The seam between a gated operation and the authority that may unlock it.
///
/// An authorizer is consulted *in addition to* the local [`Arm`](crate::session::Arm) gate: the
/// Arm level is the operator's local intent, the authorizer is the external authorization. A
/// governed operation proceeds only when both allow it.
///
/// gmdiag ships [`NoAuthorizer`] by default, which grants nothing, so out of the box no key-bearing
/// or programming operation unlocks. A [`TechlinekitAuthorizer`] delegates to the authenticated
/// techlinekit subscription over a process boundary; gmdiag itself never holds a key or a token.
pub trait Authorizer {
    /// Authorize `request`, returning the material to proceed or an [`AuthError`].
    ///
    /// # Errors
    /// Returns [`AuthError`] when the operation is not authorized (the default), the broker fails,
    /// or the grant does not fit the request.
    fn authorize(&self, request: &AuthRequest) -> Result<AuthGrant, AuthError>;

    /// A short name for diagnostics and audit lines (e.g. `none`, `techlinekit`).
    fn name(&self) -> &'static str;
}

/// The default authorizer: grants nothing, so every governed operation stays locked.
///
/// This preserves gmdiag's no-key-material boundary. Out of the box gmdiag performs no unlock and
/// no programming on its own authority; a real grant requires an authenticated source
/// ([`TechlinekitAuthorizer`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAuthorizer;

impl Authorizer for NoAuthorizer {
    fn authorize(&self, request: &AuthRequest) -> Result<AuthGrant, AuthError> {
        Err(AuthError::Unauthorized(format!(
            "{} stays locked: no authorizer configured (gmdiag holds no key material)",
            request.describe()
        )))
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

/// Environment variable naming the techlinekit entry point (a Python interpreter that will be
/// invoked with `-m techlinekit`, or a wrapper executable). When unset, `python` is used.
pub const TECHLINEKIT_PROGRAM_ENV: &str = "GMDIAG_TECHLINEKIT";

/// Delegates authorization to techlinekit — the operator's authenticated ACDelco TDS / Techline
/// Connect client — over a **process boundary**.
///
/// techlinekit is Python and gmdiag is Rust, so there is no FFI linking: the real call spawns the
/// techlinekit CLI (`python -m techlinekit …`) and reads a grant back from its output, exactly the
/// spirit of [`crate::spawn`] driving the `fakeobd` binary over a socket. gmdiag never holds a
/// SecurityAccess key or a TDS token: techlinekit holds the authenticated subscription session and
/// brokers the authorization; gmdiag asks and forwards the answer to the ECU.
///
/// # Status: STUB
///
/// The process-boundary mechanism and the [`AuthRequest`] / [`AuthGrant`] wire shapes are in place.
/// The actual techlinekit call is a documented **TODO**. The TDS RE (2026-11-21) confirmed the
/// concrete mechanism: GM's SPS2 (`sps2.jar`) carries a server-side module-unlock / seed→key
/// service. The authenticated Techline Connect / TDS session brokers on-vehicle SecurityAccess by
/// POSTing `{seed, vin, algorithmNumber}` (an encrypted `SecureEndpoint` body) to
/// `/sps/module-unlock/enc/{iecs | iecs/key-provisioning | isuzu}` on the TLC gateway under the
/// session's `Authorization: bearer <JWT>`, and the server returns the `key`. So the flow is:
/// gmdiag does its own `27 01` requestSeed on the bus, hands `{seed, vin, algorithmNumber}` to
/// techlinekit, techlinekit returns the key, and gmdiag sends `27 02` — the key is **obtained**
/// from the subscription, never derived.
///
/// Two pieces are not gmdiag's to build and are not done yet, which is why this stays a stub:
/// techlinekit must grow the broker subcommand itself, and it must replicate SPS2's
/// `SecureEndpoint` encryption envelope and the per-module endpoint selection (the exact endpoint
/// for the GMG3 head unit's ADIT ALD challenge is still inference, not proven). Until techlinekit
/// exposes that, [`TechlinekitAuthorizer::authorize`] spawns nothing and returns
/// [`AuthError::Broker`] with a clear stub message. gmdiag's boundary is unchanged in the meantime:
/// with this authorizer a gated op is still refused, just with a "stub" reason rather than
/// "unauthorized".
#[derive(Clone, Debug)]
pub struct TechlinekitAuthorizer {
    program: OsString,
}

impl TechlinekitAuthorizer {
    /// A techlinekit authorizer using the entry point from [`TECHLINEKIT_PROGRAM_ENV`], or
    /// `python` (to be invoked as `-m techlinekit`) when that is unset.
    #[must_use]
    pub fn new() -> Self {
        let program =
            std::env::var_os(TECHLINEKIT_PROGRAM_ENV).unwrap_or_else(|| OsString::from("python"));
        Self { program }
    }

    /// The resolved techlinekit entry point (for diagnostics and for the real subprocess call).
    #[must_use]
    pub fn program(&self) -> &OsStr {
        &self.program
    }
}

impl Default for TechlinekitAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Authorizer for TechlinekitAuthorizer {
    fn authorize(&self, request: &AuthRequest) -> Result<AuthGrant, AuthError> {
        // STUB (see the type documentation). The real call will cross the process boundary, e.g.:
        //
        //   <program> -m techlinekit unlock --vin <vin> --algo <algorithmNumber> --seed <hex>
        //
        // techlinekit POSTs {seed, vin, algorithmNumber} (encrypted SecureEndpoint body) to
        // /sps/module-unlock/enc/* under the authenticated TLC session bearer and prints the key;
        // this reads that AuthGrant::SecurityKey back from stdout and returns it — the spirit of
        // `crate::spawn` driving the `fakeobd` binary. The mechanism is confirmed (TDS RE); what is
        // not yet built, and keeps this a stub, is techlinekit's broker subcommand plus its
        // SecureEndpoint encryption envelope and per-module endpoint selection.
        //
        // TODO(techlinekit-TDS-API): replace this body with the real subprocess call once
        // techlinekit exposes the broker subcommand. gmdiag must still never hold a key or a token —
        // it forwards only what techlinekit returns. `self.program` is the entry point that call
        // will spawn; it is resolved here so the wiring is already in place.
        let via = self.program.to_string_lossy();
        Err(AuthError::Broker(format!(
            "TechlinekitAuthorizer is a stub: {} would be brokered by techlinekit over a process \
             boundary (via {via}), pending the TDS authorization-API investigation",
            request.describe()
        )))
    }

    fn name(&self) -> &'static str {
        "techlinekit"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_authorizer_locks_a_security_access_unlock() {
        let a = NoAuthorizer;
        let req = AuthRequest::security_access(0x01, &[0xAA, 0xBB]);
        match a.authorize(&req) {
            Err(AuthError::Unauthorized(m)) => {
                assert!(m.contains("level 01"), "{m}");
                assert!(m.contains("no key material"), "{m}");
            }
            other => panic!("NoAuthorizer must leave a sendKey locked, got {other:?}"),
        }
    }

    #[test]
    fn no_authorizer_locks_a_programming_step() {
        let a = NoAuthorizer;
        let req = AuthRequest::programming("RoutineControl start 0203");
        assert!(matches!(a.authorize(&req), Err(AuthError::Unauthorized(_))));
    }

    #[test]
    fn no_authorizer_grants_nothing_whatever_the_request() {
        // The whole point: there is no request shape that NoAuthorizer will grant.
        let a = NoAuthorizer;
        for req in [
            AuthRequest::security_access(0x03, &[]),
            AuthRequest::security_access(0x05, &[0x01, 0x02, 0x03, 0x04]),
            AuthRequest::programming("InputOutputControl DID 1234 parameter 03"),
        ] {
            assert!(a.authorize(&req).is_err(), "granted {req:?}");
        }
        assert_eq!(a.name(), "none");
    }

    #[test]
    fn techlinekit_authorizer_is_a_clearly_marked_stub() {
        // The stub mechanism is in place (an entry point is resolved) but it brokers nothing yet:
        // every request returns a Broker error that names the stub, and no subprocess is spawned.
        let a = TechlinekitAuthorizer::new();
        assert_eq!(a.name(), "techlinekit");
        match a.authorize(&AuthRequest::security_access(0x01, &[0xDE, 0xAD])) {
            Err(AuthError::Broker(m)) => {
                assert!(m.contains("stub"), "{m}");
                assert!(m.contains("techlinekit"), "{m}");
            }
            other => panic!("the stub must refuse with a Broker error, got {other:?}"),
        }
    }

    #[test]
    fn techlinekit_authorizer_resolves_its_entry_point() {
        // Default when the override is unset: `python` (invoked as `-m techlinekit`). Only asserts
        // that a non-empty entry point is resolved; it does not mutate process env (which would
        // race other tests).
        let a = TechlinekitAuthorizer::default();
        let prog = a.program().to_string_lossy();
        assert!(!prog.is_empty());
    }

    #[test]
    fn security_access_carries_the_broker_inputs_when_known() {
        // The plain constructor leaves the broker inputs unset (the raw sendKey primitive).
        let AuthKind::SecurityAccess { vin, algorithm, .. } =
            AuthRequest::security_access(0x01, &[0xAA]).kind
        else {
            panic!("expected a SecurityAccess request");
        };
        assert!(vin.is_none() && algorithm.is_none());

        // The brokered constructor carries {seed, vin, algorithmNumber} — exactly GM's
        // SgmUnlockModuleModel inputs confirmed by the TDS RE.
        let AuthKind::SecurityAccess {
            level,
            seed,
            vin,
            algorithm,
        } = AuthRequest::security_access_brokered(0x01, &[0xAA, 0xBB], "1G1FZ6S0XKUF00000", 0x07)
            .kind
        else {
            panic!("expected a SecurityAccess request");
        };
        assert_eq!(level, 0x01);
        assert_eq!(seed, vec![0xAA, 0xBB]);
        assert_eq!(vin.as_deref(), Some("1G1FZ6S0XKUF00000"));
        assert_eq!(algorithm, Some(0x07));
    }

    #[test]
    fn describe_names_the_level_and_the_step() {
        assert_eq!(
            AuthRequest::security_access(0x07, &[]).describe(),
            "SecurityAccess unlock level 07"
        );
        assert_eq!(
            AuthRequest::programming("flash").describe(),
            "programming step (flash)"
        );
    }

    #[test]
    fn auth_error_displays_its_category() {
        assert!(
            AuthError::Unauthorized("x".into())
                .to_string()
                .starts_with("unauthorized")
        );
        assert!(
            AuthError::Broker("x".into())
                .to_string()
                .starts_with("authorization broker")
        );
        assert!(
            AuthError::Mismatch("x".into())
                .to_string()
                .starts_with("authorization mismatch")
        );
    }
}
