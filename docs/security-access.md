# SecurityAccess — the boundary that holds

gmdiag can **ask** for a seed and can **send** a key it is given. It cannot compute a key. That
line is deliberate and it is enforced in the type system, not just in prose.

## What gmdiag does

- `Session::security_request_seed(level)` builds the `requestSeed` PDU with
  `udskit::security::build_request_seed` (which only accepts a requestSeed level) and returns the
  server's seed bytes. This is a **read**; it needs no arming.
- `Session::security_send_key(level, key)` sends an **externally supplied** `key` as `sendKey`. It
  needs `Arm::Actuate` and a confirmation. gmdiag never derives `key` from the seed.

Against the `fakeobd` simulator, SecurityAccess is refused under every configuration (NRC `0x33`
securityAccessDenied), so a gated routine or write stays locked. That is the expected shape: an
owner-authorised unlock needs a key from outside this tool.

## The two mechanisms (reference only, from `udskit::security::MECHANISMS`)

- **Classic GM seed/key** (`classic-gm-seed-key`): the module returns a short seed and the tester
  returns a key computed by a per-module secret algorithm held by GM. The algorithm and keys are
  not in scope.
- **ADIT ALD** (`adit-ald`, the GMG3 head unit): `0x27` is a front-end over the ADIT Access-Level
  Daemon. The server returns a 96-byte device-bound challenge (a 16-byte `rand()` nonce, an 8-byte
  timestamp, an 8-byte i.MX6 serial, a 16-byte caller `ECU_ID`); the tester returns an RSA-2048
  signed block, which the daemon verifies against the per-level public key and compares against the
  live challenge. A bad key is NRC `0x35` invalidKey. The per-level private keys are held by
  GM/Bosch and are out of scope.

## Why this is documented and not automated

Deriving a key would mean reproducing a secret the manufacturer holds — outside the scope of
authorised interoperability research, and outside what `udskit` will model. gmdiag records the
mechanism so an owner who already holds a key can use it, and goes no further. The RSA path is
described here; it is not implemented anywhere in the crate.

## The authorization seam (how a gated op is legitimately unlocked)

gmdiag will not derive a key, but it needs a *legitimate* way to actually authorize a gated op —
otherwise the only route past a lock would be key-cracking, which is out of scope. That route is the
`Authorizer` seam (`src/authorizer.rs`), a second gate on top of the `Arm` level:

- `NoAuthorizer` is the default and grants nothing, so out of the box gmdiag unlocks nothing on its
  own authority and holds no key material. `sendKey`, routine start/stop and device control stay
  locked; coding/clearing stay on the `Arm` gate alone (they carry no key material).
- `TechlinekitAuthorizer` delegates to the operator's **authenticated** techlinekit subscription
  (ACDelco TDS / Techline Connect) over a **process boundary** — techlinekit is Python and gmdiag is
  Rust, so there is no FFI, the same spirit as spawning `fakeobd`. techlinekit holds the subscription
  session and brokers the authorization; gmdiag only asks, and forwards the answer to the ECU. It is
  a clearly-marked **stub** today.

### The confirmed broker mechanism (TDS RE, 2026-11-21)

The authenticated Techline Connect / TDS session **does** broker on-vehicle SecurityAccess, through
GM's own SPS2 programmer (`sps2.jar`), which carries a server-side module-unlock / seed→key service:

1. gmdiag does its own `27 01` requestSeed on the bus and reads the `seed`.
2. It hands `{seed, vin, algorithmNumber}` to techlinekit (the `SgmUnlockModuleModel` inputs —
   `AuthKind::SecurityAccess` now carries `vin` and `algorithm` for exactly this).
3. techlinekit POSTs that as an encrypted `SecureEndpoint` body to
   `/sps/module-unlock/enc/{iecs | iecs/key-provisioning | isuzu}` on the TLC gateway under its
   session `Authorization: bearer <JWT>`, and GM's server returns the `key`.
4. gmdiag sends `27 02` sendKey with that key.

The GM/Bosch private key material stays server-side; the key is **obtained** from the owner's own
authenticated subscription, never derived or cracked — the GDS2/SPS2 flow itself. This is why the
`AuthGrant` for a SecurityAccess request is `AuthGrant::SecurityKey(key)`.

Two pieces are **not gmdiag's to build** and keep `TechlinekitAuthorizer` a stub: techlinekit must
grow the broker subcommand, and it must replicate SPS2's `SecureEndpoint` encryption envelope and
the per-module endpoint selection (the exact endpoint serving the GMG3 head unit's ADIT ALD
challenge is still inference, not proven from disk). gmdiag's side — the seam, the request/grant
shapes, and the `27 01` → broker → `27 02` flow — is ready for that call.

This gives gmdiag a GDS2-equivalent route to authorization from a real subscription, while the key a
client returns is still, per ISO 14229-1:2013 §9.4.1, one "appropriate for the Seed received" — one
gmdiag *obtains* from an authenticated source, never computes. The ADIT ALD RSA path above remains
documented-only and is never automated inside gmdiag; the legitimate unlock is the brokered service,
not a local signature.
