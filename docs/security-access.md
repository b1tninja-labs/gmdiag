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
