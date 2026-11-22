# Sources and provenance

gmdiag holds no vehicle data of its own: no DID values, no VIN, no DTC list, no keys. It builds
PDUs from the sibling catalogs and decodes what a link returns. What it *does* carry is the live
machinery — the transport, the session, the CLI — and the one thing that machinery must get right
is where it is allowed to act.

## What comes from where

- **Protocol model** — `udskit` (ISO 14229-1:2013 + GMLAN), `isotpkit` (ISO 15765-2:2016),
  `gmdtcdb` (GM DTC names), `mode06kit` (GM Mode $06). Linked by path; each anchors its own
  claims to a standard through `primarysource`.
- **The ELM327 line layer** — the reset sequence and reply parsing are ported from the read-only
  `voltkit` client (`voltkit/src/elm.rs`, `voltkit/src/scan.rs::INIT`), which proved them against
  the same `fakeobd` simulator. The 2026-11-14 bench trial (recorded under `volt/docs/`, read-only)
  is where the headers and the `ATSP6` protocol choice come from.
- **The addresses and the lab behaviour under test** — the `fakeobd` Volt-lab profile
  (`fakeobd/profiles/volt-lab.profile`), which is explicitly synthetic: "Do not read vehicle facts
  out of this file." gmdiag's integration tests assert that profile's documented answers, nothing
  more.

## The ADIT ALD SecurityAccess path (documented, never automated)

The GMG3 head unit's SecurityAccess (`0x27`) is a front-end over the ADIT Access-Level Daemon:
the server returns a device-bound challenge and the tester must return an RSA-2048 signed block
verified against a per-level public key. The private keys are held by GM/Bosch and are out of
scope. gmdiag builds and reads a `requestSeed`; it derives **no** key. See `docs/security-access.md`
and `udskit`'s `security` module (`CLASSIC_GM_SEED_KEY`, `ADIT_ALD`), which carry the mechanism
descriptors but no key material.

## Scope

Owner-authorised vehicles only; defensive / interoperability research. The whole stack is built
and tested against `fakeobd` with no hardware. Any real use points the same `Elm327Tcp` transport
at `obd-bridge` in front of an adapter, read-first, with every write behind `--write`/`--actuate`
and a confirmation.
