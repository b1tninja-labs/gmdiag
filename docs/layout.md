# Crate layout

A single binary+library crate: `Cargo.toml`, `src/`, `tests/`.

- `src/lib.rs` — module declarations and the crate-level overview; re-exports `Error`/`Result`.
- `src/error.rs` — the one error type (transport vs protocol vs refusal vs model).
- `src/transport.rs` — the `Transport` trait and `Target`, plus the `elm327` and `isotp_can`
  submodules under `src/transport/`.
  - `src/transport/elm327.rs` — `Elm327Tcp`, the primary transport (AT lines + hex PDUs over TCP;
    the adapter runs ISO-TP). Line and reply parsing ported from voltkit's proven `elm` module.
  - `src/transport/isotp_can.rs` — `IsoTpCan`, the planned raw-CAN transport over `isotpkit`.
- `src/session.rs` — `Session<T: Transport>`: session control, keep-alive, the `0x78` loop, and
  the UDS services, each write/actuation gated by an `Arm` level.
- `src/spawn.rs` — spawns the `fakeobd` binary for the dry-run and the tests (does not link it).
- `src/vcx.rs` — an offline `Transport` adapter over `vcxtoolkit`'s recovered VCX frame codecs
  (`collect::frame_identity_request` / `reply_application_bytes`): builds a GMLAN `$1A` read with
  `udskit`, exchanges it over an injected `ByteSource` seam, parses the reply with `udskit`, and
  assembles the identities into a `vcxtoolkit::modread` saved read. Ships only an in-process
  `FakeByteSource`; the hardware seam is out of scope and stays gated.
- `src/cli.rs` — the read-first command line; `run(argv, confirm) -> (code, text)`.
- `src/main.rs` — the entry point; a terminal `y/N` confirmation callback.

Conventions:

- Integration tests (`tests/fakeobd_live.rs`) use only the public API and spawn `fakeobd`. Unit
  tests sit beside the code in `#[cfg(test)]` modules.
- Lints are configured in the manifest (`[lints]`), not with scattered `#![...]` attributes.
  `doc_markdown` is allowed in the manifest (protocol prose), like the sibling crates.
- Protocol claims are anchored in `docs/iso-map.md`, read through `primarysource`, never memory.
