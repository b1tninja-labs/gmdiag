# gmdiag — plan

`gmdiag` is the **live, read/WRITE GM diagnostic driver**: the Techline / GDS2 side of the
end-to-end stack, beside `voltkit` (the read-only owner dashboard, the "voltage clone").
It does what voltkit deliberately will not: DiagnosticSessionControl, SecurityAccess (seed
only, no key), RoutineControl, InputOutputControl / device control, coding
(WriteDataByIdentifier), structured ReadDTCInformation + Clear, and keep-alive sessions.

It is a thin **driver** over the knowledge-and-model siblings, which already carry the
protocol: it links `udskit` (UDS/ISO 14229-1 + GMLAN catalogs and PDU codec), `gmdtcdb`
(841-code GM DTC names), `mode06kit` (Mode $06 labels) and `isotpkit` (ISO-TP codec, for the
later raw-CAN transport). gmdiag adds the one thing those libraries refuse to do: open a link
and exchange bytes with a vehicle — and it does so read-first, with every write gated.

Authorised interoperability / defensive research on hardware the owner holds.

## Boundaries (what gmdiag will NOT do)

- **No SecurityAccess key derivation.** gmdiag builds the `requestSeed` PDU with
  `udskit::security::build_request_seed` and can read the seed back, but it derives no key.
  udskit's boundary holds: gated routines / writes stay locked unless a key is supplied
  externally (`--key <hex>`). The ADIT ALD RSA-2048 path is documented, never automated.
- **No bus-opening in the library core beyond the ELM line protocol.** The ELM327 adapter
  runs ISO-TP; gmdiag speaks AT lines + hex PDUs to it. Raw CAN (`IsoTpCan` over `isotpkit`)
  and J2534 / VCX (`vcxtoolkit`) are planned rows, the latter blocked on SAE J2534 not being
  in `primarysource`.
- **No write or actuation without an explicit flag and a typed confirmation.** Read-first by
  default. `--write` / `--actuate` arm the write services; each still prompts before it sends.
- **Owner-authorised vehicle only.** A dry-run / replay mode runs the whole stack against a
  spawned `fakeobd` with no hardware.

## Architecture

### The one seam: `Transport`

```rust
pub trait Transport {
    fn set_target(&mut self, addr: Target) -> Result<()>;      // from udskit::gmlan addressing
    fn request(&mut self, pdu: &[u8]) -> Result<Vec<u8>>;      // send a UDS application PDU,
                                                               // return the reassembled response PDU
}
```

`Target` carries the request arbitration id (and the derived response / flow-control ids via
`udskit::gmlan::{response_id, filter_id, obd_response_id}`).

Impls:

- **`Elm327Tcp` (PRIMARY, built first).** Speaks ELM327 AT lines over TCP; the adapter does
  ISO-TP. The reset-and-format sequence is the one the 2026-11-14 trial used and voltkit
  proved: `ATZ ATL0 ATH0 ATS0 ATSP6 ATE0 ATCAF1`. `set_target` emits `ATSH<req>`,
  `ATCRA<resp>` and `ATFCSH<req>`. `request` writes the PDU as spaceless hex, reads to the
  `>` prompt, and parses the ELM reply (single frame, or the `nnn` / `i:` CAF multi-frame
  form) back into a PDU. The line + reply parsing is ported from voltkit's proven `elm`
  module — but gmdiag's transport is **neutral**: it does not refuse write SIDs. Gating lives
  one layer up, in the session / CLI.
- **`IsoTpCan` (LATER, planned row).** Raw CAN + `isotpkit` framing. A compiled stub that
  constructs `isotpkit` PCI/segment types but whose `request` returns "raw-CAN transport not
  yet wired" — honest `[open]` row, no hardware here.
- **`Replay` (test / dry-run).** Not strictly a `Transport`; the dry-run path runs `Elm327Tcp`
  against a spawned `fakeobd`.

### Session core (`session.rs`)

A `Session<T: Transport>` over the knowledge siblings:

- **DiagnosticSessionControl `0x10`** — enter a session; starts a **TesterPresent `0x3E`**
  keep-alive timer (a background thread that sends `3E 80` on an interval; stopped on drop).
- **ReadDataByIdentifier `0x22`** — resolve DIDs via `udskit::did` (`read_dids`,
  `parse_read_response`, `classify`).
- **ReadDTCInformation `0x19`** + **ClearDiagnosticInformation `0x14`** — structured, with
  status-byte decode via `udskit::dtc::decode_status` and DTC names via `gmdtcdb`.
- **RoutineControl `0x31`** (`udskit::routine::build_request` + catalog, risk flags),
  **InputOutputControl `0x2F`** / GM device control (`udskit::iocontrol::build_request`),
  **WriteDataByIdentifier `0x2E`** — all behind `--write` / `--actuate` + confirmation.
- **Mode $06 `0x06`** — labelled via `mode06kit`.
- **SecurityAccess `0x27`** — `udskit::security::build_request_seed`; read the seed, derive
  **no** key. A supplied `--key` is sent as `sendKey`; none is derived.

Every response is decoded with `udskit::message::decode_response`:
positive / negative, with a **`0x78` response-pending retry loop** (bounded).

### CLI (`cli.rs` + `main.rs`), read-first

`run(args) -> (exit_code, text)` so it is testable without spawning a process.
Subcommands (read, default): `scan` (DTCs, named), `did <id>` / `live`, `mode06`, `session`,
`seed <level>` (requestSeed only). Write subcommands (`write`, `routine`, `iocontrol`,
`clear`) require `--write` / `--actuate` and prompt. `--target <addr>` chooses the TCP peer;
`--dry-run` spawns `fakeobd`. `--request-id <hex>` sets the arbitration id.

## Dependencies (path, portfolio siblings)

`udskit`, `isotpkit`, `gmdtcdb`, `mode06kit` via `{ path = "../<name>" }` — the established
workspace pattern (`fakeprint-python` → `../fakeprint/...`). gmdiag stays `publish = false`.
Not depended on: `fakeobd` / `obd-bridge` (spawned as binaries for the dry-run, like voltkit
`lab`), `voltkit`, `vcxtoolkit`.

## fakeobd-first

The first transport target is `fakeobd serve` (the Rust ELM327 + ISO-TP simulator). The whole
stack is built and tested against a spawned `fakeobd` with **no hardware**; CI starts fakeobd
and runs gmdiag against it. The same `Elm327Tcp` later points at `obd-bridge` + a real
adapter. fakeobd's default policy refuses `$27` and every write, so the gated paths decode a
real negative response against the sim.

## Deliverables

- Buildable crate: `Transport` + `Elm327Tcp`, session core, read-first CLI (writes gated),
  tests against a spawned fakeobd.
- `ROADMAP.md` as the RUST_OWNED `Status | Obligation | Anchor | Test` matrix.
- `docs/` — iso-map (clause anchors via `primarysource` `iso_*`), sources, security-access.
- All five Rust gates green via `projecthub shells verify --rust`.

## Process

AGENTS.md: commit in the gmdiag repo only (`git rev-parse --show-toplevel`), never `-A`, no
AI attribution / no `Co-Authored-By`. Protocol wording via `primarysource`, never memory. Do
not create a GitHub remote / push (owner coordinates). Do not edit projecthub registration
(register-vehicle-tools session). Scratch stays outside the tree.
