# gmdiag

The live, read/**write** GM diagnostic driver — the Techline / GDS2 side of the end-to-end stack,
beside the read-only owner dashboard [`voltkit`](../voltkit). gmdiag does what voltkit deliberately
will not: DiagnosticSessionControl, SecurityAccess, RoutineControl, device control, coding, and
structured DTC read/clear — **read-first, with every write and actuation behind an explicit flag
and a confirmation**.

gmdiag opens the link; the protocol knowledge lives in the siblings it drives —
[`udskit`](../udskit) (UDS / ISO 14229-1 + GMLAN, the PDU codec), [`gmdtcdb`](../gmdtcdb) (841 GM
DTC names), [`mode06kit`](../mode06kit) (Mode $06 labels) and [`isotpkit`](../isotpkit) (ISO-TP,
for the planned raw-CAN link). Those libraries refuse to touch a bus; gmdiag adds exactly that.

## fakeobd-first

The whole stack is built and tested against the [`fakeobd`](../fakeobd) ELM327+ISO-TP simulator
with **no hardware**:

```text
gmdiag --dry-run scan                 # spawn fakeobd and read its DTCs, named via gmdtcdb
gmdiag --target 127.0.0.1:35000 did 002F
```

The same `Elm327Tcp` transport later points at `obd-bridge` in front of a real adapter.

## Commands

```text
# reads (no flag)
gmdiag scan [mask]           ReadDTCInformation 0x19 02, named via gmdtcdb
gmdiag did <hex>             ReadDataByIdentifier 0x22
gmdiag seed <level>          SecurityAccess requestSeed (reads the seed; derives NO key)
gmdiag mode06 <obdmid>       Mode $06 monitor results, labelled via mode06kit
gmdiag session [type]        DiagnosticSessionControl 0x10 + TesterPresent 0x3E
gmdiag catalog <what>        offline reference (services|routines|security|dids), no link

# gated: need the flag AND a confirmation
gmdiag --write   write <did> <hex>                WriteDataByIdentifier 0x2E
gmdiag --write   clear [group]                     ClearDiagnosticInformation 0x14
gmdiag --actuate routine start|stop|results <rid>  RoutineControl 0x31
gmdiag --actuate iocontrol <did> <param> [hex]     InputOutputControl 0x2F
gmdiag --actuate sendkey <level> <key>             SecurityAccess sendKey (key supplied)
```

Options: `--target <addr>` (default `127.0.0.1:35000`), `--dry-run`, `--request-id <hex>`
(default `7E0`), `--gmlan` / `--obd` addressing, `--allow-non-loopback`.

## Boundaries

- **No SecurityAccess key derivation.** gmdiag builds and reads a `requestSeed`; a `sendKey`
  carries only a key the operator supplies. The ADIT ALD RSA path is documented
  ([`docs/security-access.md`](docs/security-access.md)), never automated.
- **No bus beyond the ELM line protocol.** Raw CAN (`isotpkit`) and J2534/VCX are planned rows.
- **Owner-authorised vehicles only.** Defensive / interoperability research.

## Develop

```text
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                 # set GMDIAG_FAKEOBD to the fakeobd binary to exercise --dry-run
cargo doc --no-deps
```

The integration tests build and spawn `fakeobd`; they find its binary via `GMDIAG_FAKEOBD` or the
sibling build at `../fakeobd/target/{debug,release}/fakeobd`, and skip (green) if neither exists.
Minimum supported Rust version: 1.85 (edition 2024). The obligation matrix is
[`ROADMAP.md`](ROADMAP.md); the clause anchors are [`docs/iso-map.md`](docs/iso-map.md).
`publish = false`.
