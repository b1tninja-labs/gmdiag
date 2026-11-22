# ISO / standard clause map

gmdiag is a *driver*: the protocol definitions live in the sibling libraries it links
(`udskit`, `isotpkit`, `gmdtcdb`, `mode06kit`), each of which anchors its own claims to a
standard read through `primarysource`. This file records only the clauses that gmdiag itself
depends on — the behaviour it adds on top of those libraries: opening a session, keeping it
alive, and the response-pending loop. Every citation here was read through the `primarysource`
`iso_*` tools, not quoted from memory (workspace `AGENTS.md`).

| gmdiag behaviour | Anchor | Note |
| --- | --- | --- |
| DiagnosticSessionControl `0x10` — enter a session | ISO 14229-1:2013 §9.2 | `Session::enter_session`. Table 23 (§9.2.1) lists `0x10` as allowed in default and non-default sessions. |
| TesterPresent `0x3E` — keep the session alive | ISO 14229-1:2013 §9.6 | `Session::tester_present`. Sub-function `zeroSubFunction` (`0x00`); the positive response is requested, not suppressed (see the note in the method). |
| Response-pending `0x78` loop | ISO 14229-1:2013 §7.5.1 | `Session::exchange`. The server answers `0x78` (requestCorrectlyReceived-ResponsePending) and the final response arrives as a later message; gmdiag waits through it via `Transport::read_more`, bounded by `response_pending_limit`. |
| ISO-TP single-frame transmit (raw-CAN path) | ISO 15765-2:2016 §9.2.1 | The planned `IsoTpCan` transport frames with `isotpkit`; the ELM327 transport leaves ISO-TP to the adapter. |

## Where the rest is anchored (not duplicated here)

- The service and NRC catalogs, the request/response codec, the `0x22`/`0x19`/`0x14`/`0x27`/
  `0x31`/`0x2F`/`0x2E` request builders and the GMLAN `+0x400` / OBD `+0x08` addressing are
  `udskit`'s, anchored in `udskit/docs/iso-map.md`.
- ISO-TP (ISO 15765-2:2016) segmentation, flow control and timing are `isotpkit`'s, anchored in
  `isotpkit/docs/iso-map.md`.
- The 841 DTC names are `gmdtcdb`'s; the Mode $06 labels are `mode06kit`'s (GM's own published
  documents, via the `gm_*` tools).

## The ELM327 line protocol and `ATSP6`

The ELM327 carriage-return line protocol and its AT commands are not an ISO standard and are not
in `primarysource`; the reset-and-format sequence (`src/transport/elm327.rs::INIT`) and the
reply parsing are taken from the proven `voltkit` client and the 2026-11-14 bench trial, and
validated against the `fakeobd` simulator. `ATSP6` selects ELM protocol 6 — **ISO 15765-4** CAN,
11-bit id, 500 kbaud (the application profile), which is distinct from **ISO 15765-2**, the
transport layer. No ELM327 or STN datasheet is quoted.
