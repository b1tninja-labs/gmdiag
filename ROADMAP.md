# gmdiag roadmap

The obligation matrix below is the RUST_OWNED form read by `projecthub sync`:
`Status | Obligation | Anchor | Test`. A row is `[ok]` only when the named test would fail if the
behaviour regressed; a deferred row is `[open]` with Test `none`. Status tokens: `[ok]` done,
`[open]` not implemented, `[unread]` the test passes but an anchor could not be read cleanly.

Tests live beside the code (`src/**` `#[cfg(test)]`) and in `tests/fakeobd_live.rs` (spawns the
`fakeobd` simulator). Protocol anchors are read through `primarysource`, never memory.

## Transport

| Status | Obligation | Anchor | Test |
| --- | --- | --- | --- |
| [ok] | A `Transport` sends a UDS application PDU and returns the reassembled response PDU | ISO 15765-2:2016 §9 (reassembly, done by the adapter) | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | `Elm327Tcp` runs the trial reset-and-format sequence `ATZ ATL0 ATH0 ATS0 ATSP6 ATE0 ATCAF1` | voltkit `INIT`; 2026-11-14 bench trial | `transport::elm327::tests::init_sequence_is_the_trial_order` |
| [ok] | `set_target` sets ATSH/ATCRA/ATFCSH from GMLAN/OBD addressing | udskit::gmlan (`+0x400` / `+0x08`) | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | A single-frame hex reply parses to a PDU | ELM327 line protocol | `transport::elm327::tests::single_frame_reply_parses` |
| [ok] | A CAF multi-frame reply reassembles and trims to the stated length | ELM327 CAF format | `transport::elm327::tests::multi_frame_reply_reassembles_and_trims_to_length` |
| [ok] | Adapter status words (`NO DATA`, `CAN ERROR`, `?`, ...) become adapter errors, not PDUs | ELM327 status replies | `transport::elm327::tests::status_words_become_adapter_errors` |
| [ok] | The transport is neutral: a negative-response PDU passes through unchanged | — | `transport::elm327::tests::negative_response_is_passed_through_as_a_pdu` |
| [ok] | A PDU is hex-encoded with no separators for the wire | ELM327 input | `transport::elm327::tests::hex_compact_has_no_separators` |
| [ok] | The raw-CAN transport frames a PDU with isotpkit | ISO 15765-2:2016 §9.2.1 | `transport::isotp_can::tests::a_short_pdu_segments_into_one_frame` |
| [ok] | The raw-CAN transport refuses `request` until a target is set (no guessing) | — | `transport::isotp_can::tests::request_is_refused_until_a_target_is_set` |
| [ok] | `IsoTpCan` drives a multi-frame request end to end over the `CanLink` seam: segmentation out, flow-control paced, reassembly in | ISO 15765-2:2016 §9.3 | `transport::isotp_can::tests::a_multi_frame_request_round_trips_over_the_can_seam` |
| [ok] | The raw-CAN transport is neutral: a negative-response PDU passes through unchanged | — | `transport::isotp_can::tests::a_negative_response_is_surfaced_not_swallowed` |
| [ok] | A FlowControl OVFLW from the receiver aborts the request, not silently drops it | ISO 15765-2:2016 §9.6.5 | `transport::isotp_can::tests::a_flow_control_overflow_aborts_the_request` |
| [ok] | The SLCAN frame codec round-trips a standard 11-bit CAN frame and ignores non-data lines | LAWICEL SLCAN (serial; not in primarysource) | `transport::isotp_can::tests::slcan_rx_parses_a_standard_frame_and_ignores_acks` |
| [open] | On-vehicle validation of `IsoTpCan` over a real SLCAN dongle / SocketCAN interface | ISO 15765-2:2016 | none |
| [open] | A native SocketCAN (`AF_CAN`) `CanLink` on Linux (needs `unsafe`/`libc`, forbidden crate-wide) | — | none |
| [open] | A J2534 / VCX transport via vcxtoolkit | SAE J2534 (not in primarysource) | none |
| [open] | End-to-end against obd-bridge + a real ELM327/STN adapter | — (needs hardware) | none |

## Session core

| Status | Obligation | Anchor | Test |
| --- | --- | --- | --- |
| [ok] | DiagnosticSessionControl `0x10` enters a session | ISO 14229-1:2013 §9.2 | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | TesterPresent `0x3E` keeps the session alive (zeroSubFunction) | ISO 14229-1:2013 §9.6 | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | The response-pending (`0x78`) loop waits through to the final response | ISO 14229-1:2013 §7.5.1 | `session::tests::response_pending_loop_waits_through_0x78_then_takes_the_positive` |
| [ok] | The response-pending loop gives up past `response_pending_limit` | ISO 14229-1:2013 §7.5.1 | `session::tests::response_pending_loop_gives_up_after_the_limit` |
| [ok] | ReadDataByIdentifier `0x22` reads a DID (single and multi-frame), via udskit::did | udskit::did (ISO 14229-1 §10.2) | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | ReadDTCInformation `0x19` `0x02` parses records and names them via gmdtcdb | udskit::dtc; gmdtcdb | `session::tests::dtc_by_status_decodes_records_and_names` |
| [ok] | A ragged DTC record list is rejected, not silently truncated | ISO 14229-1:2013 §11.3 | `session::tests::dtc_by_status_rejects_a_ragged_record_list` |
| [ok] | The live DTC scan names the simulator's DTCs via gmdtcdb | gmdtcdb | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | Mode $06 `0x06` returns results and labels the OBDMID via mode06kit | mode06kit; GM Mode $06 | `fakeobd_live::reads_the_whole_stack_against_the_simulator` |
| [ok] | SecurityAccess `0x27` builds/reads a requestSeed and derives NO key | udskit::security; ISO 14229-1 §9.4 | `fakeobd_live::security_access_seed_is_refused_and_no_key_is_derived` |
| [ok] | sendKey needs `Arm::Actuate` and an externally supplied key; it is never derived | udskit::security | `session::tests::send_key_requires_actuate_and_never_derives` |
| [ok] | The `Arm` level gates writes: read-only refuses, write/actuate allow, in order | — | `session::tests::arm_ordering_gates_writes` |
| [ok] | A write is refused locally when read-only, and refused by the sim's policy when armed | obd-policy (fakeobd) | `fakeobd_live::writes_are_gated_locally_then_refused_by_the_simulator` |
| [ok] | A time-driven keep-alive clock starts not-due | — | `session::tests::keepalive_starts_not_due` |
| [open] | ReadDTCInformation sub-functions beyond `0x02` (e.g. `0x04` snapshot, `0x06` extended) | ISO 14229-1:2013 §11.3 | none |
| [open] | WriteDataByIdentifier `0x2E` coding accepted end-to-end (needs a writable target) | ISO 14229-1:2013 §10.4 | none |
| [open] | A concurrent keep-alive over a muxing relay (a single ELM link cannot carry one) | — | none |
| [open] | The ADIT ALD RSA-2048 challenge/response is **documented only**, never automated | docs/security-access.md | none |

## CLI and fakeobd-first

| Status | Obligation | Anchor | Test |
| --- | --- | --- | --- |
| [ok] | `scan` reads and names DTCs read-first over the link | — | `fakeobd_live::cli_scan_against_the_simulator_names_dtcs` |
| [ok] | A gated write declined at the confirmation prompt is not sent | — | `fakeobd_live::cli_write_declined_at_confirmation_is_not_sent` |
| [ok] | An unknown command is refused before any link is opened | — | `cli::tests::unknown_command_is_rejected_without_opening_a_link` |
| [ok] | `catalog` is offline reference and never opens a link | — | `cli::tests::catalog_is_offline_and_lists_services` |
| [ok] | `--write` / `--actuate` set the session arm level | — | `cli::tests::parse_sets_arm_from_flags` |
| [ok] | Hex arguments parse (even length, hex digits) | — | `cli::tests::parse_hex_round_trips` |
| [ok] | `--dry-run` spawns fakeobd and drives the whole stack against it | — | `fakeobd_live::cli_dry_run_spawns_fakeobd_when_the_binary_is_on_path_or_env` |
