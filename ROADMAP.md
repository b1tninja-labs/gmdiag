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
| [ok] | The planned raw-CAN transport frames a PDU with isotpkit | ISO 15765-2:2016 §9.2.1 | `transport::isotp_can::tests::a_short_pdu_segments_into_one_frame` |
| [ok] | The raw-CAN transport refuses `request` until a CAN interface exists (no guessing) | — | `transport::isotp_can::tests::request_is_refused_until_an_interface_exists` |
| [open] | A live raw-CAN (`IsoTpCan`) link over SocketCAN / a real interface | ISO 15765-2:2016 | none |
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
| [ok] | sendKey needs `Arm::Actuate` AND an `Authorizer` grant; the key is externally supplied, never derived | udskit::security; ISO 14229-1:2013 §9.4.1 | `session::tests::send_key_needs_actuate_then_authorization_and_never_derives` |
| [ok] | The `Arm` level gates writes: read-only refuses, write/actuate allow, in order | — | `session::tests::arm_ordering_gates_writes` |
| [ok] | A write is refused locally when read-only, and refused by the sim's policy when armed | obd-policy (fakeobd) | `fakeobd_live::writes_are_gated_locally_then_refused_by_the_simulator` |
| [ok] | A time-driven keep-alive clock starts not-due | — | `session::tests::keepalive_starts_not_due` |
| [open] | ReadDTCInformation sub-functions beyond `0x02` (e.g. `0x04` snapshot, `0x06` extended) | ISO 14229-1:2013 §11.3 | none |
| [open] | WriteDataByIdentifier `0x2E` coding accepted end-to-end (needs a writable target) | ISO 14229-1:2013 §10.4 | none |
| [open] | A concurrent keep-alive over a muxing relay (a single ELM link cannot carry one) | — | none |
| [open] | The ADIT ALD RSA-2048 challenge/response is **documented only**, never automated | docs/security-access.md | none |

## Authorization

The actuation-tier services check a second gate on top of the `Arm` level: an `Authorizer`
(`src/authorizer.rs`). The `Arm` level is the operator's *local intent*; the authorizer is the
*external authorization* that may actually unlock a key-bearing or programming op. The write-gating
decision: coding and clearing (`0x2E`/`0x14`) carry **no** key material, so they stay on the `Arm`
gate alone (an armed, confirmed write reaches the bus — the fakeobd write test pins that); `sendKey`
(`0x27`), routine start/stop (`0x31`) and device control (`0x2F`) additionally require an
`AuthGrant`. With the default `NoAuthorizer` nothing that needs real authorization unlocks on its
own, and gmdiag holds no key material. The legitimate route is `TechlinekitAuthorizer`, which
delegates to the operator's authenticated Techline Connect / TDS subscription over a **process
boundary** (techlinekit is Python; gmdiag is Rust, so no FFI) — not key-cracking.

The TDS RE (2026-11-21) confirmed the broker mechanism: GM's SPS2 (`sps2.jar`) exposes a
server-side seed→key service. The authenticated session POSTs `{seed, vin, algorithmNumber}` (an
encrypted `SecureEndpoint` body) to `/sps/module-unlock/enc/{iecs|iecs/key-provisioning|isuzu}`
under its `bearer` JWT and the server returns the `key`. gmdiag's `AuthKind::SecurityAccess` now
carries those broker inputs (`vin`, `algorithm`). It stays `[open]`: techlinekit must still grow the
broker subcommand and replicate SPS2's encryption envelope and per-module endpoint selection.

| Status | Obligation | Anchor | Test |
| --- | --- | --- | --- |
| [ok] | The `Authorizer` seam governs actuation on top of `Arm`; the default `NoAuthorizer` grants nothing, so no request shape unlocks and gmdiag holds no key material | ISO 14229-1:2013 §9.4.1 (the key is "appropriate for the Seed received" — obtained, not derived) | `authorizer::tests::no_authorizer_grants_nothing_whatever_the_request` |
| [ok] | sendKey needs `Arm::Actuate` AND an `AuthGrant`; with `NoAuthorizer` it is refused before any byte, and the key is never derived | ISO 14229-1:2013 §9.4.1 | `session::tests::send_key_needs_actuate_then_authorization_and_never_derives` |
| [ok] | Routine start/stop and device control each need `Arm::Actuate` AND an `AuthGrant`; results (`0x03`) stays a read | ISO 14229-1:2013 §9 (RoutineControl / InputOutputControl, via udskit) | `session::tests::routine_start_needs_actuate_and_authorization_but_results_is_a_read`; `session::tests::io_control_needs_actuate_and_authorization` |
| [ok] | Coding/clearing carry no key material and stay on the `Arm` gate alone (an armed write reaches the bus) | — | `session::tests::coding_and_clearing_stay_on_the_arm_gate_only`; `fakeobd_live::writes_are_gated_locally_then_refused_by_the_simulator` |
| [ok] | The `TechlinekitAuthorizer` stub resolves its entry point but brokers nothing yet (clearly marked) | — | `authorizer::tests::techlinekit_authorizer_is_a_clearly_marked_stub` |
| [open] | `TechlinekitAuthorizer` brokers a real `AuthGrant` over a process boundary: the TDS session returns the `0x27` key from GM's SPS2 seed→key service (`POST /sps/module-unlock/enc/*`, `{seed, vin, algorithmNumber}` → `key` under the TLC bearer). Blocked on techlinekit growing the broker subcommand + SecureEndpoint envelope + per-module endpoint mapping | SPS2 `sps2.jar` module-unlock clients; Techline Connect / TDS (not in primarysource) | none |

## CLI and fakeobd-first

| Status | Obligation | Anchor | Test |
| --- | --- | --- | --- |
| [ok] | `scan` reads and names DTCs read-first over the link | — | `fakeobd_live::cli_scan_against_the_simulator_names_dtcs` |
| [ok] | A gated write declined at the confirmation prompt is not sent | — | `fakeobd_live::cli_write_declined_at_confirmation_is_not_sent` |
| [ok] | An unknown command is refused before any link is opened | — | `cli::tests::unknown_command_is_rejected_without_opening_a_link` |
| [ok] | `catalog` is offline reference and never opens a link | — | `cli::tests::catalog_is_offline_and_lists_services` |
| [ok] | `--write` / `--actuate` set the session arm level | — | `cli::tests::parse_sets_arm_from_flags` |
| [ok] | `--techline` installs the techlinekit authorizer (default: none, actuation locked) | — | `cli::tests::parse_sets_the_authorizer_from_the_techline_flag` |
| [ok] | Hex arguments parse (even length, hex digits) | — | `cli::tests::parse_hex_round_trips` |
| [ok] | `--dry-run` spawns fakeobd and drives the whole stack against it | — | `fakeobd_live::cli_dry_run_spawns_fakeobd_when_the_binary_is_on_path_or_env` |
