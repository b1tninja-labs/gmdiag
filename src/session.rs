//! The diagnostic session core: UDS services driven over a [`Transport`].
//!
//! A [`Session`] owns a transport pointed at one [`Target`] and exchanges PDUs built and decoded
//! by `udskit`. It adds the three things a live tool needs that the offline libraries refuse to
//! do: it opens a session ([`Session::enter_session`]), it keeps the session alive
//! ([`Session::tester_present`]), and it runs the response-pending (`0x78`) loop so a slow
//! positive answer is not mistaken for a failure.
//!
//! Every method that changes vehicle state checks an [`Arm`] level first. Read services run at
//! [`Arm::ReadOnly`]; coding and clearing need [`Arm::Write`]; routines, device control and a
//! SecurityAccess `sendKey` need [`Arm::Actuate`]. The *confirmation* prompt is the caller's job
//! (the CLI prompts before it calls); the arm level is the hard gate the session enforces so a
//! read-only run cannot emit a write even by mistake.

use std::time::{Duration, Instant};

use udskit::message::{self, NegativeResponse, PositiveResponse, Response};

use crate::error::{Error, Result};
use crate::transport::{Target, Transport};

/// How far the session is armed to act on the vehicle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Arm {
    /// Reads only. The default. No service that changes vehicle state will be sent.
    ReadOnly,
    /// Reads plus coding and clearing (`0x2E` WriteDataByIdentifier, `0x14` Clear).
    Write,
    /// Everything in [`Arm::Write`] plus actuation (`0x31` routines, `0x2F` device control,
    /// `0x27` sendKey).
    Actuate,
}

impl Arm {
    fn require(self, needed: Arm, what: &str) -> Result<()> {
        if self >= needed {
            Ok(())
        } else {
            Err(Error::Refused(format!(
                "{what} needs --{} (session is armed {})",
                match needed {
                    Arm::Write => "write",
                    Arm::Actuate => "actuate",
                    Arm::ReadOnly => "read",
                },
                match self {
                    Arm::ReadOnly => "read-only",
                    Arm::Write => "write",
                    Arm::Actuate => "actuate",
                }
            )))
        }
    }
}

/// One decoded DTC from a ReadDTCInformation response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DtcReport {
    /// The display code, e.g. `P0A7F`, decoded from the first two DTC bytes.
    pub code: String,
    /// The third DTC byte: the failure-type / symptom byte (FTB).
    pub ftb: u8,
    /// The statusOfDTC byte.
    pub status: u8,
    /// The name from `gmdtcdb`, when the code is in the 841-code database.
    pub name: Option<String>,
}

impl DtcReport {
    /// A one-line summary: code, name (or `?`), FTB and the set status bits.
    #[must_use]
    pub fn summary(&self) -> String {
        let name = self.name.as_deref().unwrap_or("(not in gmdtcdb)");
        let bits: Vec<&str> = udskit::dtc::decode_status(self.status)
            .iter()
            .map(|b| b.name)
            .collect();
        format!(
            "{} {name}  ftb={:02X} status={:02X} [{}]",
            self.code,
            self.ftb,
            self.status,
            bits.join(", ")
        )
    }
}

/// A live diagnostic session over a transport.
pub struct Session<T: Transport> {
    transport: T,
    target: Target,
    arm: Arm,
    /// How many response-pending (`0x78`) follow-ups to wait through before giving up.
    pub response_pending_limit: u32,
}

impl<T: Transport> Session<T> {
    /// Open a session: point the transport at `target`. Read-only until armed.
    ///
    /// # Errors
    /// Returns an error when the transport cannot be pointed at `target`.
    pub fn new(mut transport: T, target: Target) -> Result<Self> {
        transport.set_target(target)?;
        Ok(Self {
            transport,
            target,
            arm: Arm::ReadOnly,
            response_pending_limit: 8,
        })
    }

    /// The current arm level.
    #[must_use]
    pub fn arm(&self) -> Arm {
        self.arm
    }

    /// Arm the session. A caller raises this only after the operator has confirmed.
    pub fn set_arm(&mut self, arm: Arm) {
        self.arm = arm;
    }

    /// The target this session drives.
    #[must_use]
    pub fn target(&self) -> Target {
        self.target
    }

    /// Point at a different peer mid-session.
    ///
    /// # Errors
    /// Returns an error when the transport cannot be reconfigured.
    pub fn set_target(&mut self, target: Target) -> Result<()> {
        self.transport.set_target(target)?;
        self.target = target;
        Ok(())
    }

    /// Send one request and decode the response, running the `0x78` response-pending loop.
    ///
    /// Returns the final [`Response`] — positive, or a negative that is not `0x78`.
    ///
    /// # Errors
    /// Returns a transport or decode error, or [`Error::Protocol`] when the server stays in
    /// response-pending past [`Session::response_pending_limit`].
    pub fn exchange(&mut self, sid: u8, data: &[u8]) -> Result<Response> {
        let pdu = message::encode_request(sid, data);
        let raw = self.transport.request(&pdu)?;
        let mut response = message::decode_response(&raw)?;
        let mut pending = 0u32;
        while is_pending(&response) {
            if pending >= self.response_pending_limit {
                return Err(Error::Protocol(format!(
                    "server stayed response-pending (0x78) past {} follow-ups",
                    self.response_pending_limit
                )));
            }
            pending += 1;
            let more = self.transport.read_more()?;
            response = message::decode_response(&more)?;
        }
        Ok(response)
    }

    /// A positive response, or a [`Error::Negative`] carrying the server's rejection.
    ///
    /// # Errors
    /// See [`Session::exchange`]; plus [`Error::Negative`] on a negative response.
    pub fn positive(&mut self, sid: u8, data: &[u8]) -> Result<PositiveResponse> {
        match self.exchange(sid, data)? {
            Response::Positive(p) => Ok(p),
            Response::Negative(n) => Err(Error::Negative(n.describe())),
        }
    }

    // ----- session management -------------------------------------------------------------

    /// DiagnosticSessionControl (`0x10`): enter a diagnostic session (ISO 14229-1 §9.2).
    ///
    /// `session_type` is e.g. `0x01` default, `0x02` programming, `0x03` extended.
    ///
    /// # Errors
    /// See [`Session::positive`].
    pub fn enter_session(&mut self, session_type: u8) -> Result<PositiveResponse> {
        self.positive(0x10, &[session_type])
    }

    /// TesterPresent (`0x3E`): keep the session alive (ISO 14229-1 §9.6).
    ///
    /// The sub-function is `zeroSubFunction` (`0x00`). The positive response is requested (not
    /// `suppressPosRspMsgIndicationBit`), because over an ELM327 a suppressed response leaves the
    /// adapter waiting out its timeout; an answered `3E 00` confirms the link in one exchange.
    ///
    /// # Errors
    /// See [`Session::positive`].
    pub fn tester_present(&mut self) -> Result<PositiveResponse> {
        self.positive(0x3E, &[0x00])
    }

    // ----- reads --------------------------------------------------------------------------

    /// ReadDataByIdentifier (`0x22`): read one DID. Returns the echoed DID and its value bytes.
    ///
    /// # Errors
    /// See [`Session::positive`]; plus [`Error::from`] on a malformed read response.
    pub fn read_did(&mut self, did: u16) -> Result<(u16, Vec<u8>)> {
        let p = self.positive(0x22, &did.to_be_bytes())?;
        let pdu = [&[p.response_sid], p.data.as_slice()].concat();
        Ok(udskit::did::parse_read_response(&pdu)?)
    }

    /// ReadDTCInformation (`0x19`) sub-function `0x02` reportDTCByStatusMask.
    ///
    /// `status_mask` selects which DTCs to report (e.g. `0xFF` for all). The response is parsed
    /// into [`DtcReport`]s, each DTC code named from `gmdtcdb` when known.
    ///
    /// # Errors
    /// See [`Session::positive`]; plus [`Error::Protocol`] on a malformed record list.
    pub fn read_dtcs(&mut self, status_mask: u8) -> Result<Vec<DtcReport>> {
        let p = self.positive(0x19, &[0x02, status_mask])?;
        parse_dtc_by_status(&p.data)
    }

    /// Mode $06 (`0x06`) on-board monitoring test results for one OBDMID.
    ///
    /// Returns the raw `46 ...` response bytes and a human label for the OBDMID (and, where the
    /// response names a TID, the matching `mode06kit` record description).
    ///
    /// # Errors
    /// See [`Session::positive`].
    pub fn mode06(&mut self, obdmid: u8) -> Result<(Vec<u8>, Vec<String>)> {
        let p = self.positive(0x06, &[obdmid])?;
        let records = mode06kit::catalog::sample_records();
        let labels: Vec<String> = mode06kit::parser::lookup(&records, obdmid, None)
            .iter()
            .map(|r| format!("TID {:02X}: {}", r.tid, r.description))
            .collect();
        let mut bytes = vec![p.response_sid];
        bytes.extend_from_slice(&p.data);
        Ok((bytes, labels))
    }

    /// SecurityAccess (`0x27`) requestSeed for `level`: read the seed. **No key is derived.**
    ///
    /// This is a read: it returns the server's seed bytes. gmdiag derives no key from the seed —
    /// `udskit`'s boundary holds (see `docs/security-access.md`). A gated service stays locked
    /// unless a key is supplied with [`Session::security_send_key`].
    ///
    /// # Errors
    /// See [`Session::positive`]; plus [`Error::from`] when `level` is not a requestSeed level.
    pub fn security_request_seed(&mut self, level: u8) -> Result<Vec<u8>> {
        let pdu = udskit::security::build_request_seed(level)?;
        // pdu is [0x27, level]; send the sub-function as the request data.
        let p = self.positive(pdu[0], &pdu[1..])?;
        // Positive seed response data is [level, seed...]; return the seed bytes.
        Ok(p.data.get(1..).unwrap_or(&[]).to_vec())
    }

    // ----- gated writes / actuation -------------------------------------------------------

    /// SecurityAccess (`0x27`) sendKey: send an **externally supplied** key for `level`.
    ///
    /// gmdiag never computes `key`; the operator supplies it. Needs [`Arm::Actuate`].
    ///
    /// # Errors
    /// [`Error::Refused`] when not armed to actuate; otherwise see [`Session::positive`].
    pub fn security_send_key(&mut self, level: u8, key: &[u8]) -> Result<PositiveResponse> {
        self.arm.require(Arm::Actuate, "SecurityAccess sendKey")?;
        let send_level = udskit::security::send_key_for(level)?;
        let mut data = vec![send_level];
        data.extend_from_slice(key);
        self.positive(0x27, &data)
    }

    /// WriteDataByIdentifier (`0x2E`): code a DID. Needs [`Arm::Write`].
    ///
    /// # Errors
    /// [`Error::Refused`] when not armed to write; otherwise see [`Session::positive`].
    pub fn write_did(&mut self, did: u16, value: &[u8]) -> Result<PositiveResponse> {
        self.arm
            .require(Arm::Write, "WriteDataByIdentifier (coding)")?;
        let mut data = did.to_be_bytes().to_vec();
        data.extend_from_slice(value);
        self.positive(0x2E, &data)
    }

    /// ClearDiagnosticInformation (`0x14`): clear a DTC group. Needs [`Arm::Write`].
    ///
    /// `group` is the 3-byte group (`0xFF_FFFF` clears all).
    ///
    /// # Errors
    /// [`Error::Refused`] when not armed to write; otherwise see [`Session::positive`].
    pub fn clear_dtcs(&mut self, group: u32) -> Result<PositiveResponse> {
        self.arm.require(Arm::Write, "ClearDiagnosticInformation")?;
        let b = group.to_be_bytes();
        self.positive(0x14, &[b[1], b[2], b[3]])
    }

    /// RoutineControl (`0x31`): start/stop/request-results of a routine.
    ///
    /// `requestRoutineResults` (`0x03`) is a read; `startRoutine`/`stopRoutine`
    /// (`0x01`/`0x02`) are actuation and need [`Arm::Actuate`].
    ///
    /// # Errors
    /// [`Error::Refused`] when a start/stop is sent without actuation arming; otherwise see
    /// [`Session::positive`].
    pub fn routine(
        &mut self,
        subfunction: u8,
        routine_id: u16,
        data: &[u8],
    ) -> Result<PositiveResponse> {
        if subfunction != udskit::routine::REQUEST_ROUTINE_RESULTS {
            self.arm
                .require(Arm::Actuate, "RoutineControl start/stop")?;
        }
        let pdu = udskit::routine::build_request(subfunction, routine_id, data)?;
        self.positive(pdu[0], &pdu[1..])
    }

    /// InputOutputControlByIdentifier (`0x2F`) / GM device control. Needs [`Arm::Actuate`].
    ///
    /// # Errors
    /// [`Error::Refused`] when not armed to actuate; otherwise see [`Session::positive`].
    pub fn io_control(
        &mut self,
        did: u16,
        parameter: u8,
        control_state: &[u8],
    ) -> Result<PositiveResponse> {
        self.arm
            .require(Arm::Actuate, "InputOutputControl (device control)")?;
        let pdu = udskit::iocontrol::build_request(did, parameter, control_state)?;
        self.positive(pdu[0], &pdu[1..])
    }

    /// Consume the session and return the transport (for reuse or a clean close).
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// A time-driven keep-alive clock: tells the caller when the next TesterPresent is due.
///
/// A single ELM link cannot carry a background keep-alive thread without interleaving bytes with
/// a foreground request, so gmdiag keeps time instead of spawning a thread: the `session` command
/// loop asks [`KeepAlive::due`] and sends [`Session::tester_present`] when the interval elapses.
#[derive(Debug)]
pub struct KeepAlive {
    interval: Duration,
    last: Instant,
}

impl KeepAlive {
    /// A keep-alive on `interval` (GM's S3 server timeout is nominally 5 s; keep well inside it).
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: Instant::now(),
        }
    }

    /// Whether a TesterPresent is due now.
    #[must_use]
    pub fn due(&self) -> bool {
        self.last.elapsed() >= self.interval
    }

    /// Record that a TesterPresent was just sent.
    pub fn sent(&mut self) {
        self.last = Instant::now();
    }
}

fn is_pending(response: &Response) -> bool {
    matches!(response, Response::Negative(NegativeResponse { code, .. }) if udskit::nrc::is_response_pending(*code))
}

/// Parse a ReadDTCInformation sub-function `0x02` positive response payload into [`DtcReport`]s.
///
/// The payload (after the `59 02` service bytes `udskit` strips) is one availability-mask byte
/// followed by 4-byte records: three DTC bytes and one statusOfDTC byte. The first two DTC bytes
/// decode to the display code; the third is the failure-type byte.
fn parse_dtc_by_status(data: &[u8]) -> Result<Vec<DtcReport>> {
    // data = [subfunction echo 0x02, availabilityMask, (dtc_hi dtc_mid dtc_lo status)*]
    let Some(body) = data.get(2..) else {
        return Err(Error::Protocol(
            "ReadDTCInformation response too short for sub-function and mask".into(),
        ));
    };
    if body.len() % 4 != 0 {
        return Err(Error::Protocol(format!(
            "ReadDTCInformation record bytes {} are not a multiple of 4",
            body.len()
        )));
    }
    let db = gmdtcdb::database::Database::load();
    let mut out = Vec::with_capacity(body.len() / 4);
    for record in body.chunks_exact(4) {
        let code = udskit::dtc::decode(&record[..2])?;
        let name = db.get(&code).map(|r| r.name.clone());
        out.push(DtcReport {
            code,
            ftb: record[2],
            status: record[3],
            name,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted transport: each `request`/`read_more` pops the next canned response PDU.
    struct MockTransport {
        responses: std::cell::RefCell<std::collections::VecDeque<Vec<u8>>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: std::cell::RefCell::new(responses.into()),
            }
        }
        fn pop(&self) -> Result<Vec<u8>> {
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| Error::Protocol("mock ran out of responses".into()))
        }
    }

    impl Transport for MockTransport {
        fn set_target(&mut self, _target: Target) -> Result<()> {
            Ok(())
        }
        fn request(&mut self, _pdu: &[u8]) -> Result<Vec<u8>> {
            self.pop()
        }
        fn read_more(&mut self) -> Result<Vec<u8>> {
            self.pop()
        }
    }

    fn mock_session(responses: Vec<Vec<u8>>) -> Session<MockTransport> {
        Session::new(MockTransport::new(responses), Target::new(0x7E0, 0x7E8)).unwrap()
    }

    #[test]
    fn response_pending_loop_waits_through_0x78_then_takes_the_positive() {
        // Two 0x78 pending answers, then the positive 0x50 01 session response.
        let mut s = mock_session(vec![
            vec![0x7F, 0x10, 0x78],
            vec![0x7F, 0x10, 0x78],
            vec![0x50, 0x01, 0x00, 0x32, 0x01, 0xF4],
        ]);
        let p = s.enter_session(0x01).unwrap();
        assert_eq!(p.response_sid, 0x50);
    }

    #[test]
    fn response_pending_loop_gives_up_after_the_limit() {
        let mut s = mock_session(vec![
            vec![0x7F, 0x10, 0x78],
            vec![0x7F, 0x10, 0x78],
            vec![0x7F, 0x10, 0x78],
        ]);
        s.response_pending_limit = 1;
        assert!(matches!(s.enter_session(0x01), Err(Error::Protocol(_))));
    }

    #[test]
    fn send_key_requires_actuate_and_never_derives() {
        // sendKey takes the requestSeed (odd) level; the pair is level+1. Read-only and
        // write-armed sessions both refuse before any byte is sent.
        let mut s = mock_session(vec![]);
        assert!(matches!(
            s.security_send_key(0x01, &[0xDE, 0xAD]),
            Err(Error::Refused(_))
        ));
        s.set_arm(Arm::Write);
        assert!(matches!(
            s.security_send_key(0x01, &[0xDE, 0xAD]),
            Err(Error::Refused(_))
        ));
        // Armed to actuate, the supplied key is sent (the mock accepts it with 0x67).
        let mut s = Session::new(
            MockTransport::new(vec![vec![0x67, 0x02]]),
            Target::new(0x7E0, 0x7E8),
        )
        .unwrap();
        s.set_arm(Arm::Actuate);
        assert_eq!(
            s.security_send_key(0x01, &[0xDE, 0xAD])
                .unwrap()
                .response_sid,
            0x67
        );
    }

    #[test]
    fn arm_ordering_gates_writes() {
        assert!(Arm::ReadOnly < Arm::Write);
        assert!(Arm::Write < Arm::Actuate);
        assert!(Arm::ReadOnly.require(Arm::Write, "x").is_err());
        assert!(Arm::Write.require(Arm::Write, "x").is_ok());
        assert!(Arm::Write.require(Arm::Actuate, "x").is_err());
        assert!(Arm::Actuate.require(Arm::Actuate, "x").is_ok());
    }

    #[test]
    fn dtc_by_status_decodes_records_and_names() {
        // availabilityMask 0xFF, then one record for P0A7F-00 with status 0x24.
        let p0a7f = udskit::dtc::encode("P0A7F").unwrap();
        let data = vec![0x02, 0xFF, p0a7f[0], p0a7f[1], 0x00, 0x24];
        let reports = parse_dtc_by_status(&data).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].code, "P0A7F");
        assert_eq!(reports[0].ftb, 0x00);
        assert_eq!(reports[0].status, 0x24);
    }

    #[test]
    fn dtc_by_status_rejects_a_ragged_record_list() {
        let data = vec![0x02, 0xFF, 0x01, 0x02, 0x03];
        assert!(parse_dtc_by_status(&data).is_err());
    }

    #[test]
    fn keepalive_starts_not_due() {
        let k = KeepAlive::new(Duration::from_secs(2));
        assert!(!k.due());
    }
}
