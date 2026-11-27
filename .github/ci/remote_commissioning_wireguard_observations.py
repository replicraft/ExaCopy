"""Finite kernel telemetry for a closed commissioning campaign."""
import base64
from dataclasses import asdict, dataclass
from enum import Enum
import ipaddress
import re
import time

from remote_commissioning_peer import Blocked, checkpoint
from remote_commissioning_wireguard_progress import failure

CASES = (
    ("qualification-path-control", 0), ("qualification-refusal", 0),
    ("get", 1), ("incumbent", 0), ("process-kill", 1),
    ("resume", 1), ("post-intent", 0),
)
CASE_TIMEOUT = 120
# Linux v7.0 schedules a reactive keepalive after 10 s, can schedule one more
# 10 s later, and can initiate a handshake after 15 s plus timer jitter. Leave
# the client paused while the previous connection's carrier traffic settles.
# https://github.com/torvalds/linux/blob/v7.0/drivers/net/wireguard/timers.c
PEER_QUIET_SECONDS = 22
PEER_SETTLE_SECONDS = 60
PEER_SAMPLE_SECONDS = 1


@dataclass(frozen=True)
class Counters:
    received: int
    sent: int
    handshake: int
    endpoint: str | None


class ObservationPhase(Enum):
    INITIAL_SAMPLE = "initial-sample"
    INITIAL_BASELINE = "initial-baseline"
    START_SIGNAL = "start-signal"
    CASE_RENDEZVOUS = "case-rendezvous"
    LINK_RECHECK = "link-recheck"
    CASE_SAMPLE = "case-sample"
    CASE_DELTA = "case-delta"
    PEER_SETTLING = "peer-settling"
    CASE_ACKNOWLEDGEMENT = "case-acknowledgement"


@dataclass(frozen=True)
class ObservationFailure:
    error: Exception
    phase: ObservationPhase
    case: str | None
    before: Counters | None
    after: Counters | None
    settling: dict | None

    def evidence(self):
        evidence = {
            "phase": self.phase.value,
            "case": self.case,
            "before": asdict(self.before) if self.before is not None else None,
            "after": asdict(self.after) if self.after is not None else None,
            "failure": failure(self.error),
        }
        if self.settling is not None:
            evidence["settling"] = self.settling
        return evidence


def numbers(fields, count):
    if len(fields) != count or any(re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})", f) is None for f in fields):
        raise Blocked("kernel peer counters are outside bounds")
    values = tuple(map(int, fields))
    if any(value >= 2**64 for value in values):
        raise Blocked("kernel peer count is outside u64")
    return values


def selected_line(value, peer):
    rows = value.splitlines()
    fields = rows[0].split() if len(rows) == 1 else []
    if not fields or fields[0] != peer:
        raise Blocked("kernel observations do not identify the exact synthetic peer")
    return fields[1:]


def snapshot(kernel):
    peer = base64.b64encode(bytes.fromhex(kernel.client_public))
    received, sent = numbers(selected_line(kernel.field("transfer"), peer), 2)
    handshake, = numbers(selected_line(kernel.field("latest-handshakes"), peer), 1)
    endpoint, = selected_line(kernel.field("endpoints"), peer)
    if endpoint == b"(none)":
        address = None
    else:
        try:
            host, port = endpoint.decode("ascii").rsplit(":", 1)
            address = ipaddress.IPv4Address(host)
            if address != ipaddress.IPv4Address("127.0.0.1") or not 1 <= int(port) <= 65535:
                raise ValueError
        except (UnicodeError, ValueError) as error:
            raise Blocked("kernel peer learned a wrong outer address") from error
        address = endpoint.decode("ascii")
    return Counters(received, sent, handshake, address)


def check_delta(before, after, connections):
    if connections == 0:
        if after != before:
            raise Blocked("kernel traffic changed during a no-connection case")
    elif connections == 1:
        if (
            after.received <= before.received or after.sent <= before.sent
            or after.handshake == 0 or after.handshake < before.handshake or after.endpoint is None
        ):
            raise Blocked("OpenSSH case lacks matching bidirectional kernel peer traffic")
    else:
        raise Blocked("campaign case connection count overruns the fixture")


def wait_file(path, stop=lambda: False, *, timeout=CASE_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        checkpoint()
        if stop():
            return False
        if path.is_file():
            return True
        time.sleep(0.05)
    raise Blocked("fixture telemetry rendezvous timed out")


def file_signal(path):
    with path.open("xb"):
        pass


def settle_peer(kernel, initial, halted, evidence):
    quiet_since = started = time.monotonic()
    deadline = started + PEER_SETTLE_SECONDS
    previous = initial
    while (remaining := deadline - time.monotonic()) > 0:
        if halted.wait(min(PEER_SAMPLE_SECONDS, remaining)):
            raise Blocked("carrier settling interrupted")
        checkpoint()
        current = snapshot(kernel)
        now = time.monotonic()
        evidence.update(latest=asdict(current), elapsed_ms=int((now - started) * 1000))
        if (
            current.endpoint != initial.endpoint or current.handshake < previous.handshake
            or current.received < previous.received or current.sent < previous.sent
        ):
            raise Blocked("carrier settling observed changed peer or regressed counters")
        if current != previous:
            quiet_since = now
            previous = current
        elif now - quiet_since >= PEER_QUIET_SECONDS and now <= deadline:
            evidence["observed_quiet_ms"] = int((now - quiet_since) * 1000)
            return current
    raise Blocked("carrier did not settle between network and local-only cases")


def observe_cases(kernel, mailbox, halted, rows, failures):
    phase = ObservationPhase.INITIAL_SAMPLE
    name = before = after = settling = None
    try:
        before = snapshot(kernel)
        phase = ObservationPhase.INITIAL_BASELINE
        if before != Counters(0, 0, 0, None):
            raise Blocked("kernel peer lacks a fresh quiet initial baseline")
        phase = ObservationPhase.START_SIGNAL
        file_signal(mailbox / "start")
        for index, (name, count) in enumerate(CASES):
            after = settling = None
            phase = ObservationPhase.CASE_RENDEZVOUS
            if not wait_file(mailbox / f"case-{index}.done", halted.is_set):
                return
            phase = ObservationPhase.LINK_RECHECK
            kernel.recheck_link()
            phase = ObservationPhase.CASE_SAMPLE
            after = snapshot(kernel)
            phase = ObservationPhase.CASE_DELTA
            check_delta(before, after, count)
            row = {"case": name, "before": asdict(before), "after": asdict(after)}
            next_baseline = after
            if count == 1 and index + 1 < len(CASES) and CASES[index + 1][1] == 0:
                phase = ObservationPhase.PEER_SETTLING
                settling = {"before_case": CASES[index + 1][0], "required_quiet_ms": PEER_QUIET_SECONDS * 1000}
                next_baseline = settle_peer(kernel, after, halted, settling)
                kernel.recheck_link()
                row["settling"] = settling
            rows.append(row)
            phase = ObservationPhase.CASE_ACKNOWLEDGEMENT
            file_signal(mailbox / f"case-{index}.observed")
            before = next_baseline
    except Exception as error:
        failures.append(ObservationFailure(error, phase, name, before, after, settling))
        file_signal(mailbox / "blocked")


def observe_case(mailbox):
    current = 0

    def record(name, connections):
        nonlocal current
        if current >= len(CASES) or CASES[current] != (name, connections):
            raise Blocked("unexpected fixture telemetry case")
        file_signal(mailbox / f"case-{current}.done")
        if not wait_file(mailbox / f"case-{current}.observed", lambda: (mailbox / "blocked").is_file()):
            raise Blocked("fixture telemetry observer stopped")
        current += 1

    return record
