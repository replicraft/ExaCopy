"""Finite kernel telemetry for a closed commissioning campaign."""
import base64
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import time

from remote_commissioning_peer import Blocked, checkpoint

CASES = (
    ("qualification-path-control", 0), ("qualification-refusal", 0),
    ("get", 1), ("incumbent", 0), ("process-kill", 1),
    ("resume", 1), ("post-intent", 0),
)
CASE_TIMEOUT = 120


@dataclass(frozen=True)
class Counters:
    received: int
    sent: int
    handshake: int
    endpoint: str | None


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


def wait_file(path, stop=lambda: False):
    deadline = time.monotonic() + CASE_TIMEOUT
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
