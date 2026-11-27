"""Bounded observations of the owned OpenSSH listener's inner TCP flows."""
from dataclasses import dataclass
import re

from remote_commissioning_peer import Blocked
from remote_commissioning_wireguard_net import CLIENT, SERVER, SSH_PORT, SS

TCP_STATES = frozenset({
    b"ESTAB", b"SYN-SENT", b"SYN-RECV", b"FIN-WAIT-1", b"FIN-WAIT-2",
    b"TIME-WAIT", b"CLOSE-WAIT", b"LAST-ACK", b"CLOSING",
})
TCP_TIMERS = rb"off|on|keepalive|timewait|persist|delack|unknown"
MAX_TCP_REPORT = 8192
MAX_TCP_FLOWS = 4


@dataclass(frozen=True)
class TcpFlow:
    client_port: int
    state: str
    recv_queue: int
    send_queue: int
    timer: str | None
    timer_retransmissions: int | None
    retransmissions: int | None
    bytes_retransmitted: int | None
    segments_sent: int | None

    def drained(self):
        return (
            self.state == "TIME-WAIT" and self.recv_queue == self.send_queue == 0
            and self.timer in {None, "timewait"}
        )


def counter(raw):
    if re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})", raw) is None or (number := int(raw)) >= 2**64:
        raise Blocked("inner TCP socket counter outside bounds")
    return number


def optional_field(fields, name):
    selected = [field[len(name):] for field in fields if field.startswith(name)]
    if len(selected) > 1:
        raise Blocked("duplicate inner TCP socket field")
    return selected[0] if selected else None


def parse_tcp(raw):
    lines = raw.splitlines()
    if len(raw) > MAX_TCP_REPORT or len(lines) > MAX_TCP_FLOWS:
        raise Blocked("inner TCP socket inventory outside bounds")
    result = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            raise Blocked("inner TCP socket observation incomplete")
        state, recv, send, local, remote, *details = fields
        host, _, port = remote.rpartition(b":")
        if state not in TCP_STATES or local != f"{SERVER}:{SSH_PORT}".encode() or host != CLIENT.encode():
            raise Blocked("inner TCP socket does not match the exact fixture route")
        number = counter(port)
        if not 1 <= number <= 65535 or number in result:
            raise Blocked("inner TCP socket port absent or ambiguous")
        timer = timer_retransmissions = retransmissions = None
        if (raw_timer := optional_field(details, b"timer:")) is not None:
            match = re.fullmatch(rb"\((" + TCP_TIMERS + rb"),[^,\s()]{1,24},([0-9]{1,20})\)", raw_timer)
            if match is None:
                raise Blocked("inner TCP socket timer invalid")
            timer = match[1].decode("ascii")
            timer_retransmissions = counter(match[2])
        if (raw_retransmissions := optional_field(details, b"retrans:")) is not None:
            pending, sep, total = raw_retransmissions.partition(b"/")
            if not sep or counter(pending) > (retransmissions := counter(total)):
                raise Blocked("inner TCP socket retransmissions invalid")
        raw_bytes = optional_field(details, b"bytes_retrans:")
        raw_segments = optional_field(details, b"segs_out:")
        result[number] = TcpFlow(number, state.decode("ascii"), counter(recv), counter(send),
                                 timer, timer_retransmissions, retransmissions,
                                 None if raw_bytes is None else counter(raw_bytes),
                                 None if raw_segments is None else counter(raw_segments))
    return [result[port] for port in sorted(result)]


def observe_tcp(kernel):
    # Connected includes the TIME-WAIT minisocket and omits the fixed listener.
    raw = kernel.call(kernel.peer, "observe exact inner OpenSSH sockets", SS, "-H4ntoiO",
                      "state", "connected", "src", f"{SERVER}:{SSH_PORT}", "dst", CLIENT)
    return parse_tcp(raw)
