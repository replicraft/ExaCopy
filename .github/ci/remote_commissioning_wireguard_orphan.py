"""Retire only the fixture TCP socket left by its confirmed SIGKILL cut."""
from dataclasses import asdict
import os
import re

from fixture import AUTHENTICATION, CONNECTION, MAX_PEER_LOG, canonical, checked_read, match_records, owned_directory
from process import CLEANUP_MARKER
from remote_commissioning_peer import Blocked
from remote_commissioning_wireguard_net import CLIENT, SERVER, SSH_PORT
from remote_commissioning_wireguard_tcp import observe_tcp

# A singleton IPv4 TCP SOCK_DESTROY using the original inet_diag cookie. The
# kernel checks the cookie during lookup, even if the tuple has been reused.
# Linux v7.0: include/uapi/linux/{inet_diag,sock_diag,netlink}.h,
# net/ipv4/tcp_diag.c and net/netlink/af_netlink.c.
DESTROY = f"""
import errno
import os
import socket
import struct
import sys
import time

device, inode, client_port, cookie = map(int, sys.argv[1:])
identity = os.stat('/proc/self/ns/net')
if (identity.st_dev, identity.st_ino) != (device, inode):
    raise SystemExit(2)
if not 1 <= client_port <= 65535 or not 0 < cookie < 2**64 - 1:
    raise SystemExit(2)

header = struct.Struct('=IHHII')
# Family, protocol, extensions, pad and states, then the exact socket id.
payload = struct.pack('=BBBBI', socket.AF_INET, socket.IPPROTO_TCP, 0, 0, 0)
payload += struct.pack('!HH', {SSH_PORT}, client_port)
payload += socket.inet_aton({SERVER!r}).ljust(16, b'\\0') + socket.inet_aton({CLIENT!r}).ljust(16, b'\\0')
# OpenSSH binds the fixture address without SO_BINDTODEVICE. The pinned `ss`
# selector refuses interface-qualified rows, so idiag_if is exactly zero.
payload += struct.pack('=III', 0, cookie & 0xffffffff, cookie >> 32)
with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as diag:  # NETLINK_SOCK_DIAG
    diag.bind((0, 0))
    portid = diag.getsockname()[0]
    request = header.pack(header.size + len(payload), 21, 5, 1, portid)  # destroy + request/ack
    deadline = time.monotonic() + 2
    diag.settimeout(deadline - time.monotonic())
    if diag.sendto(request + payload, (0, 0)) != len(request) + len(payload):
        raise SystemExit(2)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit(2)
    diag.settimeout(remaining)
    reply, _ancillary, flags, sender = diag.recvmsg(256)
    if sender != (0, 0) or flags or time.monotonic() > deadline:
        raise SystemExit(2)
    success = header.pack(36, 2, 0x100, 1, portid) + struct.pack('=i', 0) + request
    missing = header.pack(36 + len(payload), 2, 0, 1, portid) + struct.pack('=i', -errno.ENOENT) + request + payload
    if reply == success:
        print('removed')
    elif reply == missing:
        print('not-found')
    else:
        raise SystemExit(2)
"""


def evidence_path(evidence, name):
    owned_directory(evidence, private=True)
    if os.path.lexists(evidence / CLEANUP_MARKER):
        raise Blocked("the intentionally interrupted client group is not confirmed drained")
    return canonical(evidence / name)


def connection(evidence, name, account, *, disconnected=False):
    data = checked_read(evidence_path(evidence, f"{name}.openssh.log"), MAX_PEER_LOG)
    connections = match_records(data, CONNECTION)
    accepted = match_records(data, AUTHENTICATION)
    if len(connections) != 1 or len(accepted) != 1:
        raise Blocked("exact interrupted or resumed OpenSSH connection unavailable")
    peer, port, server, listen = connections[0]
    if (peer, server, listen) != (CLIENT, SERVER, str(SSH_PORT)) or accepted[0] != (account, peer, port):
        raise Blocked("OpenSSH fixture connection or authentication tuple changed")
    if re.fullmatch(r"[1-9][0-9]{0,4}", port) is None or int(port) > 65535:
        raise Blocked("OpenSSH fixture client port outside bounds")
    if disconnected:
        lines = data.decode("utf-8", errors="strict").splitlines()
        received = f"Received disconnect from {CLIENT} port {port}:"
        closed = f"Disconnected from user {account} {CLIENT} port {port}"
        if sum(line.startswith(received) for line in lines) != 1 or lines.count(closed) != 1:
            raise Blocked("successful resume's distinct OpenSSH disconnect was not observed")
    return int(port)


def live_flows(kernel):
    return [flow for flow in observe_tcp(kernel) if not flow.drained()]


def identify(kernel, evidence):
    evidence_path(evidence, "process-kill.journal")
    port = connection(evidence, "process-kill", kernel.fixture.account)
    flows = live_flows(kernel)
    if not flows:
        return None
    if len(flows) != 1 or flows[0].client_port != port or flows[0].state != "ESTAB":
        raise Blocked("the abandoned OpenSSH flow is not uniquely identified")
    selected = flows[0]
    if selected.cookie is None or not 0 < selected.cookie < 2**64 - 1:
        raise Blocked("the abandoned OpenSSH socket lacks an exact cookie")
    return selected


def retire(kernel, evidence, selected, report):
    resumed = connection(evidence, "resume", kernel.fixture.account, disconnected=True)
    report["resumed_client_port"] = resumed
    kernel.recheck_link()
    flows = live_flows(kernel)
    if not flows:
        report["state"] = "already-drained"
        return
    if (
        selected is None or len(flows) != 1 or flows[0].state != "ESTAB" or resumed == selected.client_port
        or (flows[0].client_port, flows[0].cookie) != (selected.client_port, selected.cookie)
    ):
        raise Blocked("TCP inventory does not contain only the original abandoned socket")
    report.update(state="submission-uncertain", before=asdict(flows[0]))
    result = kernel.call(
        kernel.peer, "retire exact socket left by fixture SIGKILL", "/usr/bin/python3", "-I", "-S", "-B", "-c", DESTROY,
        *map(str, (*kernel.peer.identity, selected.client_port, selected.cookie)),
    )
    if result not in {b"removed\n", b"not-found\n"}:
        raise Blocked("socket retirement acknowledgement was not exact")
    report["kernel_reply"] = result.decode("ascii").strip()
    after = observe_tcp(kernel)
    report["after"] = [asdict(flow) for flow in after]
    if any(not flow.drained() or flow.client_port == selected.client_port for flow in after):
        raise Blocked("socket retirement did not confirm absence in the pinned namespace")
    kernel.recheck_link()
    report["state"] = "removed" if result == b"removed\n" else "confirmed-absent"
