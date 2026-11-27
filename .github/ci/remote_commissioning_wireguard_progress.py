"""Bounded commissioning milestones without subprocess input or output."""

from enum import Enum
import subprocess

from native_supervision import CleanupUnconfirmed
from remote_commissioning_peer import Blocked


class Step(Enum):
    BUILD = "build"
    FIXTURE_ROOT = "fixture-root"
    PEER_TOOL = "peer-tool"
    PROVIDER = "provider"
    KEEPER_ADMISSION = "keeper-admission"
    KEEPER_START = "keeper-start"
    KEEPER_STATUS = "keeper-status"
    KEEPER_PROPERTIES = "keeper-properties"
    KEEPER_LEADER = "keeper-leader"
    KEEPER_CGROUP = "keeper-cgroup"
    KEEPER_NETWORK = "keeper-network"
    PIN_CREATE = "pin-create"
    PIN_BIND = "pin-bind"
    PIN_VERIFY = "pin-verify"
    PIN_STAT = "pin-stat"
    PIN_MOUNT_QUERY = "pin-mount-query"
    NAMESPACE_SEPARATION = "namespace-separation"
    LOOPBACK_INVENTORY = "loopback-inventory"
    LOOPBACK_UP = "loopback-up"
    SYNTHETIC_KEYS = "synthetic-keys"
    PROVIDER_RECHECK = "provider-recheck"
    LINK_VACANCY = "link-vacancy"
    LINK_CREATE = "link-create"
    LINK_BIRTH_IDENTITY = "link-birth-identity"
    LINK_ALIAS = "link-alias"
    LINK_FULL_IDENTITY = "link-full-identity"
    LINK_MOVE = "link-move"
    LINK_PEER_IDENTITY = "link-peer-identity"
    LINK_CONFIGURE = "link-configure"
    LINK_ADDRESS = "link-address"
    LINK_UP = "link-up"
    LINK_ROUTE = "link-route"
    LINK_LISTEN = "link-listen"
    TOPOLOGY_VERIFY = "topology-verify"
    CLIENT_OBSERVATIONS = "client-observations"
    SSH_SETUP = "ssh-setup"
    CAMPAIGN = "campaign"
    CARRIER_DOWN = "carrier-down"
    SSH_STOP = "ssh-stop"
    LINK_REMOVE = "link-remove"
    LINK_RECHECK = "link-recheck"
    LINK_ABSENCE = "link-absence"
    ROUTE_ABSENCE = "route-absence"
    SOCKET_ABSENCE = "socket-absence"
    KEEPER_STOP = "keeper-stop"
    KEEPER_DRAIN = "keeper-drain"
    PIN_RELEASE = "pin-release"
    PIN_UNMOUNT = "pin-unmount"
    PIN_RELEASED_IDENTITY = "pin-released-identity"
    FIXTURE_REMOVE = "fixture-remove"
    MARKER_REMOVE = "marker-remove"


class Role(Enum):
    CLIENT = "client"
    PEER = "peer"


class LinkPredicate(Enum):
    VACANCY = "namespace-vacancy"
    INVENTORY = "link-inventory"
    KEEPER = "namespace-keeper"
    NAME = "link-name"
    INDEX = "link-index"
    KIND = "link-kind"
    ALIAS_UNSET = "link-alias-unset"
    ALIAS_MATCH = "link-alias-match"
    EFFECT = "link-effect-unconfirmed"


class LinkUnconfirmed(CleanupUnconfirmed):
    def __init__(self, predicate):
        super().__init__("WireGuard link ownership unavailable")
        self.predicate = predicate


class ClientBudgetExpired(Blocked):
    pass


class CommandRefused(Blocked):
    def __init__(self, operation, result):
        self.operation = operation if isinstance(operation, Step) else None
        label = self.operation.value if self.operation is not None else operation
        super().__init__(f"kernel peer command refused: {label}")
        self.result = result


def failure(error):
    if isinstance(error, LinkUnconfirmed):
        result = {"kind": "ownership-unconfirmed", "predicate": error.predicate.value}
        if isinstance(error.__cause__, CommandRefused):
            result["command"] = failure(error.__cause__)
        return result
    if isinstance(error, CommandRefused):
        status = error.result.status
        allowed = {"exited", "interrupted", "startup-failed", "output-limit", "timeout", "stray-descendant"}
        result = {"kind": "command", "status": status if type(status) is str and status in allowed else "unknown"}
        if error.operation is not None:
            result["operation"] = error.operation.value
        exit_status = error.result.exit_status
        if type(exit_status) is int and -255 <= exit_status <= 255:
            result["exit_status"] = exit_status
        return result
    if isinstance(error, CleanupUnconfirmed):
        return {"kind": "ownership-unconfirmed"}
    if isinstance(error, ClientBudgetExpired):
        return {"kind": "client-supervision-budget-exhausted"}
    if isinstance(error, Blocked):
        return {"kind": "refused"}
    if isinstance(error, OSError):
        result = {"kind": "io"}
        if type(error.errno) is int and 0 < error.errno <= 255:
            result["errno"] = error.errno
        return result
    if isinstance(error, subprocess.SubprocessError):
        return {"kind": "subprocess"}
    if isinstance(error, (KeyError, TypeError, ValueError)):
        return {"kind": "invalid-observation"}
    return {"kind": "unexpected"}


class Progress:
    def __init__(self):
        self.evidence = {"disposition": "not-started"}

    def advance(self, step, role=None):
        evidence = self.evidence
        if "step" in evidence:
            evidence["last_completed"] = evidence["step"]
        evidence["step"] = {"code": step.value}
        if role is not None:
            evidence["step"]["role"] = role.value
        evidence["disposition"] = "in-progress"

    def failed(self, error):
        self.evidence.update(disposition="failed", failure=failure(error))

    def completed(self):
        self.evidence["disposition"] = "completed"

    def held(self):
        self.evidence["disposition"] = "held-uncertain"
