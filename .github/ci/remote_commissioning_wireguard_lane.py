"""Supervise the bounded unprivileged campaign inside an owned systemd cgroup."""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import os
import re
import time

from native_supervision import CleanupUnconfirmed, ProcessResult
from remote_commissioning_peer import (
    CGROUP, STAT, SYSTEMCTL, SYSTEMD_RUN, Blocked, cgroup_drained, cgroup_present,
    checkpoint, run, unit_known, unit_status,
)
from remote_commissioning_wireguard_net import KEEPER_SECONDS, command, stable_pair
from remote_commissioning_wireguard_progress import ClientBudgetExpired


# Leave the owned keepers live while the parent drains the client and peer,
# deletes the exact link, proves absence and releases the namespace pins.
NAMESPACE_CLEANUP_RESERVE = 300


@dataclass(frozen=True)
class ClientBudget:
    deadline: float

    @classmethod
    def before_keepers(cls):
        return cls(time.monotonic() + KEEPER_SECONDS - NAMESPACE_CLEANUP_RESERVE)

    def time_for(self, limit=KEEPER_SECONDS):
        remaining = min(limit, int(self.deadline - time.monotonic()))
        if remaining <= 0:
            raise ClientBudgetExpired("the protected client supervision budget is exhausted")
        return remaining


class ClientStep(Enum):
    READY = "ready"
    OBSERVE = "observe"
    OBSERVED = "observed"
    CAMPAIGN = "campaign"
    CAMPAIGN_COMPLETE = "campaign-complete"
    CARRIER_DOWN = "carrier-down"


@dataclass
class ClientLane:
    unit: str
    work: Path
    duration: int
    attempted: bool = False
    invocation: str | None = None
    group: tuple[int, int] | None = None

    @property
    def cgroup(self):
        return CGROUP / self.unit

    def start(self, selected):
        checkpoint()
        if unit_known(self.unit) or os.path.lexists(self.cgroup):
            raise Blocked("generated unprivileged lane is occupied")
        self.attempted = True
        options = [
            "Type=exec", "RemainAfterExit=yes", "KillMode=control-group", "Delegate=no",
            "ProtectControlGroups=yes", "NoNewPrivileges=yes", "Restart=no",
            f"RuntimeMaxSec={self.duration}s", "TimeoutStopSec=10s",
            "StandardOutput=null", "StandardError=null",
        ]
        command(self.work, "exact isolated CLI campaign unit", [
            SYSTEMD_RUN, "--quiet", "--unit", self.unit,
            *(f"--property={item}" for item in options), "--", *selected,
        ])
        actual = unit_status(self.unit)
        identity = self.cgroup.lstat()
        if (
            actual["LoadState"] != "loaded" or actual["ActiveState"] != "active"
            or actual["ControlGroup"] != f"/system.slice/{self.unit}"
            or not re.fullmatch(r"[0-9a-f]{32}", actual["InvocationID"])
            or actual["KillMode"] != "control-group" or actual["ProtectControlGroups"] != "yes"
            or actual["Delegate"] != "no" or actual["Transient"] != "yes" or identity.st_uid != 0
            or not cgroup_present(self.cgroup, (identity.st_dev, identity.st_ino))
        ):
            raise CleanupUnconfirmed("isolated client cgroup ownership is unconfirmed")
        self.invocation = actual["InvocationID"]
        self.group = identity.st_dev, identity.st_ino

    def mount_namespace(self):
        if not cgroup_present(self.cgroup, self.group):
            raise CleanupUnconfirmed("client group disappeared")
        actual = unit_status(self.unit)
        pid = actual["MainPID"]
        if (
            actual["InvocationID"] != self.invocation or actual["ActiveState"] != "active"
            or actual["ControlGroup"] != f"/system.slice/{self.unit}"
            or actual["ProtectControlGroups"] != "yes"
            or not re.fullmatch(r"[1-9][0-9]{0,9}", pid)
        ):
            raise CleanupUnconfirmed("client process custody changed")
        proc = Path("/proc") / pid
        group = command(self.work, "exact client leader cgroup", ["/usr/bin/cat", "--", proc / "cgroup"])
        if group != f"0::/system.slice/{self.unit}\n".encode("ascii"):
            raise CleanupUnconfirmed("client leader is outside its exact cgroup")
        observed = stable_pair(command(self.work, "exact client mount namespace", [
            STAT, "-Lc", "%d:%i", "--", proc / "ns/mnt",
        ]))
        if unit_status(self.unit) != actual:
            raise CleanupUnconfirmed("client leader changed during namespace observation")
        return observed

    def outcome(self):
        output = command(self.work, "client outcome and exact invocation", [
            SYSTEMCTL, "show", "--property=InvocationID,SubState,ExecMainCode,ExecMainStatus",
            "--", self.unit,
        ], elevated=False).decode("ascii")
        fields = dict(line.split("=", 1) for line in output.splitlines())
        if fields.get("InvocationID") != self.invocation:
            raise CleanupUnconfirmed("campaign client invocation changed")
        if fields.get("SubState") in {"exited", "failed"}:
            result = fields.get("ExecMainStatus")
            if fields.get("ExecMainCode") == "1" and result in {"0", "1", "77"}:
                return ProcessResult("exited", int(result))
            return ProcessResult("unexpected-client-exit")
        return None

    def wait(self, budget, *, signal=None, stop=lambda: False):
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            checkpoint()
            if stop():
                return ProcessResult("observer-stopped")
            if signal is not None and signal.is_file():
                return ProcessResult("rendezvous")
            if (result := self.outcome()) is not None:
                return result
            time.sleep(0.5)
        return ProcessResult("timeout")

    def stop(self):
        if not self.attempted:
            return
        if self.invocation is None:
            raise CleanupUnconfirmed("no exact client invocation to stop")
        cgroup_present(self.cgroup, self.group)
        if unit_known(self.unit):
            current = unit_status(self.unit)
            if current["InvocationID"] != self.invocation or current["ControlGroup"] not in (
                f"/system.slice/{self.unit}", "",
            ):
                raise CleanupUnconfirmed("client unit custody changed")
            # Teardown may proceed after cancellation for this exact known unit.
            run([SYSTEMCTL, "stop", "--", self.unit], privileged=True, budget=25, operation="owned client group stop")
        if not cgroup_drained(self.cgroup, self.group):
            raise CleanupUnconfirmed("client cgroup did not drain")
