#!/usr/bin/env python3
"""Host the ordinary direct CLI's READ timeout campaign in a dedicated OpenSSH jail."""

import hashlib
import os
from pathlib import Path
import stat
import sys

import remote_commissioning as commissioning
from native_supervision import CleanupUnconfirmed, logged_command, write_json
from remote_commissioning_peer import INSTALL, NOLOGIN, Blocked, Fixture, checkpoint, directory_identity, run
import remote_qualification as native
from retry_campaign import CASES, SOURCE_BYTES


COMMAND = "exacopy-fixture-sftp-v1"
CC = Path("/usr/bin/cc")
CAMPAIGN_FILES = {f"campaign/{name}.openssh.log": commissioning.MAX_SUMMARY for name, _ in CASES}
CAMPAIGN_FILES.update({f"campaign/{name}.terminal.json": 1024 for name, _ in CASES})
CAMPAIGN_FILES.update({
    "campaign/sftp-events.log": commissioning.MAX_SUMMARY,
    "campaign/openssh.log": commissioning.MAX_SUMMARY,
})
PROGRAM = "remote_retry_commissioning.py"


class RetryFixture(Fixture):
    @property
    def jail_shell(self):
        return self.chroot / Path(NOLOGIN).relative_to("/")

    @property
    def retry_trace(self):
        return self.chroot / "retry-state/events"

    @property
    def retry_release(self):
        return self.chroot / "retry-control/release-redial"

    def make_root(self):
        super().make_root()
        selected = CC.resolve(strict=True)
        info = selected.stat()
        if not selected.is_relative_to("/usr/bin") or not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise Blocked("native C compiler is unavailable in the hosted tool boundary")
        source = native.REPO / native.FIXTURES / "retry_sftp_peer.c"
        helper = self.private / "fixture-sftp"
        run([CC, "-std=c17", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
             source, "-o", helper], budget=30, operation="bounded SFTP fixture compilation")
        if not helper.is_file() or helper.is_symlink() or helper.stat().st_size > 4 * 1024 * 1024:
            raise Blocked("compiled SFTP fixture is outside its size or type budget")
        inside = self.jail_shell
        checkpoint()
        run([INSTALL, "-d", "-m", "0755", "--", inside.parent, self.chroot / "retry-input"],
            privileged=True, operation="isolated retry fixture filesystem")
        # Host passwd still selects its ordinary nologin. Only the exact
        # dedicated chroot resolves that shell path to the bounded fixture.
        checkpoint()
        run([INSTALL, "-m", "0755", "--", helper, inside],
            privileged=True, operation="restricted chroot fixture shell")
        run([INSTALL, "-d", "-m", "0755", "-o", str(os.geteuid()), "-g", str(os.getegid()),
             "--", self.retry_release.parent], privileged=True, operation="operator-only release directory")
        directory_identity(self.retry_release.parent, os.geteuid(), 0o755)

    def make_sources(self):
        for name, _ in CASES:
            checkpoint()
            with (self.source / name).open("xb") as file:
                seed = self.nonce.encode("ascii") + name.encode("ascii")
                file.write(hashlib.shake_256(seed).digest(SOURCE_BYTES))
                os.fchmod(file.fileno(), 0o444)
        chosen = self.source / "redial"
        return chosen, chosen

    def make_peer(self):
        if self.account_identity is None or self.observe_account() != self.account_identity:
            raise CleanupUnconfirmed("retry fixture account identity is unavailable")
        uid, _ = self.account_identity
        run([INSTALL, "-d", "-m", "0755", "-o", str(uid), "-g", str(os.getegid()),
             "--", self.retry_trace.parent], privileged=True, operation="owned SFTP trace namespace")
        run([INSTALL, "-m", "0640", "-o", str(uid), "-g", str(os.getegid()),
             "--", "/dev/null", self.retry_trace], privileged=True, operation="owned SFTP trace file")
        profile, log, observations = super().make_peer()
        helper = self.private / "fixture-sftp"
        observations["sftp_subsystem"] = "bounded-read-only-fault-fixture"
        observed = self.jail_shell.lstat()
        digest = commissioning.file_digest(helper)
        if (
            not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o755
            or commissioning.file_digest(self.jail_shell) != digest
        ):
            raise CleanupUnconfirmed("chroot fixture shell custody changed")
        observations["sftp_subsystem_sha256"] = digest
        return profile, log, observations

    def sshd_config(self, port):
        base = super().sshd_config(port)
        original = "Subsystem sftp internal-sftp -R -d /\nForceCommand internal-sftp -R -d /\n"
        if base.count(original) != 1:
            raise Blocked("could not select the exact isolated fixture subsystem")
        # The isolated listener forces a non-interactive command after ordinary
        # key authentication, as does the baseline internal-sftp listener. The
        # chroot executable accepts only this exact argv and read-only SFTP.
        return base.replace(original, f"Subsystem sftp {NOLOGIN}\nForceCommand {COMMAND}\n")

    def sshd_properties(self):
        settings = super().sshd_properties()
        settings["BindReadOnlyPaths"] += f" {self.source}:{self.chroot / 'retry-input'}:norbind"
        return settings


def retry_campaign(fixture, paths, binary, work):
    output = work / "campaign"
    command = [
        sys.executable, "-B", str(native.FIXTURES / "retry_campaign.py"),
        "--binary", str(binary), "--evidence", str(output),
        "--sources", str(fixture.source), "--trace", str(fixture.retry_trace),
        "--release-path", str(fixture.retry_release),
    ]
    for name in ("destination", "owner_profile", "ssh_profile", "qualification", "trust", "sshd_log"):
        command.extend(("--" + name.replace("_", "-"), str(paths[name])))
    log = work / "campaign.log"
    try:
        result = logged_command(command, log, 220, output_limit=8192)
        write_json(work / "campaign-process.json", native.process_record(result, log))
    finally:
        try:
            (output / "cleanup-unconfirmed.json").lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CleanupUnconfirmed("retry campaign child custody could not be inspected") from error
        else:
            raise CleanupUnconfirmed("retry campaign nested CLI cleanup remained unconfirmed")
    if not result.passed():
        return 1 if result.exit_status == 1 else 77
    summary = commissioning.read_json(output / "summary.json", commissioning.MAX_SUMMARY)
    if (
        summary.get("schema") != "exacopy.linux-remote-read-timeout.v1"
        or summary.get("status") != "pass" or summary.get("observed_route") != native.DIRECT
        or summary.get("qualifies_remote_download") is not False
        or summary.get("issues_new_qualification") is not False
        or summary.get("exit_status") != 0
        or [record["case"] for record in summary.get("cases", [])] != [name for name, _ in CASES]
    ):
        raise Blocked("retry campaign did not establish the exact bounded results")
    return 0


if __name__ == "__main__":
    raise SystemExit(commissioning.main(
        fixture_kind=RetryFixture, campaign=retry_campaign, program=PROGRAM,
        report_name="exacopy-retry-commissioning", case_files=CAMPAIGN_FILES, require_case_exports=True,
        events=("push",),
    ))
