#!/usr/bin/env python3
"""Select one closed provider task from the current hosted runner's boot."""

import os
from pathlib import Path
import stat

import remote_commissioning as direct
from remote_commissioning_peer import Blocked
import remote_commissioning_wireguard_enrollment as enrollment
import remote_commissioning_wireguard_provider as provider
import remote_commissioning_wireguard_provider_b as azure
from native_supervision import file_digest, write_json
from remote_commissioning_wireguard_provider_profiles import DispatchMode, known_profile


def select(observed, revision):
    if observed.get("revision") != revision:
        return DispatchMode.BLOCKED, "provider observation lacks the selected revision"
    profile = known_profile(observed.get("kernel", {}))
    if profile is not None:
        try:
            azure.admit(observed, profile)
        except Blocked:
            return DispatchMode.BLOCKED, "known profile lacks exact packaged-unloaded admission"
        return profile.mode, "exact packaged-unloaded Azure provider"
    try:
        candidate = enrollment.selected(observed)
    except Blocked:
        return DispatchMode.BLOCKED, "no exact admitted provider or read-only enrollment candidate"
    return DispatchMode.OBSERVE, candidate.tag


def write_mode(parent, mode):
    # GitHub's fresh step output file is owned by the current runner account.
    output = Path(os.environ["GITHUB_OUTPUT"])
    if not output.is_relative_to(parent) or output.resolve(strict=True) != output:
        raise Blocked("hosted step output is outside its selected custody")
    fd = os.open(output, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_APPEND | os.O_CLOEXEC)
    with os.fdopen(fd, "wb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size != 0:
            raise Blocked("hosted step output is outside its selected file type")
        handle.write(f"mode={mode.value}\n".encode("ascii"))


def main():
    azure.hosted_scope()
    parent = provider.hosted_admission()
    if direct.hosted_parent(azure.DISPATCH_PROGRAM, ("push",)) != parent:
        raise Blocked("hosted provider dispatch parent differs")
    source = direct.native.source_identity(direct.native.REPO)
    revision = os.environ["GITHUB_SHA"]
    if source["revision"] != revision:
        raise Blocked("hosted provider dispatch checkout differs")
    run = azure.dispatch_run()
    directory = parent / provider.REPORT
    directory.mkdir(mode=0o700)
    observed = provider.report()
    provider.write_report(directory, observed)
    mode, reason = select(observed, revision)
    profile = known_profile(observed.get("kernel", {}))
    try:
        if profile is not None and mode is profile.mode:
            azure.recheck_boot(profile, observed["kernel"])
        elif mode is DispatchMode.OBSERVE:
            enrollment.same_boot(observed["kernel"])
    except Blocked:
        mode, reason = DispatchMode.BLOCKED, "boot no longer matches provider selection"
    write_json(directory / azure.DISPATCH_RECORD, {
        "schema": azure.DISPATCH_SCHEMA, "mode": mode.value, "reason": reason, "revision": revision,
        "source": source, "run": run, "kernel": observed["kernel"],
        "provider_observation_sha256": file_digest(directory / "provider.json"),
        "qualified": False, "load_attempted": False,
    })
    write_mode(parent, mode)
    if mode is DispatchMode.OBSERVE:
        # Enrollment can succeed as an observation only. Commissioning keeps a
        # nonpassing disposition for this boot even with complete observations.
        enrollment.main(enrollment.EnrollmentContext.PROVIDER_B_OBSERVATION, observed)
        return 77
    return 0 if profile is not None and mode is profile.mode else 77


if __name__ == "__main__":
    raise SystemExit(main())
