"""Run the hosted root-setup/unprivileged-observer protected-slot profile."""

import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("protected_slot_common", HERE.parent / "protected_slot/run.py")
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)
ROOT = Path("/run/exacopy-protected-root-v1")
UNIT = "exacopy-protected-root-v1.service"
CGROUP = Path("/sys/fs/cgroup/system.slice") / UNIT
RECEIPT_CGROUP = f"0::/system.slice/{UNIT}"
PROFILE = "linux-hosted-root-setup-unprivileged-observer-v1"
ID = "linux-protected-slot-hosted-root-setup"
SUDO = ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin", "LANG=C"]
SERVICE = [
    *SUDO, "/usr/bin/systemd-run", f"--unit={UNIT}", "--wait", "--pipe", "--collect",
    "--service-type=exec", "--property=WorkingDirectory=/", "--property=KillMode=control-group",
    "--property=RuntimeMaxSec=60s", "--property=TimeoutStopSec=5s",
    "/usr/bin/python3", "-I", "-B", str(ROOT / "setup.py"),
]


def bind_manifest():
    manifest = HERE / "fixture.toml"
    raw = manifest.read_bytes()
    parsed = tomllib.loads(raw.decode("utf-8"))
    expected = {
        "schema_version": 1, "id": ID, "target": COMMON.TARGET, "profile": PROFILE,
        "rust_toolchain": COMMON.TOOLCHAIN, "runner": "verification/protected_root_setup/run.py",
        "controls": "verification/protected_root_setup/test_runner.py",
        "workflow": ".github/workflows/linux-protected-slot-root-setup.yml", "result": "result.json",
        "case": [
            {"selector": name, "source": "src/linux/protected_slot/tests.rs", "ignored": False}
            for name in COMMON.ORDINARY
        ] + [{"selector": COMMON.MOUNT_TEST, "source": "src/linux/protected_slot/tests/mount.rs",
              "ignored": True}],
    }
    if parsed != expected or type(parsed["schema_version"]) is not int or any(
        type(case["ignored"]) is not bool for case in parsed["case"]
    ):
        raise RuntimeError("root-setup fixture manifest drift")
    return {
        "fixture_id": ID, "fixture_manifest_sha256": COMMON.sha256(manifest), "profile": PROFILE,
        "target": COMMON.TARGET, "rust_toolchain": COMMON.TOOLCHAIN,
    }


def check_receipt(stdout, expected_hash, outer_namespace):
    records = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    if [record.get("role") for record in records] != ["setup", "observer", "unmount", "fixture_cleanup"]:
        raise RuntimeError("missing or ambiguous root-setup receipt")
    setup, observer, unmount, cleanup = records
    namespace = setup.get("namespace")
    invocation = setup.get("invocation")
    if (
        setup.get("uid") != 0 or type(setup.get("uid")) is not int
        or not isinstance(namespace, str) or re.fullmatch(r"mnt:\[[1-9][0-9]*\]", namespace) is None
        or namespace in (outer_namespace, setup.get("prior_namespace"))
        or not isinstance(invocation, str) or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
        or observer.get("invocation") != invocation
        or setup.get("cgroup") != RECEIPT_CGROUP or observer.get("cgroup") != RECEIPT_CGROUP
        or observer.get("namespace") != namespace or observer.get("sha256") != expected_hash
        or observer.get("uids") != [1001] * 4 or observer.get("gids") != [1001] * 4
        or observer.get("groups") != [] or observer.get("no_new_privs") != 1
        or observer.get("caps") != dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), 0)
        or unmount.get("covered_inode_preserved") is not True
        or unmount.get("sentinels_preserved") is not True or cleanup.get("absent") is not True
    ):
        raise RuntimeError("root-setup receipt disagrees with fixture authority or cleanup")
    return records


def require_service_absent(evidence, label):
    result = COMMON.record(evidence, label, COMMON.collect([
        "/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", UNIT,
    ]))
    if result.returncode or result.stdout.strip() or os.path.lexists(CGROUP):
        raise RuntimeError("root-setup service or cgroup absence is unconfirmed")
    if os.path.lexists(ROOT / "fixture"):
        raise RuntimeError("root-setup fixture absence is unconfirmed")


def run_mount(evidence, work, binary):
    del work
    if os.getresuid() != (1001,) * 3 or os.getresgid() != (1001,) * 3:
        raise COMMON.Blocked("expected fixed hosted runner credentials")
    expected = COMMON.sha256(binary)
    observer = ROOT / "inbox" / "observer"
    outer_namespace = os.readlink("/proc/self/ns/mnt")
    require_service_absent(evidence, "service-before")
    owned = None
    try:
        with binary.open("rb") as source, observer.open("xb") as destination:
            node = os.fstat(destination.fileno())
            owned = (node.st_dev, node.st_ino)
            shutil.copyfileobj(source, destination, length=65536)
        result = COMMON.record(evidence, "mount", COMMON.collect(SERVICE, timeout=80))
        COMMON.check_exact_test(result, COMMON.MOUNT_TEST)
        facts = check_receipt(result.stdout, expected, outer_namespace)
        (evidence / "root-setup.json").write_text(json.dumps(facts, indent=2) + "\n")
    finally:
        if owned is not None:
            require_service_absent(evidence, "service-final")
            current = observer.lstat()
            if (current.st_dev, current.st_ino) != owned:
                raise RuntimeError("observer inbox identity changed; preserve entry")
            observer.unlink()
            if os.path.lexists(observer):
                raise RuntimeError("observer inbox cleanup unconfirmed")


if __name__ == "__main__":
    sys.exit(COMMON.main(binding=bind_manifest, mount_runner=run_mount, permit_helper=False))
