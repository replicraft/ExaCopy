#!/usr/bin/env python3
"""Probe the real ExaCopy CLI on a disposable native Linux directory."""

from pathlib import Path
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid

exe = os.fsencode(Path(sys.argv[1]).resolve(strict=True))
oracle = Path(sys.argv[2]).resolve(strict=True)
expected_digest = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"


def run(*args, code, stdout=subprocess.PIPE):
    result = subprocess.run(
        [exe, *(os.fsencode(arg) for arg in args)],
        stdout=stdout,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert result.returncode == code, (args, code, result)
    return result


def report(source, baseline, code, status, error=None, difference=None):
    result = run(
        "verify", source, "--manifest", baseline, "--format", "json", code=code
    )
    assert not result.stderr, result
    value = json.loads(result.stdout)
    assert value["schema"] == "exacopy.cli.verify" and value["schema_version"] == "1.0", value
    assert value["result"] == status, value
    assert value["complete"] is (status != "inconclusive"), value
    if error:
        assert value["error"]["code"] == error, value
    if difference:
        assert value["difference"]["kind"] == difference, value
    if value["complete"]:
        facts = {
            "consistency": "live_observed",
            "algorithm": "blake3-256",
            "metadata": "explicitly_omitted",
            "baseline_authentication": "unsigned",
        }
        assert all(value[key] == item for key, item in facts.items()), value
        assert value["length"].isascii() and value["length"].isdecimal(), value
    return value


def assert_rebound_selection_is_stale(source, baseline, move, replacement):
    # Wait for the actual target capability to be open. The baseline has
    # already been decoded at that point. The scratch file is sparse but the
    # full logical extent keeps the target descriptor alive while we pause.
    command = [exe, b"verify", source, b"--manifest", baseline, b"--format", b"json"]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            descriptor_dir = os.fsencode(f"/proc/{process.pid}/fd")
            deadline = time.monotonic() + 5
            wanted = os.path.realpath(source)
            while process.poll() is None and time.monotonic() < deadline:
                for fd in os.listdir(descriptor_dir):
                    try:
                        target = os.readlink(os.path.join(descriptor_dir, fd))
                    except FileNotFoundError:
                        continue
                    if target == wanted:
                        break
                else:
                    time.sleep(0.001)
                    continue
                break
            else:
                raise AssertionError("target capability was never observed open")
            process.send_signal(signal.SIGSTOP)
            while time.monotonic() < deadline:
                _, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
                if os.WIFSTOPPED(status):
                    break
                if process.poll() is not None:
                    raise AssertionError("verification completed before controlled rename")
                time.sleep(0.001)
            else:
                raise AssertionError("verification process did not stop")
            retained = os.fsencode(move) + b".retained"
            os.rename(move, retained)
            os.rename(replacement, move)
            process.send_signal(signal.SIGCONT)
            output, errors = process.communicate(timeout=10)
            assert process.returncode == 3 and not errors, (output, errors)
            value = json.loads(output)
            assert value["result"] == "inconclusive" and not value["complete"], value
            assert value["error"]["code"] == "E_MANIFEST_STALE", value
            assert os.path.exists(retained) and os.path.exists(move)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


with tempfile.TemporaryDirectory(prefix="exacopy-manifest-probe-") as directory:
    scratch = os.fsencode(directory)
    left = os.path.join(scratch, b"left")
    right = os.path.join(scratch, b"right")
    manifests = os.path.join(scratch, b"baseline")
    for parent in (left, right, manifests):
        os.mkdir(parent)

    raw_name = b"leading\xff-and-\x1b.bin"
    source = os.path.join(left, raw_name)
    equivalent = os.path.join(right, raw_name)
    baseline = os.path.join(manifests, b"captured.json")
    for path in (source, equivalent):
        with open(path, "wb") as output:
            output.write(b"abc")
        os.chmod(path, 0o444)

    result = run("manifest", "create", source, code=0)
    assert not result.stderr and result.stdout.endswith(b"\n"), result
    created = json.loads(result.stdout)
    body = created["body"]
    assert body["schema_version"] == "1.0" and body["complete"], body
    assert body["algorithm"] == "blake3-256" and body["consistency"] == "live_observed", body
    assert body["entries"][0]["metadata_ref"] is None, body
    entry = body["entries"][0]
    assert entry["file_type"] == "regular", entry
    assert entry["streams"] == [{
        "name_raw_base64": "",
        "length": "3",
        "algorithm": "blake3-256",
        "digest": expected_digest,
    }], entry
    component, = entry["path"]["components"]
    assert component["encoding"] == "unix_bytes", component
    assert base64.b64decode(component["raw_base64"], validate=True) == raw_name, component
    assert "display" not in entry["path"]
    assert uuid.UUID(body["manifest_id"]).version == 4, body
    assert uuid.UUID(entry["path"]["root_id"]).version == 4, body
    assert body["manifest_id"] != entry["path"]["root_id"], body
    assert "signature" not in created, created
    with open(baseline, "wb") as destination:
        destination.write(result.stdout)
    os.chmod(baseline, 0o444)
    report(source, baseline, 0, "verified")
    report(equivalent, baseline, 0, "verified")
    human = run("verify", source, "--manifest", baseline, "--format", "human", code=0)
    assert b"unsigned BLAKE3 baseline" in human.stdout and b"\x1b" not in human.stdout, human
    print("create, standard abc digest, raw-name preservation, independent v4 IDs, exact verify and logical root remapping")

    os.chmod(equivalent, 0o644)
    with open(equivalent, "wb") as destination:
        destination.write(b"abd")
    result = report(equivalent, baseline, 5, "mismatch", difference="digest")
    assert result["difference"]["expected"] == expected_digest, result
    assert result["difference"]["observed"] != expected_digest, result
    with open(equivalent, "wb") as destination:
        destination.write(b"abcd")
    result = report(equivalent, baseline, 5, "mismatch", difference="length")
    assert result["difference"] == {
        "kind": "length", "expected": "3", "observed": "4"
    }, result
    print("stable equal-length digest and length mismatches use exit 5")

    unknown = os.path.join(scratch, b"wrong\x1b-basename")
    report(unknown, baseline, 2, "inconclusive", error="E_MANIFEST_SCOPE")
    human = run("verify", unknown, "--manifest", baseline, "--format", "human", code=2)
    assert not human.stdout and b"\x1b" not in human.stderr, human

    malformed = os.path.join(manifests, b"malformed.json")
    with open(malformed, "wb") as destination:
        destination.write(b"invalid\x1b")
    report(unknown, malformed, 2, "inconclusive", error="E_MANIFEST_INVALID")
    result = report(source, os.path.join(manifests, b"absent.json"), 2, "inconclusive", error="E_MANIFEST_INVALID")
    assert result["error"]["os_code"] == "2", result
    oversized = os.path.join(manifests, b"oversized.json")
    with open(oversized, "wb") as destination:
        destination.write(b" " * (16 * 1024 + 1))
    report(source, oversized, 2, "inconclusive", error="E_MANIFEST_INVALID")

    attack = os.path.join(manifests, b"invalid-digest.json")
    created["digest"] = "00" * 32
    with open(attack, "w", encoding="utf8") as destination:
        json.dump(created, destination)
    report(source, attack, 5, "inconclusive", error="E_MANIFEST_INTEGRITY")
    # The raw basename is correct, but opening the independently selected
    # target would fail. The baseline integrity decision comes first.
    unopened = os.path.join(scratch, b"unopened-parent", raw_name)
    report(unopened, attack, 5, "inconclusive", error="E_MANIFEST_INTEGRITY")
    assert not os.path.exists(os.path.dirname(unopened))
    print("raw scope mismatch, output redaction, missing, oversized, malformed and digest-invalid baselines refuse")

    baseline_link = os.path.join(manifests, b"linked")
    os.symlink(baseline, baseline_link)
    report(source, baseline_link, 6, "inconclusive", error="E_MANIFEST_UNSUPPORTED")
    os.unlink(equivalent)
    os.mkfifo(equivalent)
    report(equivalent, baseline, 6, "inconclusive", error="E_MANIFEST_UNSUPPORTED")
    os.unlink(equivalent)
    os.symlink(source, equivalent)
    report(equivalent, baseline, 6, "inconclusive", error="E_MANIFEST_UNSUPPORTED")

    empty = os.path.join(left, b"\xff.bin")
    with open(empty, "wb"):
        pass
    report(empty, oracle / "empty-nonutf8.json", 0, "verified")
    embedded = os.path.join(left, b"prefix-\xff-suffix.bin")
    with open(embedded, "wb") as destination:
        destination.write(b"abc")
    report(embedded, oracle / "embedded-nonutf8.display-input.json", 0, "verified")
    print("native symlinks and FIFO refuse; CLI accepts independent empty, raw-name and display annotation oracle fixtures")

    big = os.path.join(right, raw_name)
    os.unlink(big)
    with open(big, "wb") as output:
        output.truncate(128 * 1024 * 1024)
    baseline_replacement = os.path.join(manifests, b"replacement")
    with open(baseline, "rb") as original, open(baseline_replacement, "wb") as output:
        output.write(original.read())
    assert_rebound_selection_is_stale(big, baseline, baseline, baseline_replacement)
    target_replacement = os.path.join(right, b"replacement")
    with open(target_replacement, "wb") as output:
        output.truncate(128 * 1024 * 1024)
    assert_rebound_selection_is_stale(big, baseline, big, target_replacement)
    print("controlled byte-identical baseline and target rebindings during observation both refuse with exit 3")

    with open("/dev/full", "wb", buffering=0) as output:
        result = run("manifest", "create", source, code=4, stdout=output)
        assert b"could not write the manifest baseline (OS error 28)" in result.stderr, result
        result = run("verify", source, "--manifest", baseline, "--format", "json", code=4, stdout=output)
        assert b"could not write the verification result (OS error 28)" in result.stderr, result

    with open(source, "rb") as input_file:
        assert input_file.read() == b"abc"
    print("I/O output failure uses exit 4, source bytes preserved")
