"""Portable receipt controls for the distinct hosted root-setup profile."""

from copy import deepcopy
import hashlib
import json
import os
import subprocess
import textwrap
import unittest

import run


class ReceiptControls(unittest.TestCase):
    def test_manifest_identifies_only_root_setup_profile(self):
        self.assertEqual(run.bind_manifest()["profile"], run.PROFILE)
        self.assertNotEqual(run.bind_manifest()["profile"], "linux-unprivileged-same-device-bind-v1")

    def test_receipt_requires_sealed_observer_identity_and_cleanup(self):
        digest = "a" * 64
        records = [
            {"role": "setup", "uid": 0, "prior_namespace": "mnt:[1]", "namespace": "mnt:[2]",
             "invocation": "c" * 32, "cgroup": run.RECEIPT_CGROUP},
            {"role": "observer", "namespace": "mnt:[2]", "sha256": digest,
             "invocation": "c" * 32, "cgroup": run.RECEIPT_CGROUP,
             "uids": [1001] * 4, "gids": [1001] * 4, "groups": [], "no_new_privs": 1,
             "caps": dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), 0)},
            {"role": "unmount", "covered_inode_preserved": True, "sentinels_preserved": True},
            {"role": "fixture_cleanup", "absent": True},
        ]

        def text(items):
            return "\n".join(map(json.dumps, items))

        self.assertEqual(run.check_receipt(text(records), digest, "mnt:[1]"), records)
        for index, key, value in [
            (0, "namespace", "mnt:[1]"), (1, "sha256", "b" * 64),
            (1, "uids", [0] * 4), (1, "groups", [1001]), (1, "no_new_privs", 0),
            (1, "caps", {"CapEff": 1}), (1, "invocation", "d" * 32), (0, "cgroup", "0::/wrong"), (2, "sentinels_preserved", False), (3, "absent", False),
        ]:
            with self.subTest(key=key):
                changed = deepcopy(records)
                changed[index][key] = value
                with self.assertRaises(RuntimeError):
                    run.check_receipt(text(changed), digest, "mnt:[1]")
        with self.assertRaises(RuntimeError):
            run.check_receipt(text(records[:-1]), digest, "mnt:[1]")


class WorkflowControls(unittest.TestCase):
    def test_preflight_requires_successful_clean_git_status(self):
        workflow = run.HERE.parents[4] / ".github/workflows/linux-protected-slot-root-setup.yml"
        preflight = workflow.read_text().split(
            "      - name: Verify clean canonical revision and pinned source\n", 1
        )[1]
        block = preflight.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
        script = textwrap.dedent(block)
        environment = {
            **os.environ,
            "GITHUB_SHA": "a" * 40,
            "REVIEWED_HELPER_SHA256": hashlib.sha256(b"pinned helper\n").hexdigest(),
        }
        for label, status, expected in (
            ("clean", "return 0", 0),
            ("failed with empty output", "return 42", 42),
            ("dirty", "printf ' M changed\\n'", 1),
        ):
            with self.subTest(status=label):
                stand_ins = textwrap.dedent(f"""\
                    git() {{
                      case "$1" in
                        rev-parse) printf '%s\\n' "$GITHUB_SHA" ;;
                        status) {status} ;;
                        show) printf 'pinned helper\\n' ;;
                        *) return 90 ;;
                      esac
                    }}
                    sha256sum() {{
                      python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
                    }}
                    """)
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail"],
                    input=stand_ins + script,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
