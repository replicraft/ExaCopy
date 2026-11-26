from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import remote_commissioning_wireguard_dispatch as dispatch
from remote_commissioning_wireguard_provider_b_test import observed as azure_observation
from remote_commissioning_wireguard_enrollment_test import AZURE, AWS, AWS_1014, observation
from remote_commissioning_wireguard_provider_profiles import AZURE_1017, AZURE_1020, DispatchMode

azure = dispatch.azure
REVISION = "a" * 40


class DispatcherControls(unittest.TestCase):
    def test_exact_profile_is_the_only_activation_selection(self):
        known = azure_observation() | {"revision": REVISION}
        self.assertIs(dispatch.select(known, REVISION)[0], DispatchMode.AZURE_1017)
        for key, status in (("provider", "unknown"), ("provider", "already-live"), ("revision", "b" * 40)):
            self.assertIs(dispatch.select(known | {key: status}, REVISION)[0], DispatchMode.BLOCKED)
        changed = deepcopy(known)
        changed["observations"]["module_file"]["sha256"] = "0" * 64
        self.assertIs(dispatch.select(changed, REVISION)[0], DispatchMode.BLOCKED)
        reviewed = azure_observation(AZURE_1020) | {"revision": REVISION}
        self.assertIs(dispatch.select(reviewed, REVISION)[0], DispatchMode.AZURE_1020)
        self.assertIs(dispatch.select(observation(AZURE), REVISION)[0], DispatchMode.BLOCKED)
        for status in ("packaged-but-unloaded", "unknown"):
            selected = observation(AWS) | {"provider": status}
            self.assertIs(dispatch.select(selected, REVISION)[0], DispatchMode.OBSERVE)
            changed = deepcopy(selected)
            changed["kernel"]["build"] += "-other"
            self.assertIs(dispatch.select(changed, REVISION)[0], DispatchMode.BLOCKED)

    def test_single_same_boot_dispatch_uses_nonpassing_readonly_disposition(self):
        known = azure_observation() | {"revision": REVISION}
        for selected, expected, exit_status, drift in (
            (known, DispatchMode.AZURE_1017, 0, False),
            (known, DispatchMode.BLOCKED, 77, True),
            (observation(AWS), DispatchMode.OBSERVE, 77, False),
            (observation(AWS_1014), DispatchMode.OBSERVE, 77, False),
            (observation(AWS_1014), DispatchMode.BLOCKED, 77, True),
            (azure_observation(AZURE_1020) | {"revision": REVISION}, DispatchMode.AZURE_1020, 0, False),
            (azure_observation(AZURE_1020) | {"revision": REVISION}, DispatchMode.BLOCKED, 77, True),
            (observation(AZURE), DispatchMode.BLOCKED, 77, False),
            (known | {"provider": "unknown"}, DispatchMode.BLOCKED, 77, False),
        ):
            with self.subTest(expected=expected, record=selected["kernel"], drift=drift), tempfile.TemporaryDirectory() as scratch:
                parent = Path(scratch).resolve()
                output = parent / "output"
                output.touch()
                refusal = dispatch.Blocked("wrong boot") if drift else None
                with (
                    patch.dict(os.environ, {"GITHUB_SHA": REVISION, "GITHUB_RUN_ID": "123",
                                            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_OUTPUT": str(output)}),
                    patch.object(azure, "hosted_scope"),
                    patch.object(dispatch.provider, "hosted_admission", return_value=parent),
                    patch.object(dispatch.direct, "hosted_parent", return_value=parent),
                    patch.object(dispatch.direct.native, "source_identity", return_value={"revision": REVISION}),
                    patch.object(dispatch.provider, "report", return_value=selected) as observe,
                    patch.object(azure, "recheck_boot", side_effect=refusal),
                    patch.object(dispatch.enrollment, "same_boot", side_effect=refusal),
                    patch.object(dispatch.enrollment, "main", return_value=0) as enrollment,
                ):
                    self.assertEqual(dispatch.main(), exit_status)
                    observe.assert_called_once()
                    if expected is DispatchMode.OBSERVE:
                        enrollment.assert_called_once_with(dispatch.enrollment.EnrollmentContext.PROVIDER_B_OBSERVATION, selected)
                    else:
                        enrollment.assert_not_called()
                    self.assertEqual(output.read_text(), f"mode={expected.value}\n")
                    directory = parent / dispatch.provider.REPORT
                    record = json.loads((directory / azure.DISPATCH_RECORD).read_text())
                    self.assertEqual(record["kernel"], selected["kernel"])
                    self.assertEqual(record["provider_observation_sha256"], sha256((directory / "provider.json").read_bytes()).hexdigest())
                    self.assertFalse(record["qualified"])
                    self.assertFalse(record["load_attempted"])
                    profile = azure.known_profile(selected["kernel"])
                    if expected in (DispatchMode.AZURE_1017, DispatchMode.AZURE_1020):
                        self.assertEqual(azure.verify_dispatch(parent, profile, selected["kernel"]), record)
                        with self.assertRaises(dispatch.Blocked):
                            foreign = AZURE_1020 if profile is AZURE_1017 else AZURE_1017
                            azure.verify_dispatch(parent, foreign, selected["kernel"])
                        with self.assertRaises(dispatch.Blocked):
                            azure.verify_dispatch(parent, profile, selected["kernel"] | {"boot_id": "different"})
                        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}), self.assertRaises(dispatch.Blocked):
                            azure.verify_dispatch(parent, profile, selected["kernel"])
                        (directory / "provider.json").write_text("altered evidence")
                        with self.assertRaises(dispatch.Blocked):
                            azure.verify_dispatch(parent, profile, selected["kernel"])
                    else:
                        with self.assertRaises(dispatch.Blocked):
                            azure.verify_dispatch(parent, profile, selected["kernel"])

    def test_observation_context_requires_closed_launch_and_matched_snapshot(self):
        enrollment = dispatch.enrollment
        snapshot = observation(AWS)
        context = enrollment.EnrollmentContext.PROVIDER_B_OBSERVATION
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch)
            with (
                patch.dict(os.environ, {"GITHUB_SHA": REVISION, "GITHUB_WORKFLOW_SHA": REVISION,
                                        "GITHUB_WORKFLOW_REF": azure.WORKFLOW_REF}),
                patch.object(dispatch.provider, "hosted_admission", return_value=parent),
                patch.object(dispatch.direct, "hosted_parent", return_value=parent) as hosted,
                patch.object(dispatch.direct.native, "source_identity", return_value={"revision": REVISION}),
                patch.object(enrollment.signal, "signal"),
                patch.object(enrollment, "collect") as collect,
            ):
                with self.assertRaises(dispatch.Blocked):
                    enrollment.main()
                with self.assertRaises(dispatch.Blocked):
                    enrollment.main(context)
                self.assertEqual(enrollment.main(context, snapshot), 0)
                self.assertEqual(hosted.call_args.args, (azure.DISPATCH_PROGRAM, ("push",)))
                self.assertEqual(collect.call_args.args[4], snapshot)
                collect.assert_called_once()
                record = json.loads((parent / enrollment.JOB / "report/provider.json").read_text())
                self.assertEqual(record["context"], context.value)
                self.assertFalse(record["qualified"])

    def test_selection_output_refuses_foreign_symlink_or_nonempty_file(self):
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch).resolve()
            real = parent / "real"
            real.write_text("pre-existing")
            link = parent / "link"
            link.symlink_to(real)
            for path in (real, link, parent.parent / "foreign"):
                with patch.dict(os.environ, {"GITHUB_OUTPUT": str(path)}), self.assertRaises(dispatch.Blocked):
                    dispatch.write_mode(parent, DispatchMode.AZURE_1017)
            self.assertEqual(real.read_text(), "pre-existing")

    def test_workflow_literal_gates_every_commissioning_effect(self):
        path = Path(__file__).resolve().parent.parent / "workflows/linux-remote-wireguard-provider-b.yml"
        workflow = path.read_text()
        literal = ("if: (steps.provider.outputs.mode == 'commission-azure-1017' || "
                   "steps.provider.outputs.mode == 'commission-azure-1020')")
        for name in ("Prepare pinned sources and Rust", "Stage bounded independent fixture tools",
                     "Verify the Azure module closure and commission the ordinary embedded CLI"):
            self.assertIn(f"      - name: {name}\n        {literal}\n", workflow)
        self.assertIn(f"if: always() && {literal.removeprefix('if: ')}", workflow)
        for pin in (AZURE_1017, AZURE_1020):
            self.assertIn(f"{pin.mode.value}) module_package='{pin.package}={pin.version}' ;;", workflow)
        for artifact in ("dispatch.json", "Release.gpg", "Packages.xz", "exacopy-wireguard-enrollment.pending",
                         "exacopy-wireguard-provider-b-tools.pending"):
            self.assertIn(artifact, workflow)


if __name__ == "__main__":
    unittest.main()
