#!/usr/bin/env python3
"""Collect fixed hosted kernel evidence for review without loading modules."""

from dataclasses import asdict, dataclass
from enum import Enum
from lzma import LZMAError
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile

import remote_commissioning as direct
from remote_commissioning_peer import Blocked, checkpoint
import remote_commissioning_wireguard_provider as provider
import remote_commissioning_wireguard_provider_b as parsing
from native_supervision import CleanupUnconfirmed, interrupted, write_json
import wireguard_enrollment_archive as archive

PROGRAM = "remote_commissioning_wireguard_enrollment.py"
WORKFLOW_REF = "replicraft/ExaCopy/.github/workflows/linux-remote-wireguard-enrollment.yml@refs/heads/main"
JOB = "exacopy-wireguard-enrollment"
PENDING = f"{JOB}.pending"
SHA256 = re.compile(r"[a-f0-9]{64}")
MOD_PATHS = {
    "wireguard": "kernel/drivers/net/wireguard/wireguard.ko.zst",
    "udp_tunnel": "kernel/net/ipv4/udp_tunnel.ko.zst",
    "ip6_udp_tunnel": "kernel/net/ipv6/ip6_udp_tunnel.ko.zst",
    "libcurve25519": "kernel/lib/crypto/libcurve25519.ko.zst",
}


@dataclass(frozen=True)
class Candidate:
    tag: str
    release: str
    build: str
    version: str
    cloud: str
    known_hashes: tuple[str, ...] = ()

    def image(self):
        return f"linux-image-{self.release}"

    def module_package(self):
        return f"linux-modules-{self.release}"

    def package_record(self, name):
        return {"package": name, "version": self.version, "architecture": "amd64"}

    def expected_packages(self):
        return {
            name: (self.version, f"pool/main/l/{prefix}-{self.cloud}-7.0/{name}_{self.version}_amd64.deb")
            for name, prefix in ((self.image(), "linux-signed"), (self.module_package(), "linux"))
        }

    def config(self):
        return Path(f"/boot/config-{self.release}")

    def builtin(self):
        return Path(f"/lib/modules/{self.release}/modules.builtin")

    def modules(self):
        return {name: Path(f"/lib/modules/{self.release}") / suffix for name, suffix in MOD_PATHS.items()}


CANDIDATES = (
    # Hosted provider observation from run 45879217518 at 415f557.
    Candidate(
        "aws-1014", "7.0.0-1014-aws", "#14~24.04.1-Ubuntu SMP PREEMPT Fri Sep 18 21:24:59 UTC 2026",
        "7.0.0-1014.14~24.04.1", "aws",
        (
            "5b62bbad5d3b8defbf86f42bcd5851b1ea7305928346263eecc1b975ab07f04d",
            "e6f4ea792c1576e1408324dcb00b15c7c1bc0c7dd0e9f93fdbe5203f7031b0b0",
            "e3d9d233acdd46e198473f6f007fb70ee8e1e98fa8da8ef39b871bec14813586",
        ),
    ),
    Candidate(
        "aws-1018", "7.0.0-1018-aws", "#19~24.04.1-Ubuntu SMP PREEMPT Thu Nov 12 17:17:32 UTC 2026",
        "7.0.0-1018.19~24.04.1", "aws",
        (
            "ceb67b03057b87bae01721ffea153ef042d39a9e2b894d200a20047ea2a417c5",
            "1545f931aa703759852995e1ab20770c943de95f54f13c0e20808dc12b8e830e",
            "24f9bef455a7b4a9839b236bf22c77e7d1351f33dcfdca504100fe1c29924791",
        ),
    ),
    Candidate(
        "azure-1020", "7.0.0-1020-azure", "#21~24.04.2-Ubuntu SMP PREEMPT Tue Nov 10 01:36:36 UTC 2026",
        "7.0.0-1020.21~24.04.2", "azure",
    ),
)


def selected(observed):
    kernel = observed.get("kernel", {})
    boot = kernel.get("boot_id")
    if observed.get("schema") != provider.SCHEMA or not isinstance(boot, str) or not re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot,
    ):
        raise Blocked("provider observation lacks its exact native boot identity")
    for candidate in CANDIDATES:
        if kernel == {
            "release": candidate.release, "build": candidate.build, "architecture": "x86_64", "boot_id": boot,
        }:
            return candidate
    raise Blocked("hosted boot did not select a fixed enrollment candidate")


def provider_hashes(observed, candidate, revision):
    facts = observed.get("observations", {})
    if (
        observed.get("revision") != revision or selected(observed) != candidate
        or observed.get("provider") != "packaged-but-unloaded"
        or facts.get("booted_kernel_package") != candidate.package_record(candidate.image())
        or facts.get("module_listing_before", {}).get("status") != "absent"
        or facts.get("module_listing_after", {}).get("status") != "absent"
        or facts.get("module_initstate", {}).get("status") != "missing"
    ):
        raise Blocked("exact signed kernel package ownership or unloaded observation is unavailable")
    result = {}
    record = candidate.package_record(candidate.module_package())
    for field, path, status in (
        ("config", candidate.config(), "module"),
        ("builtin_inventory", candidate.builtin(), "absent"),
        ("module_file", candidate.modules()["wireguard"], "packaged"),
    ):
        fact = facts.get(field, {})
        digest = fact.get("sha256")
        if fact.get("status") != status or not isinstance(digest, str) or not SHA256.fullmatch(digest) or any(
            fact.get(key) != value for key, value in record.items()
        ):
            raise Blocked("candidate provider fingerprint lacks exact installed package binding")
        result[path] = digest
    if candidate.known_hashes and tuple(result.values()) != candidate.known_hashes:
        raise Blocked("candidate provider fingerprints differ from retained independent observations")
    return result


def same_boot(kernel):
    native = os.uname()
    if (
        native.sysname != "Linux" or native.release != kernel["release"] or native.version != kernel["build"]
        or native.machine != "x86_64" or provider.boot_id() != kernel["boot_id"]
    ):
        raise Blocked("hosted boot changed during read-only enrollment")


def module_metadata(work, candidate, name, path, digest):
    probe = {}
    for field in ("name", "depends", "vermagic", "signer", "sig_id"):
        value = parsing.read_command(work, "candidate ELF module metadata", [parsing.MODINFO, "-F", field, "--", path])
        if not re.fullmatch(rb"[\x20-\x7e]{0,200}\n?", value):
            raise Blocked("malformed candidate ELF module metadata")
        probe[field] = value.decode("ascii").rstrip("\n")
    depends = probe["depends"].split(",") if probe["depends"] else []
    if (
        probe["name"] != name or not probe["vermagic"].startswith(candidate.release + " ")
        or not probe["signer"] or probe["sig_id"] != "PKCS#7" or len(depends) != len(set(depends))
        or any(dep not in MOD_PATHS for dep in depends)
    ):
        raise Blocked("candidate ELF module ABI, signer or dependency outside fixed inventory")
    return parsing.Module(name, digest, tuple(depends), probe["vermagic"], probe["signer"])


def order_modules(candidate, modules, plan):
    return parsing.closure_order(modules, plan, candidate.modules())


def check_selected_archive(work, candidate, signed, fingerprints, evidence):
    package = work / "modules.deb"
    bound = archive.Extent(signed["size"], signed["sha256"])
    archive.fetch(f"/".join((archive.ORIGIN, signed["filename"])), package, 180, bound.size)
    original = archive.verify_blob(package, bound)
    control = parsing.read_command(work, "module archive control", [
        parsing.DPKG_DEB, "--show", "--showformat=${Package}\\t${Version}\\t${Architecture}\\n", package,
    ])
    if control != f"{candidate.module_package()}\t{candidate.version}\tamd64\n".encode():
        raise Blocked("module archive control differs from the signed package index")
    tar = work / "package.tar"
    archive.bounded([parsing.DPKG_DEB, "--fsys-tarfile", package], tar, 45, parsing.TAR_BYTES)
    if parsing.regular(package, os.geteuid(), bound.size) != original:
        raise Blocked("authenticated module archive changed during extraction")
    stage = work / "members"
    stage.mkdir(mode=0o700)
    paths = candidate.modules()
    staged = parsing.extract_selected(tar, stage, (candidate.config(), candidate.builtin(), *paths.values()))
    members = evidence["members_sha256"] = {}
    metadata = evidence["elf"] = []
    modules = {}
    for path, held in staged.items():
        checkpoint()
        digest = parsing.checked_hash(held, os.geteuid(), parsing.MODULE_BYTES)
        installed = provider.from_kernel_package(
            path, candidate.release, candidate.version, parsing.MODULE_BYTES, lambda _: "packaged",
        )
        binding = candidate.package_record(candidate.module_package())
        if installed["status"] != "packaged" or any(installed.get(key) != binding[key] for key in binding):
            raise Blocked("archive member lacks exact installed kernel package ownership")
        if installed["sha256"] != digest or (path in fingerprints and fingerprints[path] != digest):
            raise Blocked("archive member bytes differ from installed package or provider fact")
        members[str(path)] = digest
        name = next((name for name in paths if paths[name] == path), None)
        if name is not None:
            module = module_metadata(work, candidate, name, held, digest)
            modules[name] = module
            metadata.append(asdict(module))
    empty = work / "kmod-empty.conf"
    empty.touch(mode=0o600, exist_ok=False)
    plan = parsing.read_command(work, "read-only candidate kmod dependency plan", [
        parsing.MODPROBE, "--show-depends", f"--config={empty}", f"--set-version={candidate.release}", "--", "wireguard",
    ])
    evidence["kmod_plan_sha256"] = provider.digest(plan)
    evidence["kmod_order"] = order_modules(candidate, modules, plan)
    evidence["kmod_plan"] = plan.decode("ascii").splitlines()


def collect(work, report, source, evidence, observed=None):
    if observed is None:
        observed = provider.report()
    evidence["provider_observation"] = observed
    candidate = selected(observed)
    evidence["candidate"] = candidate.tag
    kernel = observed["kernel"]
    same_boot(kernel)
    executables = (archive.CURL, archive.GPGV, parsing.DPKG_DEB, parsing.MODINFO, parsing.MODPROBE, provider.DPKG_QUERY)
    tools = {name: parsing.checked_hash(Path(name).resolve(strict=True), 0, 4 * 1024 * 1024) for name in executables}
    evidence["tools_sha256"] = tools
    packages, signed_inputs = archive.signed_index(work, evidence, candidate.expected_packages())
    # Keep exact Release/signature and verified index so review can reproduce the signature-to-record chain.
    for path, bound in signed_inputs.items():
        output = report / path.name
        pending = report / f".{path.name}.pending"
        shutil.copyfile(path, pending)
        archive.verify_blob(pending, bound)
        pending.replace(output)
    same_boot(kernel)
    fingerprints = provider_hashes(observed, candidate, source["revision"])
    check_selected_archive(work, candidate, packages[candidate.module_package()], fingerprints, evidence)
    latest = provider.report()
    evidence["provider_recheck"] = latest
    if latest["kernel"] != kernel or provider_hashes(latest, candidate, source["revision"]) != fingerprints:
        raise Blocked("candidate provider identity changed during read-only observation")
    if any(parsing.checked_hash(Path(path).resolve(strict=True), 0, 4 * 1024 * 1024) != sha for path, sha in tools.items()):
        raise Blocked("native evidence tool identity changed")
    same_boot(kernel)


class EnrollmentContext(Enum):
    STANDALONE = "standalone"
    PROVIDER_B_OBSERVATION = "provider-b-observation"


def main(context=EnrollmentContext.STANDALONE, observed=None):
    program, workflow = {
        EnrollmentContext.STANDALONE: (PROGRAM, WORKFLOW_REF),
        EnrollmentContext.PROVIDER_B_OBSERVATION: (parsing.DISPATCH_PROGRAM, parsing.WORKFLOW_REF),
    }[context]
    parent = provider.hosted_admission()
    if direct.hosted_parent(program, ("push",)) != parent or (
        os.environ.get("GITHUB_WORKFLOW_REF") != workflow
        or os.environ.get("GITHUB_WORKFLOW_SHA") != os.environ["GITHUB_SHA"]
    ):
        raise Blocked("candidate collection requires its exact canonical main push workflow")
    if (context is EnrollmentContext.PROVIDER_B_OBSERVATION) != (observed is not None):
        raise Blocked("enrollment context requires its exact observation origin")
    source = direct.native.source_identity(direct.native.REPO)
    if source["revision"] != os.environ["GITHUB_SHA"]:
        raise Blocked("candidate collection checkout differs from its hosted revision")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    checkpoint()
    pending = parent / PENDING
    write_json(pending, {"job": JOB, "source_revision": source["revision"]})
    job = parent / JOB
    job.mkdir(mode=0o700)
    report, work = job / "report", job / "private"
    report.mkdir(mode=0o700)
    marker = report / "cleanup-unconfirmed.json"
    write_json(marker, {"private_work": work.name})
    work.mkdir(mode=0o700)
    evidence = {
        "schema": "exacopy.hosted-wireguard-abi-enrollment-observation.v1",
        "source": source, "context": context.value,
        "commissioned": False, "qualified": False, "load_attempted": False,
    }
    uncertain = False
    try:
        if context is EnrollmentContext.STANDALONE:
            collect(work, report, source, evidence)
        else:
            collect(work, report, source, evidence, observed)
        checkpoint()
        evidence["status"] = "observed"
    except CleanupUnconfirmed:
        uncertain = True
        evidence["status"] = "blocked"
        evidence["reason"] = "an owned read-only subprocess group could not be confirmed drained"
    except (Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError, LZMAError) as error:
        evidence["status"] = "blocked"
        evidence["reason"] = str(error) if isinstance(error, Blocked) else type(error).__name__
    finally:
        if not uncertain:
            try:
                shutil.rmtree(work)
                marker.unlink()
                pending.unlink()
            except OSError:
                uncertain = True
                evidence["status"] = "blocked"
                evidence["reason"] = "owned collector scratch cleanup could not be confirmed"
        evidence["cleanup_unconfirmed"] = uncertain
        try:
            current = direct.native.source_identity(direct.native.REPO)
            evidence["source_recheck"] = current
        except (OSError, ValueError, subprocess.SubprocessError):
            current = None
        if current != source:
            evidence["status"] = "blocked"
            evidence["reason"] = "collector source recheck differed"
        provider.write_report(report, evidence)
    return 0 if evidence["status"] == "observed" else 77


if __name__ == "__main__":
    raise SystemExit(main())
