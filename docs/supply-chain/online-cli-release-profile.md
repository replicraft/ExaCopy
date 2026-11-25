# GitHub CLI release archive profile

This profile delivers the [offline signed CLI bundle](offline-release-profile.md)
through the GitHub Releases service for `replicraft/ExaCopy`. It uses the
existing user-scoped install and uninstall paths. Distribution packaging and
installer tests establish their own evidence. Each operation exposed by the
shipped CLI must separately meet its qualification requirements.

The online install uses a trusted checkout of the installer scripts and their
helper files. Before running them, obtain and approve the publisher's DER
certificate and its lowercase SHA-256 fingerprint independently. ExaCopy has
yet to issue production trust material. An ephemeral CI publisher applies only
to its own fixture.

Supply the certificate and fingerprint through `--publisher-cert` and
`--publisher-sha256` on POSIX, or `-PublisherCert` and `-PublisherSha256` on
Windows. Omit the offline bundle argument to select the latest release. Use
`--dry-run` or `-DryRun` to verify the selection without publishing to the
installation root.

Online POSIX installation uses the current supported host's `/usr/bin/curl`
and `/usr/bin/perl` with `IO::Uncompress::Gunzip`. Windows uses PowerShell
7.4 or newer and .NET's HTTP client. Keep the host HTTP/TLS runtime current.

## Resolve one release

Send an HTTPS `HEAD` request to
`https://github.com/replicraft/ExaCopy/releases/latest` with redirects disabled.
Accept an HTTP 302 location only for the exact same repository's
`/replicraft/ExaCopy/releases/tag/vMAJOR.MINOR.PATCH` path. Absolute redirects
must use `https://github.com`. The latest route selects the published stable
release once. The version components use the offline profile's canonical
decimal grammar and 999999 ceiling. The first tag under this grammar is
`v0.1.0` for workspace version `0.1.0`. The tag, checked-out release source and
signed inner descriptor must agree on the version. The release provenance
binds the exact source commit and artifact digest. [GitHub release links](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases)

Build the asset URLs from the validated tag and fixed asset basenames under
`https://github.com/replicraft/ExaCopy/releases/download/<tag>/`. Fetch the
checksum list and archive from that same tag. The requests require TLS 1.2 or
newer and admit at most 16 KiB of response headers. GitHub may serve downloads
via one HTTPS 302 per asset to `release-assets.githubusercontent.com` or
`objects.githubusercontent.com`. Missing releases, missing requested assets,
malformed metadata, invalid tags, broken redirects and failed downloads all
end the attempt. An explicit expected version must match the resolved
release. The existing explicit version and local bundle parameters select
offline installation.

## Names and contents

| Native target | Release asset | Executable member |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `exacopy-cli-x86_64-unknown-linux-gnu.tar.gz` | `exacopy` |
| `aarch64-unknown-linux-gnu` | `exacopy-cli-aarch64-unknown-linux-gnu.tar.gz` | `exacopy` |
| `aarch64-apple-darwin` | `exacopy-cli-aarch64-apple-darwin.tar.gz` | `exacopy` |
| `x86_64-apple-darwin` | `exacopy-cli-x86_64-apple-darwin.tar.gz` | `exacopy` |
| `x86_64-pc-windows-msvc` | `exacopy-cli-x86_64-pc-windows-msvc.zip` | `exacopy.exe` |
| `aarch64-pc-windows-msvc` | `exacopy-cli-aarch64-pc-windows-msvc.zip` | `exacopy.exe` |

The table defines admissible target names. The initial release candidate matrix
covers Linux x86-64 GNU, macOS ARM64 and Windows x86-64 MSVC. Advertise only
assets whose native build, installation and product operation evidence clears
the applicable release gates.

Each archive contains exactly three flat regular file members with exact
case-sensitive paths. They are the executable member named in the table,
`release.manifest` and `release.sig`. The archive is gzip-compressed USTAR or
ZIP as named in the table. The producer uses one gzip member with a zeroed
timestamp and no optional header fields. ZIP production uses stored entries
with regular-file attributes and omits extra fields, ZIP64 and comments.
Archive parsing refuses duplicate and unexpected entries, directories,
alternate paths, special entries and links. Extraction must create only the
three expected filenames as regular files under a private directory. Select
publication metadata through the existing installer lifecycle.

The compressed archive is bounded to 269484032 bytes. Each extracted member
has a positive length. The executable is bounded to 268435456 bytes, the
manifest to 4096 bytes, and the detached signature to 1024 bytes. Check
declared bounds when the container exposes them and enforce bounds while
reading or extracting the actual bytes.

## Archive checksum and publisher signature

Attach one `SHA256SUMS.txt` to the release. It is at most 4096 bytes and
contains one row per published CLI archive, sorted by basename in ASCII byte
order. Each row contains an exact 64-character lowercase hexadecimal SHA-256,
two ASCII spaces, an asset basename from the table, and an LF. At least one
row is required. A BOM, CR, blank line, missing LF, duplicate basename or
unknown name invalidates the list. Calculate each hash on the full compressed
archive bytes. Verify the selected file's hash before extraction.

The GitHub checksum list provides transport integrity. The detached signature
within the archive provides publisher authentication under the independently
approved DER certificate and fingerprint. The offline v1 verifier checks
the signature, stable channel, validity window, target, selected version,
OS and ABI floors, and raw executable size and SHA-256. File names and
download location supply no installation authority. Bound downloads and
extract with the expectation that the archive can be untrusted. Failed
checksum, archive or publisher verification blocks installation before
publication. Installation publishes a versioned executable and reports its
path. The installer never executes the downloaded payload.

Attach `exacopy-cli-<target>.cdx.json` and
`exacopy-cli-<target>.provenance.json` for every released target. The signed
manifest's `sbom_sha256` and `provenance_sha256` fields bind the exact bytes of
those two attachments respectively. Release packaging checks both digests.
The installer authenticates the embedded manifest and binary. A separate
release verification inspects the SBOM and provenance documents.

## Host and ownership

The signed floors and current host checks apply together. The baseline is
macOS 14.0 on native ARM64 or x86-64, Linux kernel 5.15 with glibc 2.35 on
native ARM64 or x86-64, or Windows build 22000 desktop / 20348 server on
native ARM64 or x86-64. Use the platform's published target only if a signed
release asset exists for it. A release built against a newer runtime declares
the higher floor and is tested there. A recent runner alone cannot establish
compatibility with an older floor.

- macOS installs under
  `$HOME/Library/Application Support/ExaCopy/install/versions/<version>/exacopy`.
- Linux installs under
  `${XDG_DATA_HOME:-$HOME/.local/share}/exacopy/install/versions/<version>/exacopy`.
- Windows installs under
  `%LOCALAPPDATA%\Programs\ExaCopy\versions\<version>\exacopy.exe`.

POSIX accepts an explicit eligible install root under the owner's home and
retains its sequence and manifest digest across uninstall. Windows admits
one owner-bound signed release identity in its root and retains the root's
signed evidence across uninstall. A later release cannot replace the
retained identity through this profile. A fresh root has no previous release
history. A valid older release within its signed lifetime can satisfy latest
resolution if GitHub points to it. An independently chosen expected
version gives the caller a stronger version constraint.

Publication, idempotence, conflict handling, and uninstall follow the raw
offline installers. User scope reports an explicit versioned path for
direct invocation and requires no PATH, service, or system registration.
Uninstall selects an exact local version and requires operator quiescence.
Profiles, repositories, credentials, journals, recovery files and unrelated
entries are outside the installation's ownership.

## Release evidence

R-190–192, R-307–310 and their matching acceptance cases cover unsigned rebuild
evidence, release gate refusals, signed packaging and installer admission.
The distribution slice applies INV-002, INV-009, INV-013, INV-019, INV-029
and INV-032 to staging, bounds, signature decisions, ownership and evidence.
R-312/A-312 continues to govern preservation on uninstall.

Candidate CI uses pinned tooling, locked dependencies and fixed source commit.
Record exact target, source/lockfile/toolchain, tested floor, signed bundle
identity, archive and checksum digests, SBOM and provenance. Candidate fixtures
can exercise downloaded archive verification and same-platform installation
with an ephemeral signature, including corrupted checksum, malformed archive,
wrong target or version, signature refusal and preserved incumbent tests.

Before production publication, provide owner-authorized signing and out-of-band
trust provisioning, exact SBOM/provenance documents bound by the manifests,
and actual passing release evidence for each advertised asset and operation.
For successive releases, assign monotonically increasing signed sequences and
choose a validity window that covers intended availability. Keep each admitted
manifest and archive byte-identical for the lifetime of its tag. A new expiry
or changed payload requires signing and publishing a new version.
Prepare a draft for the exact release commit and complete its asset set before
publication. Enable GitHub release immutability so that publication locks the
tag and release assets. The latest pointer can subsequently select a different
authorized release. [GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)

Native platform signatures, lowest-floor execution, signed distribution,
independent reproducibility and real process-crash or power-loss qualification
each require their own evidence before claiming the corresponding property.
