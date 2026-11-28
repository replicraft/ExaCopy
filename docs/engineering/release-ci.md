# CLI release workflow

Dispatch **CLI release** on an existing canonical `vMAJOR.MINOR.PATCH` tag
whose commit carries this workflow and the matching Cargo CLI version.
Signed publication currently refuses any tag with an existing GitHub release
or draft. The `v0.1.0` tag already identifies the unsigned
[testing prerelease](../releases/v0.1.0.md). Promoting or replacing it
requires a separate release-lifecycle change.

GitHub's dispatch API accepts a tag as the ref. The default `publish=false`
uses an ephemeral fixture certificate for each of the three archive targets.
The workflow tests the generated candidate archives and keeps the unsigned
CLI, build record, SBOM and fixture evidence as Actions artifacts. Rerun
all jobs when retrying because downstream jobs require the same run attempt.

The Linux x64 release-default workspace suite runs on Ubuntu 24.04 at the
candidate tag's exact commit. The Linux GNU archive build, glibc 2.35 ABI
check, and installed launcher checks run on Ubuntu 22.04. The release gates
require both sets of Linux evidence. The macOS ARM64 and Windows x64 jobs
run their workspace and archive checks on macOS 15 and Windows Server 2025,
respectively. Hosted runs retain exact runner versions, package verification
and available native CLI smoke results. Release reviewers must check operation
and runtime-floor evidence for the advertised profiles, including the Windows
install lifecycle and any lower OS or ABI floor. The default Windows CLI
currently exercises an explicit-refusal profile. A signature verification pass
establishes publisher identity and artifact integrity for the tested profile.

## Protected production environments

Configure required reviewers and release-tag deployment restrictions on the
four named environments. Use a tag ruleset that restricts creation and
prevents changes to release tags. Enable GitHub immutable releases. Reviewers
approve the exact source, signed binaries, SBOMs and platform evidence at the
appropriate environment. Carry open and failed results forward in the release
decision. The same-revision main CI and installer workflow, repeat-build
byte comparisons, native signing service results and signed archive tests
must all succeed before publication.

| Environment | Required inputs |
| --- | --- |
| `release-macos-signing` | Secrets `EXACOPY_MACOS_CERT_P12_B64`, `EXACOPY_MACOS_CERT_PASSWORD` and `EXACOPY_APPLE_NOTARY_KEY_B64`. Variables `EXACOPY_MACOS_SIGNING_IDENTITY`, `EXACOPY_MACOS_TEAM_ID`, `EXACOPY_APPLE_NOTARY_KEY_ID` and `EXACOPY_APPLE_NOTARY_ISSUER_ID`. Use an approved Developer ID Application identity and a scoped notarization API key. |
| `release-windows-signing` | Variables `EXACOPY_AZURE_CLIENT_ID`, `EXACOPY_AZURE_TENANT_ID`, `EXACOPY_AZURE_SUBSCRIPTION_ID`, `EXACOPY_WINDOWS_SIGNING_ENDPOINT`, `EXACOPY_WINDOWS_SIGNING_ACCOUNT`, `EXACOPY_WINDOWS_CERTIFICATE_PROFILE` and `EXACOPY_WINDOWS_SIGNER_SUBJECT`. Federate only this environment to the Artifact Signing certificate profile with signer privileges. |
| `release-publisher-signing` | Secrets `EXACOPY_RELEASE_PRIVATE_KEY_PEM` and `EXACOPY_RELEASE_PUBLISHER_CERT_DER_B64`. Variables `EXACOPY_RELEASE_PUBLISHER_SHA256`, the independently approved lowercase DER fingerprint, and positive `EXACOPY_RELEASE_VALIDITY_DAYS`. Use the RSA key and certificate described in the offline release profile. Provision installer trust out of band. |
| `release-publication` | Secret `EXACOPY_IMMUTABILITY_READ_TOKEN` with Administration read access scoped to this repository. GitHub's workflow token separately has the contents-write permission needed for the release draft and assets. |

Production dispatch requires `publish=true` and the publisher's next
monotonically increasing sequence. Whenever required evidence is unavailable,
keep the job or the release approval blocked. The final verification matrix
installs the exact production archive for each target using the generated
checksum index and the separately configured publisher pin. It launches the
selected CLI and withdraws the owned installation from a disposable root.
The macOS and Windows checks verify the native signature of the installed
executable against the approved signer before launch. The POSIX checks launch
through the stable entry point. The Windows check executes the selected binary
after confirming the shim and its selection, and public non-elevated shim
execution remains a separate qualification. Publication downloads the same
immutable Actions artifact identifier that passed the matrix.

The workflow attaches the three
archives, the checksum index, and the per-target SBOM and provenance. It
compares GitHub's asset digests with the local file digests before it selects
the draft as latest and checks the resulting immutable release again. If
publication fails after a draft is opened, retain it and reconcile its tag,
status and assets before further action.

Production signing requires that the exact Pomologie revision, tree and source
archive resolve from the configured repository. The current supply-chain
record also identifies macOS repeat-build divergence from the local-path
companion dependency. The repeat-build check remains active for every native
production target.

[Offline publisher trust](../../docs/supply-chain/offline-release-profile.md) ·
[Supply-chain evidence](../../docs/supply-chain/README.md) ·
[GitHub release immutability](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) ·
[Apple notarization](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool) ·
[Azure Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations)
