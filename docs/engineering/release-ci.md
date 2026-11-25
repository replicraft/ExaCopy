# CLI release workflow

Dispatch **CLI release** on an existing canonical `vMAJOR.MINOR.PATCH` tag
whose commit carries this workflow and the matching Cargo CLI version.
GitHub's dispatch API accepts a tag as the ref. The default `publish=false`
uses an ephemeral fixture certificate on each of the three native runners.
The workflow tests the generated candidate archives and keeps the unsigned
CLI, build record, SBOM and fixture evidence as Actions artifacts. Rerun
all jobs when retrying because downstream jobs require the same run attempt.

The case for publication depends on the actual commit and artifacts. The
current hosted matrix exercises Linux x64 on Ubuntu 22.04, macOS ARM64 on
macOS 15 and Windows x64 on Windows Server 2025. Hosted runs retain exact
runner versions, package verification and available native CLI smoke
results. Release reviewers must check operation and runtime-floor evidence
for the precise advertised profiles, including Windows install lifecycle
and any lower OS or ABI floor. The default Windows CLI currently exercises
an explicit-refusal profile. A signature verification pass establishes
publisher identity and artifact integrity for the tested profile.

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
keep the job or the release approval blocked. The workflow attaches the three
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
