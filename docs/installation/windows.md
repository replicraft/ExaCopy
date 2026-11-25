# Offline Windows CLI installation

The root PowerShell scripts implement the first user-scope offline profile
for a pinned raw CLI artifact. Run them in PowerShell 7.4 or newer on native
x64 or ARM64 Windows 11 or Windows Server 2022 and newer, using a local fixed
NTFS volume and a non-elevated user session. The script refuses a host below
the signed Windows build floor. Native Windows lifecycle qualification is
pending. The installed binary's supported commands depend on the artifact
and the repository's feature matrix.

## Inputs and trust

Obtain the scripts and their support files together from an independently
trusted source. Obtain the publisher's raw DER certificate and its
lowercase SHA-256 fingerprint through that trusted channel. The certificate
and fingerprint must be supplied separately from the offline bundle. No
official publisher key, download URL, or Authenticode release qualification
is supplied by these scripts.

The offline bundle is a directory containing exactly `release.manifest`,
`release.sig`, and `exacopy.exe`. The raw signature authenticates the exact
ASCII manifest bytes under the pinned RSA publisher key. The installer
requires an exact stable version and native target, enforces the signed
validity window, verifies the signed byte size and SHA-256, and checks the
PE32+ header and architecture without loading the binary. SBOM and
provenance digests are bound by the manifest. Those artifacts have separate
release verification.

Supply `$publisherPin` from the trusted channel and set the exact release
version before running these commands.

```powershell
$arguments = @{
    OfflineBundle = '.\offline-bundle'
    Version = '1.2.3'
    PublisherCert = '.\separate-trust\publisher.der'
    PublisherSha256 = $publisherPin
}
.\install.ps1 @arguments -DryRun -Json
.\install.ps1 @arguments -NonInteractive
```

The second invocation installs the selected version. `-DryRun` validates
the same inputs and observes any existing installation without creating
files. The scripts use an exclusive, same-volume directory rename and
report the exact executable under
`%LOCALAPPDATA%\Programs\ExaCopy\versions\<version>\exacopy.exe`.
They do not register an active version or alter PATH.

## Reinstall and uninstall

A root accepts only its first exact signed release. Repeating the same
installation verifies the owned files. Reinstall after uninstall requires
that same release and a currently valid manifest. New-release selection,
automatic update, downgrade, system scope, service registration, portable
profile management, and purge are outside this profile.

Close any active ExaCopy programs and prevent new launches before passing
`-Quiesced`. Keep the publisher trust inputs available for uninstall.

```powershell
$remove = @{
    Version = '1.2.3'
    PublisherCert = '.\separate-trust\publisher.der'
    PublisherSha256 = $publisherPin
}
.\uninstall.ps1 @remove -DryRun -Json
.\uninstall.ps1 @remove -Quiesced -NonInteractive
```

Uninstall revalidates the retained signature, ownership, exact version
contents, and expected executable bytes. It refuses conflicting entries,
named NTFS streams, reparse points, unsafe permissions, and observable
active or locked binaries. It removes only the owned executable, its version
marker, and the empty version directory. The root owner marker and signed
release records stay in place to retain provenance. Expired release
metadata can still authenticate an uninstall.

Profiles, jobs, destination-local journals, keys, and repositories remain in
their original locations. The scripts leave execution policy, firewall,
drivers, service settings, SSH, WireGuard, and PATH alone.

A failure can leave private evidence such as an `.ExaCopy-install-*` stage
or partially removed version directory. Inspect the named paths before
retrying. Unrecognized evidence blocks automated adoption and deletion.
These filesystem calls establish neither power-loss durability nor safe
uninstall in the presence of concurrent launches.

## Testing

Run `pwsh -NoProfile -NonInteractive -File tools/install/windows/test.ps1`.
The fixture tests PowerShell syntax, ephemeral signed metadata, PE header
admission, and failure controls in disposable directories. On Windows,
`-Artifact PATH` adds validation of a built native CLI binary without
executing it. Passing those checks does not qualify installation and
uninstallation on native Windows. The native ACL, rename, stream,
active-process, and interruption cases still need a dedicated test run.
