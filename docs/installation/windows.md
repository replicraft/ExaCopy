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
official publisher key or Authenticode release qualification is supplied by
these scripts.

## Latest stable release

```powershell
./install.ps1 -Latest -PublisherCert $Cert -PublisherSha256 $Pin
```

Latest mode is the default when `-OfflineBundle` is absent. Optional `-Version`
requires the selected latest version to match. The installer freezes GitHub's
`releases/latest` redirect to one tag, downloads the native platform's
`exacopy-cli-<target>.zip` and `SHA256SUMS.txt`, verifies the archive checksum,
and extracts the three permitted files into private staging. The original
publisher, executable and owned-path checks still precede installation.
The [online release contract](../supply-chain/online-cli-release-profile.md)
defines the strict download and archive profile. An existing store bound to a
different release identity still refuses replacement. Synthetic PowerShell
tests on macOS do not qualify native Windows installation or live delivery.

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
The installer also publishes a stable PowerShell launcher at
`%LOCALAPPDATA%\Programs\ExaCopy\bin\exacopy.ps1`. It does not alter PATH.

```powershell
$launcher = Join-Path $env:LOCALAPPDATA 'Programs\ExaCopy\bin\exacopy.ps1'
& $launcher --version
```

The launcher verifies the selected signed manifest and executable and holds
the executable against write or deletion through child exit. It forwards
arguments and the child exit status. Its locally installed script requires
PowerShell 7.4+ and an execution policy that admits it. The direct executable
path remains available for Command Prompt and restricted script policies.
The launcher itself makes no Authenticode claim. Install and uninstall
must use the same trusted launcher-generation support files; a changed
generation needs a separately specified migration.

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
marker, and the empty version directory. It first withdraws the exact owned
launcher directory and removes its known files. The root owner marker and signed
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
Also run `pwsh -NoProfile -NonInteractive -File tools/install/windows/launcher-fixture.ps1`.
The fixture tests PowerShell syntax, ephemeral signed metadata, PE header
admission, and failure controls in disposable directories. On Windows,
`-Artifact PATH` adds validation of a built native CLI binary without
executing it. Passing those checks does not qualify installation and
uninstallation on native Windows. The native ACL, rename, stream,
active-process, and interruption cases still need a dedicated test run.

### Opt-in native NTFS lifecycle fixture

Use PowerShell 7.4 or newer with a trusted Pester 5.5+ installation, a
non-elevated Windows user, and an owner-controlled fixed NTFS volume.
Prevent concurrent ExaCopy launches during the run. From the repository
root, run:

```powershell
Import-Module Pester -MinimumVersion 5.5.0
$cases = New-PesterContainer -Path ./tools/install/windows/Lifecycle.Tests.ps1
Invoke-Pester -Container $cases -Output Detailed -CI
```

For a built native CLI binary, pass its path as container data:

```powershell
$artifact = (Resolve-Path ./target/release/exacopy.exe).ProviderPath
$cases = New-PesterContainer -Path ./tools/install/windows/Lifecycle.Tests.ps1 `
    -Data @{ Artifact = $artifact }
Invoke-Pester -Container $cases -Output Detailed -CI
```

The fixture prints a new owner-private evidence path under
`%LOCALAPPDATA%\.ExaCopy-install-*`. It supplies this disposable layout to
the shipped lifecycle functions and leaves the ordinary ExaCopy install
root alone. It signs only the synthetic fixture bundle with an ephemeral
key. The optional built binary is verified and copied without being run.
Without an artifact path, lifecycle checks use a synthetic PE header.

The cases check exact hashes of synthetic profile settings, a key, a job
journal, and a repository object before and after the installer operations.
They cover dry-run, idempotence, exact reinstall and uninstall, an
unowned directory and a junction, unexpected files, a locked executable,
tampering, named streams, and an unexpected ACL. The fixture retains
its disposable evidence for inspection. This manual test needs a native
run before its results can contribute to Windows qualification.
