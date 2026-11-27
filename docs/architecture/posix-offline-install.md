# CLI installation on macOS and Linux

Cargo is the primary recommended installation method. See the
[source installation instructions](../../README.md#installation).
Use `install.sh` for a prebuilt executable when you do not want to install
Rust. The script does not compile ExaCopy or require Cargo.

The root shell scripts install a user-scoped CLI release from GitHub's latest stable release or an exact offline bundle. Use the scripts from a trusted source tree, with their companion shell files in `tools/installer`. ExaCopy has yet to provision an official publisher certificate or signed distributable bundle for this profile.

## Install the latest stable release

Supply the independently trusted publisher certificate and fingerprint:

```sh
./install.sh --latest --publisher-cert "$CERT" --publisher-sha256 "$PIN"
```

Latest mode is also the default when `--offline-bundle` is absent. An optional
`--version` requires the selected latest release to match that exact version.
The installer resolves `releases/latest` once, downloads the running platform's
`exacopy-cli-<target>.tar.gz` and `SHA256SUMS.txt` from that tag, checks the
archive checksum, and extracts only the three permitted files into private
staging. The existing publisher signature and executable hash checks run before
installation. This mode requires a supported host curl and `/usr/bin/perl`
with `IO::Uncompress::Gunzip`; missing prerequisites stop before download.
The [online release contract](../supply-chain/online-cli-release-profile.md)
defines redirect, size and extraction limits. Live official delivery remains
unqualified; local tests use synthetic signed releases and scripted HTTP.

## Verify the source and choose a release

Obtain the publisher certificate in DER encoding and its lowercase SHA-256 fingerprint through a trusted channel independent of the bundle. Keep the DER certificate outside the bundle. The bundle contains exactly `release.manifest`, `release.sig`, and a raw `exacopy` executable. The shared offline release profile specifies the signed manifest and the RSA/SHA-256 signature.

The install script checks the supplied certificate pin, detached signature, exact requested version, stable channel, signed UTC validity interval, target, platform floors, and artifact length and hash. It authenticates privately staged data and never executes the artifact. The signed SBOM and provenance fields identify documents by digest. Inspecting those documents and verifying OS package signatures are separate release checks.

The supported script profile targets native arm64 or x86-64 on macOS 14 or newer, or Linux kernel 5.15 or newer with glibc 2.35 or newer. A signed release can require a higher floor. The scripts require the host OpenSSL or compatible LibreSSL at `/usr/bin/openssl`, a SHA-256 utility and standard host shell utilities. Use an unprivileged account and supported local storage. Use absolute, symlink-free paths whose ancestors exclude other users' writes. The paths can include spaces and Unicode. The script rejects added macOS ACL grants that would complicate that protection.

## Install an exact version

Set `VERSION`, `BUNDLE`, `CERT` and `PIN` to your independently verified inputs. Preview the operation first.

```sh
./install.sh --version "$VERSION" --offline-bundle "$BUNDLE" \
  --publisher-cert "$CERT" --publisher-sha256 "$PIN" --dry-run
```

Run the same command without `--dry-run` to install. The script prints both the exact versioned executable path and the stable `$HOME/.local/bin/exacopy` path. Run `exacopy` when the current PATH already contains `$HOME/.local/bin`. Otherwise invoke the printed launcher path or add its directory to PATH using your shell's settings. The default store is `$HOME/Library/Application Support/ExaCopy/install` on macOS and `${XDG_DATA_HOME:-$HOME/.local/share}/exacopy/install` on Linux. The install root must be below the installing owner's home and named `install`. Use `--install-root` to choose a different such directory. The script is noninteractive and also accepts `--scope user`, `--cli-only`, and `--non-interactive`.

The store keeps an owner record, a monotone release sequence with its exact signed manifest digest, and the published `versions/<version>` directories. A version directory holds the immutable executable bytes, verified release descriptor and signature, and its install intent. Install stages and verifies the next version under the same versions parent, records its release sequence, and publishes the directory without replacing an incumbent. A repeat of the latest exact release rechecks the existing bytes. Stale releases and reuse of a sequence for a different manifest fail. An unrelated or symlinked existing path is a conflict. Rollback history applies to the retained store and trust root. A new store has no history to inherit.

## Stable launcher and interruption

The public launcher is a symlink to the exact verified executable under the selected store. The installer validates the owner-controlled bin directory and its ancestors and checks the existing command on the caller's PATH. An unrelated command on that PATH or an unowned object at the launcher pathname blocks activation. This check covers the invoking PATH. Shell settings and aliases in other sessions remain under the user's control.

The store and launcher directory have separate lifecycle locks so two stores under the same home cannot claim the same entry concurrently. The installer re-verifies the current release and the newly published version, then flushes a private transition record. Its two sides bind the prior and intended selections to the store, publisher pin, exact target, symlink identity, and signed content digests. The installer publishes the first selector exclusively and switches an owned selector by same-volume rename. The prior verified version stays in its versioned directory. Invoking the launcher uses the installed bytes authenticated at activation.

An interruption before the switch leaves the prior launcher usable. After the switch the stable path targets the new version. A retry re-verifies the selected installed version and accepts an exact match to a recorded side. Retained locks, unexpected ownership or identity, and unknown transition data require owner reconciliation. Keep that evidence with the owned versions. This protocol assumes cooperative processes of the installing UID, a trusted administrator, and local storage with the stated link and rename behavior.

A dry-run retry for a verified installed version reports `Would activate launcher` when the stable path is absent or selects an earlier release. The stable path selects the requested version after the install retry completes. A dry run for the already selected release reports `Already installed`.

A non-preview retry that observes the requested version already selected repeats the installer's global `sync` and checks the selection again before reporting success. An interruption may have happened after the selector changed and before the previous flush. Power-loss durability remains unqualified.

## Remove an exact version

Stop all launches and uses of the selected version before uninstalling. No managed services participate in this profile. Preview with `--dry-run`, then use `--quiesced` to assert the operator established quiescence. The installer lock only serializes the installer scripts. It cannot discover jobs or prevent direct program launches.

```sh
./uninstall.sh --version "$VERSION" --publisher-cert "$CERT" \
  --publisher-sha256 "$PIN" --quiesced
```

Repeat the installation's `--install-root` if you used one. Uninstall re-verifies the historical release signature, ownership records, and exact artifact bytes. It withdraws only the named version, removes its four known files and the resulting empty version directory, and retains the rollback sequence. Removing the active version withdraws its owned launcher first. Removing a different version leaves the active launcher pointing at its selected release. The previous version remains available by its versioned path after active removal. A tampered file, unexpected entry, missing ownership, lock, or interrupted withdrawal blocks the operation. Preserve the evidence and reconcile with the owner if the installer reports an ambiguous state.

Repeating removal or preview for the absent version recorded in the retained release history reports `Already absent` after checking store ownership and the supplied publisher certificate pin. The result describes the current pathname. Missing or mismatched history, an unowned store, a dangling version link, and pending withdrawal evidence still produce a refusal.

On macOS, removal also refuses if the selected version directory, any of its four owned paths, or the affected launcher or selector record carries a resource fork. The signed raw release verifies the ordinary file bytes. A separately attached resource fork needs preservation before the version can be removed. Preview performs the same check. The check reads attribute names using the host `/usr/bin/xattr`.

Profiles, saved credentials, journals, partial transfers, repositories, source and destination files, retained originals, shell startup files, PATH, and other installed versions are outside the removal scope. Profile migrations, safe service draining, managed update and rollback, purge, system scope, and power-loss qualification remain later work. The script assumes cooperative processes of the installing UID and a trusted administrator.

## Verification

From a trusted source tree, run the shell checks and the fixture suite as an unprivileged user.

```sh
shellcheck -x install.sh uninstall.sh
python3 -B tools/installer/test_posix.py
python3 -B tools/installer/test_latest.py
python3 -B tools/installer/test_posix_launcher.py
```

Use `--artifact /absolute/path/to/exacopy` with `test_posix.py` to repeat that
suite with actual locally built CLI bytes. The suites generate temporary
test-only publishers and operate in disposable homes. The launcher fixture
also exercises direct invocation, competing stores, incumbent preservation
and process interruption around activation and removal.

At `57581c1`, the hosted Linux x86-64 and macOS arm64 installer jobs passed.
Each latest-release fixture reported 56 passing cases, including authenticated
installation, exact repeat, offline uninstall, and refusal of malformed CDN
redirects. Curl receives the validated download URL through stdin; the fixtures
check that the signed query stays out of curl arguments and installer output.
They also require a failed curl exit to stop installation even when its body
and response metadata otherwise indicate success. The fixtures checked removal
of their download directories and preservation of incumbent bytes.
[Exact installer run](https://github.com/replicraft/ExaCopy/actions/runs/46026139382).

These results cover the synthetic publisher and fixture profiles. macOS
x86-64, official release keys and signed artifacts, real installation/reboot,
and power-loss behavior remain unqualified.
