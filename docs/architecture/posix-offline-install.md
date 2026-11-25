# Offline CLI installation on macOS and Linux

The root shell scripts install and remove an exact, user-scoped CLI release from an offline bundle. Use the scripts from a trusted source tree, with their companion shell files in `tools/installer`. ExaCopy has yet to provision an official publisher certificate or signed distributable bundle for this profile.

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

Run the same command without `--dry-run` to install. The script prints the exact versioned executable path for direct invocation. The default store is `$HOME/Library/Application Support/ExaCopy/install` on macOS and `${XDG_DATA_HOME:-$HOME/.local/share}/exacopy/install` on Linux. The install root must be below the installing owner's home and named `install`. Use `--install-root` to choose a different such directory. The script is noninteractive and also accepts `--scope user`, `--cli-only`, and `--non-interactive`.

The store keeps an owner record, a monotone release sequence with its exact signed manifest digest, and the published `versions/<version>` directories. A version directory holds the immutable executable bytes, verified release descriptor and signature, and its install intent. Install stages and verifies the next version under the same versions parent, records its release sequence, and publishes the directory without replacing an incumbent. A repeat of the latest exact release rechecks the existing bytes. Stale releases and reuse of a sequence for a different manifest fail. An unrelated or symlinked existing path is a conflict. Rollback history applies to the retained store and trust root. A new store has no history to inherit.

## Remove an exact version

Stop all launches and uses of the selected version before uninstalling. No managed services participate in this profile. Preview with `--dry-run`, then use `--quiesced` to assert the operator established quiescence. The installer lock only serializes the installer scripts. It cannot discover jobs or prevent direct program launches.

```sh
./uninstall.sh --version "$VERSION" --publisher-cert "$CERT" \
  --publisher-sha256 "$PIN" --quiesced
```

Repeat the installation's `--install-root` if you used one. Uninstall re-verifies the historical release signature, ownership records, and exact artifact bytes. It withdraws only the named version, removes its four known files and the resulting empty version directory, and retains the rollback sequence. A tampered file, unexpected entry, missing ownership, lock, or interrupted withdrawal blocks the operation. Preserve the evidence and reconcile with the owner if the installer reports an ambiguous state.

On macOS, removal also refuses if the selected version directory or any of its four owned paths carries a resource fork. The signed raw release verifies the ordinary file bytes. A separately attached resource fork needs preservation before the version can be removed. Preview performs the same check. The check reads attribute names using the host `/usr/bin/xattr`.

Profiles, saved credentials, journals, partial transfers, repositories, source and destination files, retained originals, shell startup files, PATH, and other installed versions are outside the removal scope. A stable launcher, profile migrations, safe service draining, managed update and rollback, purge, online downloads, system scope, and power-loss qualification remain later work. The script assumes cooperative processes of the installing UID and a trusted administrator.

## Verification

From a trusted source tree, run the shell checks and the fixture suite as an unprivileged user.

```sh
shellcheck -x install.sh uninstall.sh
python3 -B tools/installer/test_posix.py
```

Use `--artifact /absolute/path/to/exacopy` to repeat the suite with actual locally built CLI bytes. The suite generates a temporary test-only publisher and operates in a disposable home. The macOS arm64 controls check signed installation, exact repeated installation, signature and metadata rejection, path and history conflicts, and byte preservation on uninstall. Linux native execution, macOS x86-64, release keys and artifacts, real installation/reboot, and power-loss behavior are unqualified.
