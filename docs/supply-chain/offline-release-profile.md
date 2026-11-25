# Offline CLI installer release profile v1

This profile defines a user-scoped install of a local raw CLI artifact. It
defines the same signed bytes and verification decisions on POSIX and
Windows. It uses an explicitly approved publisher SHA-256 fingerprint,
provided separately from the bundle. ExaCopy currently provides no production
publisher certificate or official signed release for this profile. Before
running a root installer script, authenticate the complete script bundle,
including its local helper files, or use a trusted source checkout.

## Trust inputs

The owner acquires and approves a single X.509 certificate in DER encoding
and its 64-character lowercase SHA-256 fingerprint through a trustworthy
out-of-band channel. The installer requires both inputs. The bundle cannot
supply the expected certificate or expected fingerprint. The certificate
binds a public verification key through its independently approved exact
bytes. Host certificate stores provide no authority for this profile.

The certificate and detached signature are bounded before opening untrusted
metadata. Certificate limit is 16,384 bytes. The RSA key size must be
3072 through 8192 bits. The signature is raw algorithm output and its size
must equal the RSA modulus byte length, at most 1024 bytes. The operation is
RSASSA-PKCS1-v1_5 with SHA-256 over the exact manifest bytes. The signature
includes the manifest schema discriminator and all publisher-bound fields.
Verification tools must be from the host or independently trusted. POSIX
can use OpenSSL or compatible LibreSSL. Windows can use .NET RSA through
RSACertificateExtensions and RSA.VerifyData with Pkcs1 padding.

## Bundle

The input directory contains exactly three regular files with exact names.

- release.manifest
- release.sig
- exacopy on macOS/Linux or exacopy.exe on Windows

Treat the three files and their names as untrusted. Hold or privately copy
bounded objects before verification, and authenticate the copied manifest
before parsing its fields. Do not use shell evaluation or trust based on a
file name. Enforce the hash and length on the exact privately staged artifact
that will become the installed file. The installer does not execute it.
This raw format has no archive entries and needs no archive extraction.

## Signed descriptor

The manifest is at most 4096 bytes. Every byte is ASCII. Every line ends with
a single LF. Field names and ordering below are exact. There is no BOM,
carriage return, leading or trailing whitespace, duplicate field, omitted
field, extra line, or extra key. Values use the grammar below.

```text
schema=exacopy-release-v1
version=<major.minor.patch>
channel=stable
created=<ten-digit nonzero-leading Unix seconds>
expires=<ten-digit nonzero-leading Unix seconds>
sequence=<positive decimal>
target=<Rust target triple>
variant=cli
format=raw
artifact=<exacopy or exacopy.exe>
size=<positive decimal bytes>
sha256=<64 lowercase hexadecimal>
publisher_sha256=<64 lowercase hexadecimal>
min_os=<numeric platform floor>
min_abi=<numeric glibc floor or native>
sbom_sha256=<64 lowercase hexadecimal>
provenance_sha256=<64 lowercase hexadecimal>
```

Version components are canonical unsigned decimals in 0 through 999999.
Sequence is canonical decimal in 1 through 2147483647. Size is canonical
decimal in 1 through 268435456. Decimal fields omit redundant leading
zeroes. Timestamp fields are UTC and require created < expires. Installation
uses a trusted-enough host clock and accepts only created <= now < expires.
The caller requests the exact version. The SHA-256 of the approved DER
certificate must equal publisher_sha256. The SBOM/provenance fields bind
referenced exact file digests. The initial raw bundle does not carry those
documents and installing it alone does not verify their contents.

Cases for the target field are aarch64-apple-darwin, x86_64-apple-darwin,
aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu, aarch64-pc-windows-msvc
and x86_64-pc-windows-msvc. The signer certifies that the executable is for
the named target. The installer checks the executing host's native
architecture and OS. The signed OS floor must be at least macOS 14.0, Linux
kernel 5.15, or Windows 10.0.20348, as applicable. Linux requires signed
glibc 2.35 or higher, and non-Linux uses min_abi=native. Both the baseline
host floor and any higher signed OS/ABI floor apply. Windows desktop must
have build 22000 or newer, and server must have build 20348 or newer.

## Ownership and rollback

The first implementation can publish a single immutable version in its
user-owned install root and report the exact path. Each published version
retains the signed manifest, detached signature and an install-created
owner record. The owner record is created under individually checked local
ownership before publication and binds scope, root, release identity and
its exact owned files. A matching version name alone grants no ownership.
Unknown entries, symlink/reparse paths, mismatched bytes, and ambiguous
interrupted state remain conflicts. Publish a fully checked staged version
on the same volume without overwriting another directory. For idempotence,
compare the existing owned version against the same signed manifest digest.

Where retained, a scope/target/publisher high-water record contains the
highest accepted sequence and that manifest digest. Refuse a lower sequence
and refuse a different digest at the same sequence. An identical digest is
an idempotent candidate. Preserve the record across uninstall. Initial
installs rely on the explicit version, approved bundle trust and replay
window. An owner reset or entirely new root cannot inherit a prior rollback
record without a separate recovered authorization. A slice that lacks a
retained high-water record must scope rollback protection to known retained
installs and document that limit.

Uninstall re-verifies the historical signed descriptor and artifact hash
under the owner-supplied trust anchor. Installation-time expiry need not
apply to owned-path cleanup. Remove only checked exact files recorded under
the validated root, and remove an empty version directory only. A different
version remains separate. Preserve profiles, journals, credentials, user
files, retained rollback evidence and foreign entries. Require owner
quiescence. An installer lock only serializes installers and cannot exclude
a concurrent direct launch. If lifecycle evidence is uncertain, stop and
retain the installation.

The first raw profile leaves stable launchers, PATH, service and task
registration, system scope, updates/downgrades, transactional selector
switching, purge, GUI, online delivery and native platform signatures for
their separate implementation and release evidence. No remote URL or
official key is provisioned by this profile.

## Test bundles

The development fixture generator uses a temporary local RSA3072 private
key and emits an external public fixture certificate. It destroys the
private key before returning. Never accept its key for release. It signs
the supplied local artifact bytes without executing them. A fixture with
inert bytes is sufficient for protocol boundary tests. Use an actual local
binary separately for installation integration checks and ensure the test
only installs inside a disposable user root.
