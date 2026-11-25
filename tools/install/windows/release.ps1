# Shared signed offline CLI release profile. No paths are selected by bundle contents.
$ExaCopyReleaseFiles = @('release.manifest', 'release.sig', 'exacopy.exe')
$ExaCopyManifestLimit = 4096
$ExaCopySignatureLimit = 1024
$ExaCopyCertLimit = 16384
$ExaCopyArtifactLimit = 256MB
$ExaCopyDigestPattern = '\A[0-9a-f]{64}\z'
$ExaCopyVersionPattern = '\A(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}\z'
$ExaCopyMachine = @{
    'x86_64-pc-windows-msvc' = 0x8664
    'aarch64-pc-windows-msvc' = 0xaa64
}

function Get-ExaCopySha256 {
    param([byte[]] $Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Assert-ExaCopyTrustArguments {
    param([string] $Version, [string] $PublisherCert, [string] $PublisherSha256)
    if ($Version -cnotmatch $ExaCopyVersionPattern) {
        throw 'Supply an exact release version in canonical N.N.N form.'
    }
    Assert-ExaCopyPublisherArguments $PublisherCert $PublisherSha256
}

function Assert-ExaCopyPublisherArguments {
    param([string] $PublisherCert, [string] $PublisherSha256)
    if ([string]::IsNullOrWhiteSpace($PublisherCert) -or
        $PublisherSha256 -cnotmatch $ExaCopyDigestPattern) {
        throw 'Supply an independently trusted DER publisher certificate and its exact SHA-256 pin.'
    }
}

function Read-ExaCopyManifestFields {
    param([byte[]] $Bytes)

    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt $ExaCopyManifestLimit -or
        $Bytes[$Bytes.Length - 1] -ne 10) {
        throw 'Release manifest exceeds its bound or lacks its final LF.'
    }
    $lines = [Text.Encoding]::ASCII.GetString($Bytes).Split([char]10)
    $keys = @('schema', 'version', 'channel', 'created', 'expires', 'sequence', 'target',
        'variant', 'format', 'artifact', 'size', 'sha256', 'publisher_sha256',
        'min_os', 'min_abi', 'sbom_sha256', 'provenance_sha256')
    if ($lines.Length -ne $keys.Length + 1) {
        throw 'Release manifest has missing, duplicate, or unknown fields.'
    }

    $fields = [ordered]@{}
    for ($i = 0; $i -lt $keys.Length; $i++) {
        $prefix = $keys[$i] + '='
        if (!$lines[$i].StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw 'Release manifest has incorrect field order or names.'
        }
        $fields[$keys[$i]] = $lines[$i].Substring($prefix.Length)
    }

    if ($fields.schema -cne 'exacopy-release-v1' -or $fields.channel -cne 'stable' -or
        $fields.variant -cne 'cli' -or $fields.format -cne 'raw' -or
        $fields.artifact -cne 'exacopy.exe' -or $fields.min_abi -cne 'native' -or
        ($fields.target -cne 'x86_64-pc-windows-msvc' -and
         $fields.target -cne 'aarch64-pc-windows-msvc')) {
        throw 'Unsupported offline Windows CLI release profile.'
    }
    if ($fields.version -cnotmatch $ExaCopyVersionPattern -or
        $fields.created -cnotmatch '\A[1-9][0-9]{9}\z' -or
        $fields.expires -cnotmatch '\A[1-9][0-9]{9}\z' -or
        $fields.sequence -cnotmatch '\A[1-9][0-9]{0,9}\z' -or
        $fields.size -cnotmatch '\A[1-9][0-9]{0,8}\z' -or
        $fields.min_os -cnotmatch '\A10\.0\.[1-9][0-9]{0,8}\z') {
        throw 'Invalid canonical release version, time, sequence, size, or Windows floor.'
    }
    foreach ($name in @('sha256', 'publisher_sha256', 'sbom_sha256', 'provenance_sha256')) {
        if ($fields[$name] -cnotmatch $ExaCopyDigestPattern) {
            throw 'Release manifest has an invalid SHA-256 field.'
        }
    }

    $culture = [Globalization.CultureInfo]::InvariantCulture
    $fields.created = [long]::Parse($fields.created, $culture)
    $fields.expires = [long]::Parse($fields.expires, $culture)
    $fields.sequence = [long]::Parse($fields.sequence, $culture)
    $fields.size = [long]::Parse($fields.size, $culture)
    $fields.min_os = [Version]::Parse($fields.min_os)
    if ($fields.created -ge $fields.expires -or $fields.sequence -gt [int]::MaxValue -or
        $fields.size -gt $ExaCopyArtifactLimit -or $fields.min_os.Build -lt 20348) {
        throw 'Release manifest exceeds a supported value bound.'
    }
    return $fields
}

function Confirm-ExaCopyRelease {
    param(
        [byte[]] $Manifest, [byte[]] $Signature, [byte[]] $Certificate,
        [string] $PublisherSha256, [string] $Version, [string] $Target,
        [long] $UnixNow, [switch] $Historical
    )

    if ($Certificate.Length -eq 0 -or $Certificate.Length -gt $ExaCopyCertLimit -or
        $PublisherSha256 -cnotmatch $ExaCopyDigestPattern -or
        (Get-ExaCopySha256 $Certificate) -cne $PublisherSha256) {
        throw 'Publisher certificate does not match the independently supplied pin.'
    }
    if ($Manifest.Length -eq 0 -or $Manifest.Length -gt $ExaCopyManifestLimit -or
        $Signature.Length -eq 0 -or $Signature.Length -gt $ExaCopySignatureLimit) {
        throw 'Missing or oversized release manifest or detached signature.'
    }
    if ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Certificate) -ne
        [Security.Cryptography.X509Certificates.X509ContentType]::Cert) {
        throw 'Publisher trust input must contain one raw DER certificate.'
    }

    $publisher = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate)
    try {
        if ($publisher.HasPrivateKey -or (Get-ExaCopySha256 $publisher.RawData) -cne $PublisherSha256) {
            throw 'Publisher trust input must contain one raw DER certificate.'
        }
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($publisher)
        if ($null -eq $rsa) {
            throw 'Publisher certificate does not contain an RSA key.'
        }
        try {
            if ($rsa.KeySize -lt 3072 -or $rsa.KeySize -gt 8192 -or
                $Signature.Length -ne [Math]::Ceiling($rsa.KeySize / 8) -or
                !$rsa.VerifyData($Manifest, $Signature, [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
                throw 'Detached release signature verification failed.'
            }
        }
        finally {
            $rsa.Dispose()
        }
    }
    finally {
        $publisher.Dispose()
    }

    $release = Read-ExaCopyManifestFields $Manifest
    if ($release.publisher_sha256 -cne $PublisherSha256 -or
        $release.version -cne $Version -or $release.target -cne $Target) {
        throw 'Signed release does not match the pinned publisher, version, or native target.'
    }
    if (!$Historical -and ($UnixNow -lt $release.created -or $UnixNow -ge $release.expires)) {
        throw 'Signed release is outside its validity window.'
    }
    return $release
}

function Get-ExaCopyTarget {
    $native = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($native) {
        'X64' { return 'x86_64-pc-windows-msvc' }
        'Arm64' { return 'aarch64-pc-windows-msvc' }
        default { throw 'This offline installer supports native Windows x64 and ARM64.' }
    }
}

function Assert-ExaCopyWindowsFloor {
    param([Version] $SignedFloor)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property ProductType, Version
    $version = [Version]::Parse($os.Version)
    $floor = switch ($os.ProductType) {
        1 { 22000 }
        { $_ -in 2, 3 } { 20348 }
        default { throw 'The Windows product type could not be established.' }
    }
    if ($version.Major -ne 10 -or $version.Minor -ne 0 -or
        $version.Build -lt $floor -or $version.Build -lt $SignedFloor.Build) {
        throw 'Windows is below the supported release floor.'
    }
}

function Assert-ExaCopyExecutableHeader {
    param([IO.Stream] $Stream, [string] $Target)

    # Microsoft PE/COFF header fields. This check does not load the executable.
    $dosPePointer = 0x3c
    $coffHeaderBytes = 24
    $reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
        if ($Stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw 'Artifact lacks the Windows executable header.'
        }
        $Stream.Position = $dosPePointer
        $pe = [long]$reader.ReadUInt32()
        if ($pe -lt 64 -or $pe -gt $Stream.Length - $coffHeaderBytes - 2) {
            throw 'Artifact has an invalid PE header offset.'
        }
        $Stream.Position = $pe
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne $ExaCopyMachine[$Target]) {
            throw 'Artifact does not have the signed native PE architecture.'
        }
        $sections = $reader.ReadUInt16()
        $Stream.Position = $pe + 20
        $optional = $reader.ReadUInt16()
        $flags = $reader.ReadUInt16()
        if ($sections -eq 0 -or $optional -lt 112 -or $optional -gt $Stream.Length - $Stream.Position -or
            ($flags -band 0x0002) -eq 0 -or ($flags -band 0x2000) -ne 0 -or
            $reader.ReadUInt16() -ne 0x020b) {
            throw 'Artifact is not a supported standalone PE32+ executable.'
        }
    }
    finally {
        $reader.Dispose()
        $Stream.Position = 0
    }
}

function Confirm-ExaCopyArtifact {
    param([string] $Path, $Release)
    [void](Confirm-ExaCopyPath $Path -File)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $Release.size) {
            throw 'Artifact byte length does not match the signed manifest.'
        }
        Assert-ExaCopyExecutableHeader $stream $Release.target
        $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        if ($digest -cne $Release.sha256 -or $stream.Position -ne $Release.size) {
            throw 'Artifact SHA-256 does not match the signed manifest.'
        }
    }
    finally {
        $stream.Dispose()
    }
}
