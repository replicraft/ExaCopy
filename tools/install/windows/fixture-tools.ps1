# Synthetic test helpers. Loading this file performs no filesystem work.

function New-FixturePublisher {
    param([DateTimeOffset] $Now)
    $rsa = [Security.Cryptography.RSA]::Create(3072)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=ExaCopy synthetic installer fixture', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned($Now.AddDays(-1), $Now.AddDays(1))
        try {
            $der = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            return [pscustomobject]@{ SigningKey = $rsa; Certificate = $der }
        }
        finally { $certificate.Dispose() }
    }
    catch {
        $rsa.Dispose()
        throw
    }
}

function New-ExecutableHeader {
    param([uint16] $Machine)
    # Bounded synthetic header for parsing fixtures. Never execute these bytes.
    $memory = [IO.MemoryStream]::new([byte[]]::new(512))
    $writer = [IO.BinaryWriter]::new($memory)
    try {
        $writer.Write([uint16]0x5a4d)
        $memory.Position = 0x3c
        $writer.Write([uint32]64)
        $writer.Write([uint32]0x4550)
        $writer.Write($Machine)
        $writer.Write([uint16]1)
        $memory.Position = 64 + 20
        $writer.Write([uint16]112)
        $writer.Write([uint16]0x0002)
        $writer.Write([uint16]0x020b)
        return ,($memory.ToArray())
    }
    finally { $writer.Dispose() }
}

function New-FixtureManifest {
    param(
        [string] $Publisher, [string] $Digest, [long] $Now,
        [long] $Length = 512, [string] $Target = 'x86_64-pc-windows-msvc',
        [long] $WindowSeconds = 300
    )
    $lines = @(
        'schema=exacopy-release-v1'
        'version=1.2.3'
        'channel=stable'
        "created=$($Now - $WindowSeconds)"
        "expires=$($Now + $WindowSeconds)"
        'sequence=7'
        "target=$Target"
        'variant=cli'
        'format=raw'
        'artifact=exacopy.exe'
        "size=$Length"
        "sha256=$Digest"
        "publisher_sha256=$Publisher"
        'min_os=10.0.20348'
        'min_abi=native'
        ('sbom_sha256=' + ('1' * 64))
        ('provenance_sha256=' + ('2' * 64))
    )
    return ,([Text.Encoding]::ASCII.GetBytes(($lines -join "`n") + "`n"))
}

function Test-FixtureManifest {
    param([byte[]] $Bytes, [Security.Cryptography.RSA] $SigningKey, $Arguments)
    $signed = $Arguments.Clone()
    $signed.Manifest = $Bytes
    $signed.Signature = $SigningKey.SignData(
        $Bytes, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return Confirm-ExaCopyRelease @signed
}
