# Loaded by test.ps1. Uses only synthetic HTTP responses and inert payloads.
. (Join-Path $PSScriptRoot 'download.ps1')
. (Join-Path $PSScriptRoot 'archive.ps1')
. (Join-Path $PSScriptRoot 'online.ps1')

function New-OnlineFixtureArchive {
    param([string[]] $Names, [string] $Special = '', [int] $Attributes = 0)

    $buffer = [IO.MemoryStream]::new()
    try {
        $zip = [IO.Compression.ZipArchive]::new($buffer, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($name in $Names) {
                $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::NoCompression)
                $entry.ExternalAttributes = if ($name -ceq $Special) { $Attributes } else { 0 }
                $payload = [Text.Encoding]::ASCII.GetBytes("fixture $name")
                $file = $entry.Open()
                try { $file.Write($payload, 0, $payload.Length) }
                finally { $file.Dispose() }
            }
        }
        finally { $zip.Dispose() }
        return ,($buffer.ToArray())
    }
    finally { $buffer.Dispose() }
}

function Test-OnlineFixtureArchive {
    param([byte[]] $Bytes)
    $stream = [IO.MemoryStream]::new($Bytes, $false)
    try { return Read-ExaCopyReleaseArchiveEntries $stream }
    finally { $stream.Dispose() }
}

function New-OnlineFixtureResponse {
    param([int] $Status, [string] $Location, [byte[]] $Bytes)
    $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$Status)
    if ($Location) {
        $response.Headers.Location = [uri]::new($Location, [UriKind]::RelativeOrAbsolute)
    }
    if ($null -ne $Bytes) { $response.Content = [Net.Http.ByteArrayContent]::new($Bytes) }
    return $response
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public sealed class ExaCopyFixtureHttpHandler : HttpMessageHandler
{
    public readonly Queue<HttpResponseMessage> Responses = new();
    public readonly List<string> Requests = new();

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add($"{request.Method} {request.RequestUri}");
        return Responses.Dequeue();
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(Send(request, cancellationToken));
    }
}
'@

$asset = 'exacopy-cli-x86_64-pc-windows-msvc.zip'
$canonicalLatest = "$ExaCopyGitHubRepository/releases/tag/v1.2.3"
$relativeLatest = [uri]::new('/replicraft/ExaCopy/releases/tag/v1.2.3', [UriKind]::Relative)
if ((Get-ExaCopyReleaseVersion $canonicalLatest '1.2.3') -cne '1.2.3' -or
    (Get-ExaCopyReleaseVersion $relativeLatest) -cne '1.2.3') { throw 'Canonical latest tag was refused.' }
foreach ($bad in @(
    $canonicalLatest.Replace('https://', 'http://')
    $canonicalLatest.Replace('github.com', 'github.com.example')
    $canonicalLatest.Replace('replicraft', 'other')
    $canonicalLatest.Replace('v1', 'v01')
    $canonicalLatest.Replace('v1', '%761')
    "$canonicalLatest-rc.1"
    "${canonicalLatest}?other=1"
    "$canonicalLatest#page"
)) {
    Assert-Refuses { Get-ExaCopyReleaseVersion $bad } 'Unsafe latest release tag was admitted.'
}
Assert-Refuses { Get-ExaCopyReleaseVersion $canonicalLatest '1.2.2' } 'Latest differs from exact version.'

foreach ($hostName in @('release-assets.githubusercontent.com', 'objects.githubusercontent.com')) {
    Confirm-ExaCopyReleaseAssetLocation "https://$hostName/opaque/asset?signature=fixture%2Btext"
}
foreach ($bad in @(
    'https://release-assets.githubusercontent.com.evil.invalid/asset'
    'https://release-assets.githubusercontent.com@evil.invalid/asset'
    'https://user@release-assets.githubusercontent.com/asset'
    'http://release-assets.githubusercontent.com/asset'
    'https://release-assets.githubusercontent.com:443/asset'
    'https://release-assets.githubusercontent.com:444/asset'
    'https://release-assets.githubusercontent.com/asset#fragment'
    'https://release-assets.githubusercontent.com\@evil.invalid/asset'
    '//release-assets.githubusercontent.com/asset'
)) {
    Assert-Refuses { Confirm-ExaCopyReleaseAssetLocation $bad } 'Unsafe release asset redirect was admitted.'
}

$line = ('b' * 64) + "  $asset"
$mixed = ('a' * 64) + "  exacopy-cli-aarch64-apple-darwin.tar.gz`n" + $line + "`n" +
    ('c' * 64) + "  exacopy-cli-x86_64-unknown-linux-gnu.tar.gz`n"
if ((Get-ExaCopyReleaseAssetDigest ([Text.Encoding]::ASCII.GetBytes($mixed)) $asset) -cne ('b' * 64)) {
    throw 'Mixed target release checksum was refused.'
}
foreach ($bad in @(
    $line
    "$line`n$line`n"
    "$line`n$mixed"
    "$line`r`n"
    ($line.ToUpperInvariant() + "`n")
    ($line.Replace('  ', ' ') + "`n")
    ($line.Replace('exacopy-cli-', '../exacopy-cli-') + "`n")
    ($line.Replace('pc-windows-msvc.zip', 'unknown-linux-gnu.zip') + "`n")
    ($line.Replace('pc-windows-msvc.zip', 'pc-windows-msvc.tar.gz') + "`n")
    ("$line`n" + ('x' * 4097))
)) {
    Assert-Refuses { Get-ExaCopyReleaseAssetDigest ([Text.Encoding]::ASCII.GetBytes($bad)) $asset } 'Invalid checksum index was admitted.'
}

$http = [ExaCopyFixtureHttpHandler]::new()
$client = [Net.Http.HttpClient]::new($http)
$destination = [IO.MemoryStream]::new()
try {
    $http.Responses.Enqueue((New-OnlineFixtureResponse 302 $canonicalLatest))
    $version = Open-ExaCopyLatestVersion $client '1.2.3'
    $cdn = 'https://release-assets.githubusercontent.com/opaque/asset?signature=fixture'
    $http.Responses.Enqueue((New-OnlineFixtureResponse 302 $cdn))
    $payload = [Text.Encoding]::ASCII.GetBytes($mixed)
    $http.Responses.Enqueue((New-OnlineFixtureResponse 200 '' $payload))
    Receive-ExaCopyReleaseAsset $client $version 'SHA256SUMS.txt' $destination 4096
    if ([Text.Encoding]::ASCII.GetString($destination.ToArray()) -cne $mixed -or
        ($http.Requests -join "`n") -cne (
            "HEAD $ExaCopyGitHubRepository/releases/latest`n" +
            "GET $ExaCopyGitHubRepository/releases/download/v1.2.3/SHA256SUMS.txt`nGET $cdn"
        )) { throw 'Latest selection did not freeze the tag-scoped release fetch.' }

    $http.Responses.Enqueue((New-OnlineFixtureResponse 302 $cdn))
    $http.Responses.Enqueue((New-OnlineFixtureResponse 302 $cdn))
    Assert-Refuses { Receive-ExaCopyReleaseAsset $client $version $asset $destination 4096 } 'A second redirect was followed.'
    $http.Responses.Enqueue((New-OnlineFixtureResponse 302 'https://example.invalid/asset'))
    Assert-Refuses { Receive-ExaCopyReleaseAsset $client $version $asset $destination 4096 } 'A foreign redirect was followed.'
    $http.Responses.Enqueue((New-OnlineFixtureResponse 200 '' $payload))
    Assert-Refuses { Receive-ExaCopyReleaseAsset $client $version $asset $destination 3 } 'Oversized Content-Length was admitted.'
    $body = [IO.MemoryStream]::new($payload, $false)
    try {
        Assert-Refuses { Copy-ExaCopyBoundedStream $body $destination 3 } 'Oversized actual stream was admitted.'
    }
    finally { $body.Dispose() }
}
finally {
    $destination.Dispose()
    $client.Dispose()
}

$zipBytes = New-OnlineFixtureArchive $ExaCopyReleaseFiles
$members = Test-OnlineFixtureArchive $zipBytes
if ($members.Count -ne 3) { throw 'Canonical release ZIP entry count differs.' }
foreach ($badNames in @(
    @('release.manifest', 'release.sig', '../exacopy.exe')
    @('release.manifest', 'release.sig', 'EXACOPY.EXE')
    @('release.manifest', 'release.sig', 'EXACOPY:EX')
    @('release.manifest', 'release.sig', 'release.sig')
    @('release.manifest', 'release.sig', 'exacopy.exe', 'new.txt')
)) {
    $bad = New-OnlineFixtureArchive $badNames
    Assert-Refuses { Test-OnlineFixtureArchive $bad } 'Invalid release ZIP entries were admitted.'
}
foreach ($attributes in @(0x10, 0x400, -1610612736)) {
    $bad = New-OnlineFixtureArchive $ExaCopyReleaseFiles 'exacopy.exe' $attributes
    Assert-Refuses { Test-OnlineFixtureArchive $bad } 'Release ZIP nonregular member was admitted.'
}
$bad = [byte[]]$zipBytes.Clone()
$bad[30] = 0x58
Assert-Refuses { Test-OnlineFixtureArchive $bad } 'Local and central ZIP names differed.'
Assert-Refuses { Test-OnlineFixtureArchive ([byte[]]($zipBytes + 0)) } 'Release ZIP trailing data was admitted.'

$downloadFixture = [IO.Directory]::CreateTempSubdirectory('exacopy-online-fixture-')
$created = [Collections.Generic.List[string]]::new()
$fixtureStream = [IO.MemoryStream]::new($zipBytes, $false)
try {
    Assert-Refuses {
        Expand-ExaCopyReleaseArchive $fixtureStream ('0' * 64) $downloadFixture.FullName $created
    } 'Release ZIP with a mismatching SHA-256 was admitted.'
    Assert-ExaCopyExactEntries $downloadFixture.FullName @()
    Expand-ExaCopyReleaseArchive $fixtureStream (Get-ExaCopySha256 $zipBytes) $downloadFixture.FullName $created
    Assert-ExaCopyExactEntries $downloadFixture.FullName $ExaCopyReleaseFiles
    foreach ($name in $created) {
        if ([IO.File]::ReadAllText((Join-Path $downloadFixture.FullName $name)) -cne "fixture $name") {
            throw 'Release ZIP member bytes changed during extraction.'
        }
    }
}
finally {
    $fixtureStream.Dispose()
    foreach ($name in $created) { [IO.File]::Delete((Join-Path $downloadFixture.FullName $name)) }
    [IO.Directory]::Delete($downloadFixture.FullName, $false)
}
