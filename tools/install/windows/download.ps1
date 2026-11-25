# The moving endpoint is used only to discover the stable tag. Every asset
# comes from that tag through an explicitly checked single CDN redirect.
$ExaCopyGitHubRepository = 'https://github.com/replicraft/ExaCopy'
$ExaCopyReleaseChecksumsLimit = 4096
$ExaCopyReleaseZipLimit = 257MB
$ExaCopyWindowsArchivePattern = 'exacopy-cli-(?:aarch64|x86_64)-pc-windows-msvc\.zip'
$ExaCopyReleaseArchivePattern = "(?:$ExaCopyWindowsArchivePattern|exacopy-cli-(?:aarch64|x86_64)-(?:apple-darwin|unknown-linux-gnu)\.tar\.gz)"

function Get-ExaCopyReleaseVersion {
    param([uri] $Location, [string] $Expected)

    $path = '/replicraft/ExaCopy/releases/tag/v'
    $origin = 'https://github.com'
    if ($null -eq $Location) { throw 'GitHub did not provide a latest release location.' }
    $value = $Location.OriginalString
    $prefix = if ($Location.IsAbsoluteUri) { $origin + $path } else { $path }
    if (!$value.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw 'GitHub latest did not select a tag in the ExaCopy repository.'
    }
    $resolved = $value.Substring($prefix.Length)
    if ($resolved -cnotmatch $ExaCopyVersionPattern) {
        throw 'GitHub latest did not select a canonical stable vN.N.N tag.'
    }
    if ($Expected -and $resolved -cne $Expected) {
        throw 'The latest ExaCopy release differs from the requested version.'
    }
    return $resolved
}

function Confirm-ExaCopyReleaseAssetLocation {
    param([uri] $Location)

    if ($null -eq $Location -or !$Location.IsAbsoluteUri -or
        $Location.OriginalString -cnotmatch '\Ahttps://(?:release-assets|objects)\.githubusercontent\.com/[^\x00-\x20\x7f-\uffff\\#]+\z' -or
        $Location.UserInfo.Length -ne 0 -or !$Location.IsDefaultPort) {
        throw 'GitHub redirected a release asset outside its approved HTTPS asset hosts.'
    }
}

function Open-ExaCopyLatestVersion {
    param([Net.Http.HttpClient] $Client, [string] $Expected)

    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Head, "$ExaCopyGitHubRepository/releases/latest")
    try {
        $response = $Client.Send($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
        try {
            if ($response.StatusCode -ne [Net.HttpStatusCode]::Found) {
                throw "GitHub did not provide a latest ExaCopy release (HTTP $([int]$response.StatusCode))."
            }
            return Get-ExaCopyReleaseVersion $response.Headers.Location $Expected
        }
        finally { $response.Dispose() }
    }
    finally { $request.Dispose() }
}

function Copy-ExaCopyBoundedStream {
    param(
        [IO.Stream] $Source, [IO.Stream] $Destination, [long] $Limit,
        [Threading.CancellationToken] $CancellationToken = [Threading.CancellationToken]::None
    )

    $buffer = [byte[]]::new(128KB)
    $copied = 0L
    while ($true) {
        $count = $Source.ReadAsync($buffer, 0, $buffer.Length, $CancellationToken).GetAwaiter().GetResult()
        if ($count -eq 0) { break }
        if ($count -gt $Limit - $copied) { throw 'Release stream exceeds its byte limit.' }
        $Destination.Write($buffer, 0, $count)
        $copied += $count
    }
    return $copied
}

function Receive-ExaCopyReleaseAsset {
    param(
        [Net.Http.HttpClient] $Client, [string] $Version, [string] $Name,
        [IO.Stream] $Destination, [long] $Limit
    )

    if ($Version -cnotmatch $ExaCopyVersionPattern -or
        ($Name -cne 'SHA256SUMS.txt' -and $Name -cnotmatch "\A$ExaCopyWindowsArchivePattern\z")) {
        throw 'The release asset is outside the stable CLI profile.'
    }
    $uri = [uri]"$ExaCopyGitHubRepository/releases/download/v$Version/$Name"
    $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromMinutes(5))
    try {
        for ($hop = 0; $hop -le 1; $hop++) {
            $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
            try {
                $response = $Client.Send($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token)
                try {
                    $status = [int]$response.StatusCode
                    if ($hop -eq 0 -and $response.StatusCode -eq [Net.HttpStatusCode]::Found) {
                        $uri = $response.Headers.Location
                        Confirm-ExaCopyReleaseAssetLocation $uri
                        continue
                    }
                    if ($status -ne 200) {
                        throw "Unable to obtain $Name for ExaCopy v$Version (HTTP $status)."
                    }
                    $declared = $response.Content.Headers.ContentLength
                    if ($null -ne $declared -and ($declared -le 0 -or $declared -gt $Limit)) {
                        throw 'Release asset Content-Length is outside its byte limit.'
                    }
                    $stream = $response.Content.ReadAsStream($deadline.Token)
                    try { $copied = Copy-ExaCopyBoundedStream $stream $Destination $Limit $deadline.Token }
                    finally { $stream.Dispose() }
                    if ($copied -eq 0 -or ($null -ne $declared -and $copied -ne $declared)) {
                        throw 'Release asset is empty or differs from its declared byte length.'
                    }
                    return
                }
                finally { $response.Dispose() }
            }
            finally { $request.Dispose() }
        }
    }
    finally { $deadline.Dispose() }
}

function Get-ExaCopyReleaseAssetDigest {
    param([byte[]] $Bytes, [string] $Name)

    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt $ExaCopyReleaseChecksumsLimit -or
        $Bytes[$Bytes.Length - 1] -ne 10) {
        throw 'SHA256SUMS.txt exceeds its byte limit or lacks its final LF.'
    }
    $lines = [Text.Encoding]::ASCII.GetString($Bytes).Split([char]10)
    $previous = ''
    $digest = ''
    $pattern = "\A([0-9a-f]{64})  ($ExaCopyReleaseArchivePattern)\z"
    for ($index = 0; $index -lt $lines.Length - 1; $index++) {
        $match = [Regex]::Match($lines[$index], $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if (!$match.Success) { throw 'SHA256SUMS.txt contains an invalid release archive record.' }
        $file = $match.Groups[2].Value
        if ([string]::CompareOrdinal($previous, $file) -ge 0) {
            throw 'SHA256SUMS.txt contains duplicate or unsorted release archives.'
        }
        if ($file -ceq $Name) { $digest = $match.Groups[1].Value }
        $previous = $file
    }
    if (!$digest) { throw "The latest release does not publish a checksum for $Name." }
    return $digest
}
