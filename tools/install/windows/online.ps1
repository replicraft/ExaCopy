function Remove-ExaCopyDownloadStage {
    param([string] $Stage, [Collections.Generic.List[string]] $Created, $Context)

    Assert-ExaCopyContextAncestors $Context $Context.Local
    Confirm-ExaCopyOwnerAcl $Stage $Context.Owner -Root
    Assert-ExaCopyExactEntries $Stage ($Created.ToArray())
    Assert-ExaCopyNoNamedStreams $Stage
    foreach ($name in $Created) {
        $path = Join-Path $Stage $name
        [void](Confirm-ExaCopyPath $path -File)
        Assert-ExaCopyNoNamedStreams $path
    }
    foreach ($name in $Created) { [IO.File]::Delete((Join-Path $Stage $name)) }
    [IO.Directory]::Delete($Stage, $false)
}

function Install-ExaCopyLatestVersion {
    param($Context, [switch] $DryRun)

    $certificate = Read-ExaCopyBoundedBytes $Context.CertificatePath $ExaCopyCertLimit
    if ((Get-ExaCopySha256 $certificate) -cne $Context.PublisherSha256) {
        throw 'Publisher certificate does not match the independently supplied pin.'
    }
    Assert-ExaCopyWindowsFloor ([Version]'10.0.20348')
    Assert-ExaCopyContextAncestors $Context $Context.Local

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.MaxResponseHeadersLength = 16
    $handler.SslProtocols = [Security.Authentication.SslProtocols]::Tls12 -bor
        [Security.Authentication.SslProtocols]::Tls13
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('ExaCopy-installer/1')
    $stage = $null
    $created = [Collections.Generic.List[string]]::new()
    try {
        $Context.Version = Open-ExaCopyLatestVersion $client $Context.Version
        $archiveName = "exacopy-cli-$($Context.Target).zip"
        $checksums = [IO.MemoryStream]::new()
        try {
            Receive-ExaCopyReleaseAsset $client $Context.Version 'SHA256SUMS.txt' $checksums $ExaCopyReleaseChecksumsLimit
            $expected = Get-ExaCopyReleaseAssetDigest ($checksums.ToArray()) $archiveName
        }
        finally { $checksums.Dispose() }

        Assert-ExaCopyContextAncestors $Context $Context.Local
        $stage = New-ExaCopyPrivateStage $Context.Local $Context.Owner
        $archivePath = Join-Path $stage $archiveName
        $archive = [IO.FileStream]::new($archivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $created.Add($archiveName)
        try {
            Receive-ExaCopyReleaseAsset $client $Context.Version $archiveName $archive $ExaCopyReleaseZipLimit
            $archive.Flush($true)
            Expand-ExaCopyReleaseArchive $archive $expected $stage $created
        }
        finally { $archive.Dispose() }

        Confirm-ExaCopyOwnerAcl $stage $Context.Owner -Root
        Assert-ExaCopyExactEntries $stage ($created.ToArray())
        [void](Confirm-ExaCopyPath $archivePath -File)
        Assert-ExaCopyNoNamedStreams $archivePath
        Assert-ExaCopyContextAncestors $Context $Context.Local
        [IO.File]::Delete($archivePath)
        [void]$created.Remove($archiveName)

        Assert-ExaCopyNoNamedStreams $stage
        foreach ($name in $created) {
            $path = Join-Path $stage $name
            [void](Confirm-ExaCopyPath $path -File)
            Assert-ExaCopyNoNamedStreams $path
        }
        return Install-ExaCopySignedVersion $stage $Context -DryRun:$DryRun
    }
    finally {
        $client.Dispose()
        if ($null -ne $stage) {
            try { Remove-ExaCopyDownloadStage $stage $created $Context }
            catch { [Console]::Error.WriteLine("ExaCopy download stage '$stage' retained. $($_.Exception.Message)") }
        }
    }
}
