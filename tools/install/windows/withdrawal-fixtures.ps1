# Test-only Windows version withdrawal controls. Loading this file has no effects.
function Get-FixtureRefusal {
    param([scriptblock] $Attempt)
    try { [void](& $Attempt) }
    catch { return $_.Exception.Message }
    throw 'Expected the installer fixture to refuse.'
}

function Invoke-FixtureWithdrawalFault {
    param($Context)

    $exactEntries = ${function:Assert-ExaCopyExactEntries}
    $programs = $Context.Programs
    # Local function scope restores the shipped helper on return, including on error.
    function Assert-ExaCopyExactEntries {
        param([string] $Directory, [string[]] $Names)
        & $exactEntries $Directory $Names
        if ([IO.Path]::GetDirectoryName($Directory) -ceq $programs -and
            [IO.Path]::GetFileName($Directory) -cmatch '\A[.]ExaCopy-version-retired-[0-9a-f]{32}\z' -and
            ($null -eq $Names -or $Names.Count -eq 0)) {
            throw 'Fixture stopped after removing the retired version marker.'
        }
    }

    Uninstall-ExaCopySignedVersion $Context -Quiesced
}

function Test-ExaCopyWithdrawalRetry {
    param([string] $Bundle, $Context, $Signed, [string] $Executable)

    $versionPath = [IO.Path]::GetDirectoryName($Executable)
    $versions = [IO.Path]::GetDirectoryName($versionPath)
    $bin = Join-Path $Context.Root 'bin'
    $lookalikeName = '.ExaCopy-version-retired-' + ('0' * 32)
    $lookalike = Join-Path $Context.Programs $lookalikeName
    [void][IO.Directory]::CreateDirectory($lookalike)
    $sentinel = Join-Path $lookalike 'unrelated.txt'
    [IO.File]::WriteAllText($sentinel, 'preserve a retirement-looking directory')
    if ((Install-ExaCopySignedVersion $Bundle $Context).status -cne 'installed') {
        throw 'Could not reinstall the exact package for the withdrawal control.'
    }

    $failure = Get-FixtureRefusal { Invoke-FixtureWithdrawalFault $Context }
    $retired = @([IO.Directory]::EnumerateDirectories($Context.Programs, '.ExaCopy-version-retired-*') |
        Where-Object { $_ -cne $lookalike })
    if ($retired.Count -ne 1) { throw "Expected one retired version directory. $failure" }
    $prefix = "Version withdrawal to '$($retired[0])' completed but cleanup could not be confirmed."
    if (!$failure.StartsWith($prefix, [StringComparison]::Ordinal) -or
        !$failure.EndsWith('Fixture stopped after removing the retired version marker.', [StringComparison]::Ordinal) -or
        (Get-ExaCopyNodeExists $bin)) {
        throw "The withdrawal fault did not retain exact retirement evidence. $failure"
    }
    Assert-ExaCopyExactEntries $versions @()
    Assert-ExaCopyExactEntries $retired[0] @()
    if ((Uninstall-ExaCopySignedVersion $Context -Quiesced).status -cne 'already_absent') {
        throw 'Uninstall retry did not recognize that the live version was withdrawn.'
    }

    # An old interrupted uninstall can leave an empty live path with no ownership proof.
    [void][IO.Directory]::CreateDirectory($versionPath)
    $installRefusal = Get-FixtureRefusal { Install-ExaCopySignedVersion $Bundle $Context }
    $removeRefusal = Get-FixtureRefusal { Uninstall-ExaCopySignedVersion $Context -Quiesced }
    if ($installRefusal -cnotlike 'Version directory is incomplete.*' -or
        $removeRefusal -cne 'Directory lacks one or more required entries.' -or (Get-ExaCopyNodeExists $bin)) {
        throw 'An unmarked live version was not refused at the ownership boundary.'
    }
    Assert-ExaCopyExactEntries $versionPath @()
    [IO.Directory]::Delete($versionPath, $false)

    if ((Install-ExaCopySignedVersion $Bundle $Context).status -cne 'installed') {
        throw 'Retirement evidence blocked reinstall of the exact package.'
    }
    Confirm-ExaCopyArtifact $Executable $Signed.Release
    if ((Uninstall-ExaCopySignedVersion $Context -Quiesced).status -cne 'uninstalled' -or
        (Get-ExaCopyNodeExists $bin) -or
        [IO.File]::ReadAllText($sentinel) -cne 'preserve a retirement-looking directory') {
        throw 'Normal cleanup did not preserve the unrelated sibling.'
    }
    Assert-ExaCopyExactEntries $versions @()
    Assert-ExaCopyExactEntries $Context.Programs @('ExaCopy', $lookalikeName, [IO.Path]::GetFileName($retired[0]))
    Assert-ExaCopyExactEntries $retired[0] @()
    Assert-ExaCopyExactEntries $lookalike @('unrelated.txt')
    [IO.Directory]::Delete($retired[0], $false)
    [IO.File]::Delete($sentinel)
    [IO.Directory]::Delete($lookalike, $false)
    Write-Output 'Windows verified withdrawal retry, legacy unmarked version refusal, and unrelated sibling preservation.'
}

function Test-ExaCopyPrivateWithdrawal {
    param([byte[]] $Certificate, [Security.Cryptography.RSA] $SigningKey, [long] $Epoch)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $fixtureOwner = $identity.User }
    finally { $identity.Dispose() }
    $fixtureAnchor = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
    $fixtureAncestry = Open-ExaCopyProductAncestry $fixtureAnchor $fixtureOwner
    try {
        Assert-ExaCopyInstallAncestors $fixtureAnchor $fixtureOwner $fixtureAncestry
        $fixtureLocal = New-ExaCopyPrivateStage $fixtureAnchor $fixtureOwner
        Write-Output "Disposable Windows withdrawal fixture: $fixtureLocal"
        $fixturePrograms = Join-Path $fixtureLocal 'Programs'
        $installRoot = Join-Path $fixturePrograms 'ExaCopy'
        $bundle = Join-Path $fixtureLocal 'bundle'
        $certificatePath = Join-Path $fixtureLocal 'publisher.der'
        [void][IO.Directory]::CreateDirectory($fixturePrograms)
        [void][IO.Directory]::CreateDirectory($bundle)
        $target = Get-ExaCopyTarget
        $payload = New-ExecutableHeader ($ExaCopyMachine[$target])
        $pin = Get-ExaCopySha256 $Certificate
        $manifest = New-FixtureManifest $pin (Get-ExaCopySha256 $payload) $Epoch $payload.Length $target 3600
        $signature = $SigningKey.SignData($manifest, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        Write-ExaCopyNewBytes $certificatePath $Certificate
        Write-ExaCopyNewBytes (Join-Path $bundle 'release.manifest') $manifest
        Write-ExaCopyNewBytes (Join-Path $bundle 'release.sig') $signature
        Write-ExaCopyNewBytes (Join-Path $bundle 'exacopy.exe') $payload
        $fixtureScope = [object]::new()
        $fixtureContext = [pscustomobject]@{
            Local = $fixtureLocal; Programs = $fixturePrograms; Root = $installRoot
            Owner = $fixtureOwner; Target = $target; Version = '1.2.3'
            CertificatePath = $certificatePath; PublisherSha256 = $pin
            WithdrawalFixtureScope = $fixtureScope
        }

        # The real known-folder handle admits the parent of the private case.
        # Its production Programs method does not accept a test path.
        $realAncestors = ${function:Assert-ExaCopyContextAncestors}
        function Assert-ExaCopyContextAncestors {
            param($Context, [string] $Path)
            $scope = $Context.PSObject.Properties['WithdrawalFixtureScope']
            if ($null -eq $scope -or ![object]::ReferenceEquals($scope.Value, $fixtureScope)) {
                & $realAncestors $Context $Path
                return
            }
            if ($Context.Local -cne $fixtureLocal -or $Context.Programs -cne $fixturePrograms -or
                $Context.Root -cne $installRoot -or $Context.Owner.Value -cne $fixtureOwner.Value -or
                ($Path -cne $fixtureLocal -and $Path -cne $fixturePrograms)) {
                throw 'Unexpected mutation parent in the private withdrawal fixture.'
            }
            Assert-ExaCopyInstallAncestors $fixtureAnchor $fixtureOwner $fixtureAncestry
            Confirm-ExaCopyOwnerAcl $fixtureLocal $fixtureOwner -Root
            Confirm-ExaCopyOwnerAcl $fixturePrograms $fixtureOwner
        }

        $signed = Read-ExaCopyReleaseFiles $bundle $fixtureContext $Certificate
        $expectedExecutable = Join-Path (Join-Path (Join-Path $installRoot 'versions') $fixtureContext.Version) 'exacopy.exe'
        $expectedLauncher = Join-Path (Join-Path $installRoot 'bin') 'exacopy.ps1'
        $installed = Install-ExaCopySignedVersion $bundle $fixtureContext
        if ($installed.status -cne 'installed' -or $installed.path -cne $expectedExecutable -or
            $installed.launcher -cne $expectedLauncher -or
            (Uninstall-ExaCopySignedVersion $fixtureContext -Quiesced).status -cne 'uninstalled') {
            throw 'The private withdrawal fixture did not establish its normal lifecycle control.'
        }
        Assert-ExaCopyExactEntries $fixturePrograms @('ExaCopy')
        Test-ExaCopyWithdrawalRetry $bundle $fixtureContext $signed $expectedExecutable

        Assert-ExaCopyExactEntries $fixtureLocal @('Programs', 'bundle', 'publisher.der')
        Assert-ExaCopyExactEntries $fixturePrograms @('ExaCopy')
        Assert-ExaCopyExactEntries $installRoot @('owner.marker', 'release.manifest', 'release.sig', 'versions')
        Assert-ExaCopyExactEntries (Join-Path $installRoot 'versions') @()
        Assert-ExaCopyExactEntries $bundle $ExaCopyReleaseFiles
        foreach ($name in @('owner.marker', 'release.manifest', 'release.sig')) {
            [IO.File]::Delete((Join-Path $installRoot $name))
        }
        foreach ($name in $ExaCopyReleaseFiles) { [IO.File]::Delete((Join-Path $bundle $name)) }
        [IO.File]::Delete($certificatePath)
        foreach ($directory in @((Join-Path $installRoot 'versions'), $installRoot, $fixturePrograms, $bundle, $fixtureLocal)) {
            [IO.Directory]::Delete($directory, $false)
        }
        if (Get-ExaCopyNodeExists $fixtureLocal) { throw 'The private withdrawal fixture was not removed.' }
        Write-Output 'Windows automatic withdrawal fixture completed on the disposable NTFS path.'
    }
    finally { $fixtureAncestry.Dispose() }
}
