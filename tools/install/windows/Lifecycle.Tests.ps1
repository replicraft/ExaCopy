#Requires -Version 7.4
param([string] $Artifact)

Describe 'Offline installer lifecycle on user-owned local NTFS' {
    BeforeAll {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        if (!$IsWindows) { throw 'Lifecycle qualification requires native Windows.' }

        . (Join-Path $PSScriptRoot 'paths.ps1')
        . (Join-Path $PSScriptRoot 'release.ps1')
        . (Join-Path $PSScriptRoot 'lifecycle.ps1')
        . (Join-Path $PSScriptRoot 'fixture-tools.ps1')

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $owner = $identity.User
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                throw 'Lifecycle qualification requires a non-elevated owner.'
            }
        }
        finally { $identity.Dispose() }

        function New-CaseContext {
            param([string] $Name)
            $local = Join-Path $fixture $Name
            $programs = Join-Path $local 'Programs'
            [void][IO.Directory]::CreateDirectory($local)
            # The fixture only assembles a private path context. Install and
            # uninstall themselves run without mocks or production overrides.
            [pscustomobject]@{
                Local = $local
                Programs = $programs
                Root = Join-Path $programs 'ExaCopy'
                Owner = $owner
                Target = $target
                Version = '1.2.3'
                CertificatePath = $trustFile
                PublisherSha256 = $pin
            }
        }

        function Assert-ExactFile {
            param([string] $Path, [string] $ExpectedDigest)
            (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly $ExpectedDigest
        }

        $localApp = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
        Assert-ExaCopyInstallAncestors $localApp $owner
        $fixture = New-ExaCopyPrivateStage $localApp $owner
        Write-Host "Disposable Windows installer evidence root: $fixture"
        $target = Get-ExaCopyTarget
        Assert-ExaCopyWindowsFloor ([Version]'10.0.20348')

        $bundle = Join-Path $fixture 'bundle'
        [void][IO.Directory]::CreateDirectory($bundle)
        $trustFile = Join-Path $fixture 'synthetic-publisher.der'
        $bundleExe = Join-Path $bundle 'exacopy.exe'
        if ([string]::IsNullOrWhiteSpace($Artifact)) {
            Write-ExaCopyNewBytes $bundleExe (New-ExecutableHeader ($ExaCopyMachine[$target]))
            Write-Host 'Using a synthetic PE header for lifecycle verification.'
        }
        else {
            $artifactPath = Resolve-ExaCopyWindowsPath $Artifact
            [void](Confirm-ExaCopyPath $artifactPath -File)
            $inputFile = [IO.FileStream]::new($artifactPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                if ($inputFile.Length -le 0 -or $inputFile.Length -gt $ExaCopyArtifactLimit) {
                    throw 'The optional fixture artifact exceeds the release profile bounds.'
                }
                Assert-ExaCopyExecutableHeader $inputFile $target
                $outputFile = [IO.FileStream]::new($bundleExe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $inputFile.CopyTo($outputFile)
                    $outputFile.Flush($true)
                }
                finally { $outputFile.Dispose() }
            }
            finally { $inputFile.Dispose() }
            Write-Host 'Using the supplied native CLI artifact. It will not be executed.'
        }
        $artifactHash = (Get-FileHash -LiteralPath $bundleExe -Algorithm SHA256).Hash.ToLowerInvariant()
        $artifactLength = [IO.FileInfo]::new($bundleExe).Length

        $now = [DateTimeOffset]::UtcNow
        $publisher = New-FixturePublisher $now
        try {
            $pin = Get-ExaCopySha256 $publisher.Certificate
            $manifest = New-FixtureManifest $pin $artifactHash ($now.ToUnixTimeSeconds()) $artifactLength $target 3600
            $signature = $publisher.SigningKey.SignData(
                $manifest, [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            Write-ExaCopyNewBytes $trustFile $publisher.Certificate
            Write-ExaCopyNewBytes (Join-Path $bundle 'release.manifest') $manifest
            Write-ExaCopyNewBytes (Join-Path $bundle 'release.sig') $signature
        }
        finally { $publisher.SigningKey.Dispose() }

        $protected = [ordered]@{}
        foreach ($relative in @('profile/owner.seed', 'profile/settings.json', 'jobs/0001.exajnl', 'repository/objects/42')) {
            $path = Join-Path $fixture $relative
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
            $bytes = [Text.Encoding]::UTF8.GetBytes("synthetic preserved fixture: $relative")
            Write-ExaCopyNewBytes $path $bytes
            $protected[$path] = Get-ExaCopySha256 $bytes
        }
    }

    AfterEach {
        foreach ($path in $protected.Keys) {
            Assert-ExactFile $path $protected[$path]
        }
        Assert-ExactFile $bundleExe $artifactHash
    }

    It 'publishes exclusively, repeats idempotently, and uninstalls and reinstalls the same release' {
        $context = New-CaseContext 'successful-lifecycle'
        $preview = Install-ExaCopySignedVersion $bundle $context -DryRun
        $preview.status | Should -BeExactly 'would_install'
        (Get-ExaCopyNodeExists $context.Programs) | Should -BeFalse

        $first = Install-ExaCopySignedVersion $bundle $context
        $first.status | Should -BeExactly 'installed'
        $first.path | Should -BeExactly (Join-Path $context.Root 'versions/1.2.3/exacopy.exe')
        Assert-ExactFile $first.path $artifactHash
        (Install-ExaCopySignedVersion $bundle $context).status | Should -BeExactly 'already_installed'
        (Uninstall-ExaCopySignedVersion $context -DryRun).status | Should -BeExactly 'would_uninstall'
        { Uninstall-ExaCopySignedVersion $context } | Should -Throw '*Quiesced*'
        Assert-ExactFile $first.path $artifactHash

        (Uninstall-ExaCopySignedVersion $context -Quiesced).status | Should -BeExactly 'uninstalled'
        (Get-ExaCopyNodeExists $first.path) | Should -BeFalse
        Assert-ExactFile (Join-Path $context.Root 'release.manifest') (Get-ExaCopySha256 $manifest)
        Assert-ExactFile (Join-Path $context.Root 'release.sig') (Get-ExaCopySha256 $signature)
        (Uninstall-ExaCopySignedVersion $context -Quiesced).status | Should -BeExactly 'already_absent'
        (Install-ExaCopySignedVersion $bundle $context).status | Should -BeExactly 'installed'
        Assert-ExactFile $first.path $artifactHash
        (Uninstall-ExaCopySignedVersion $context -Quiesced).status | Should -BeExactly 'uninstalled'
    }

    It 'refuses an unowned root and a junction without modifying either incumbent' {
        $context = New-CaseContext 'path-conflicts'
        [void][IO.Directory]::CreateDirectory($context.Root)
        $incumbent = Join-Path $context.Root 'user-data'
        $unowned = [Text.Encoding]::UTF8.GetBytes('synthetic unowned directory entry')
        Write-ExaCopyNewBytes $incumbent $unowned
        { Install-ExaCopySignedVersion $bundle $context } | Should -Throw
        { Uninstall-ExaCopySignedVersion $context -Quiesced } | Should -Throw
        Assert-ExactFile $incumbent (Get-ExaCopySha256 $unowned)

        $linked = New-CaseContext 'reparse'
        [void][IO.Directory]::CreateDirectory($linked.Programs)
        $outside = [IO.Directory]::CreateDirectory((Join-Path $fixture 'junction-target')).FullName
        $sentinel = Join-Path $outside 'untouched'
        Write-ExaCopyNewBytes $sentinel $unowned
        [void](New-Item -ItemType Junction -Path $linked.Root -Target $outside)
        try {
            { Install-ExaCopySignedVersion $bundle $linked } | Should -Throw '*reparse point*'
            { Uninstall-ExaCopySignedVersion $linked -Quiesced } | Should -Throw '*reparse point*'
            Assert-ExactFile $sentinel (Get-ExaCopySha256 $unowned)
        }
        finally { [IO.Directory]::Delete($linked.Root, $false) }
        Assert-ExactFile $sentinel (Get-ExaCopySha256 $unowned)
    }

    It 'preserves a modified, busy, or unexpectedly populated version until exact ownership is verified' {
        $context = New-CaseContext 'ownership-controls'
        $install = Install-ExaCopySignedVersion $bundle $context
        $exe = $install.path
        $version = [IO.Path]::GetDirectoryName($exe)

        $extra = Join-Path $version 'unowned'
        $bytes = [Text.Encoding]::UTF8.GetBytes('synthetic extra version file')
        Write-ExaCopyNewBytes $extra $bytes
        { Uninstall-ExaCopySignedVersion $context -Quiesced } | Should -Throw '*unexpected entry*'
        Assert-ExactFile $extra (Get-ExaCopySha256 $bytes)
        Assert-ExactFile $exe $artifactHash
        [IO.File]::Delete($extra)

        $locked = [IO.FileStream]::new($exe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try {
            { Uninstall-ExaCopySignedVersion $context -Quiesced } | Should -Throw
            $locked.Length | Should -Be $artifactLength
        }
        finally { $locked.Dispose() }
        Assert-ExactFile $exe $artifactHash

        $file = [IO.FileStream]::new($exe, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $last = $file.Length - 1
            $file.Position = $last
            $previous = $file.ReadByte()
            $file.Position = $last
            $file.WriteByte([byte]($previous -bxor 0xff))
            $file.Flush($true)
        }
        finally { $file.Dispose() }
        $changed = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $changed | Should -Not -Be $artifactHash
        { Install-ExaCopySignedVersion $bundle $context } | Should -Throw '*SHA-256*'
        { Uninstall-ExaCopySignedVersion $context -Quiesced } | Should -Throw '*SHA-256*'
        Assert-ExactFile $exe $changed
        $file = [IO.FileStream]::new($exe, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $file.Position = $last
            $file.WriteByte([byte]$previous)
            $file.Flush($true)
        }
        finally { $file.Dispose() }
        Assert-ExactFile $exe $artifactHash

        $stream = 'ExaCopy-UnownedLifecycleFixture'
        Set-Content -LiteralPath $exe -Stream $stream -NoNewline -Value 'synthetic named stream'
        { Uninstall-ExaCopySignedVersion $context -Quiesced } | Should -Throw '*named NTFS stream*'
        Get-Content -LiteralPath $exe -Stream $stream -Raw | Should -BeExactly 'synthetic named stream'
        Assert-ExactFile $exe $artifactHash
        Remove-Item -LiteralPath $exe -Stream $stream

        $directory = [IO.DirectoryInfo]::new($version)
        $before = [IO.FileSystemAclExtensions]::GetAccessControl($directory)
        $modified = [IO.FileSystemAclExtensions]::GetAccessControl($directory)
        $everyone = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::WorldSid, $null)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $everyone, [Security.AccessControl.FileSystemRights]::Write,
            [Security.AccessControl.AccessControlType]::Allow)
        $modified.AddAccessRule($rule)
        [IO.FileSystemAclExtensions]::SetAccessControl($directory, $modified)
        try {
            { Uninstall-ExaCopySignedVersion $context -Quiesced } | Should -Throw '*owner-only ACL*'
            Assert-ExactFile $exe $artifactHash
        }
        finally { [IO.FileSystemAclExtensions]::SetAccessControl($directory, $before) }

        (Uninstall-ExaCopySignedVersion $context -Quiesced).status | Should -BeExactly 'uninstalled'
    }
}
