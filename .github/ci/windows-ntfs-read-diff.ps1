# Fixed local NTFS Read/Diff verification only. Sourcing this file performs no I/O.

function Get-ReadDiffHostedSystemVolume {
    param([string] $Parent)
    $path = 'replicraft/ExaCopy/.github/workflows/windows-ntfs-read-diff.yml@refs/heads/main'
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ARCH -cne 'X64' -or
        $env:GITHUB_SERVER_URL -cne 'https://github.com' -or $env:GITHUB_REPOSITORY -ine 'replicraft/ExaCopy' -or
        $env:GITHUB_EVENT_NAME -cne 'push' -or $env:GITHUB_REF -cne 'refs/heads/main' -or
        $env:GITHUB_WORKFLOW_REF -ine $path -or $env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or
        $env:GITHUB_WORKFLOW_SHA -cne $env:GITHUB_SHA -or $env:SystemDrive -notmatch '^[A-Z]:$' -or
        $Parent -ine $env:USERPROFILE) {
        throw 'Read/Diff qualification requires the selected canonical hosted push profile.'
    }
    $root = $env:SystemDrive + '\'
    if ($env:SystemRoot -ine ($root + 'Windows') -or
        [Environment]::SystemDirectory -ine ($root + 'Windows\System32') -or
        !$Parent.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or $Parent -ieq $root) {
        throw 'Read/Diff requires the hosted system volume and its fixture parent.'
    }
    return $root
}

function Assert-ReadDiffTreeSecurity {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner)
    $trusted = @($Owner.Value, 'S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.Owner -or $raw.Owner.Value -cnotin $trusted -or $null -eq $raw.DiscretionaryAcl -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) {
        throw 'A Read/Diff fixture entry lacks trusted ownership or a discretionary ACL.'
    }

    $write = [int][Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    # Generic write and generic all can also appear in a native ACE.
    $write = $write -bor 0x40000000 -bor 0x10000000
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceQualifier -notin @([Security.AccessControl.AceQualifier]::AccessAllowed,
                [Security.AccessControl.AceQualifier]::AccessDenied) -or
            ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
                $ace.SecurityIdentifier.Value -cnotin $trusted -and ($ace.AccessMask -band $write) -ne 0)) {
            throw 'A Read/Diff fixture entry permits unqualified custody or inherited competing changes.'
        }
    }
}

function Remove-ReadDiffBuildChildren {
    param([string] $Build, [string] $BuildIdentity, [Security.Principal.SecurityIdentifier] $Owner,
        [switch] $IncludeHidden)
    $directories = [Collections.Generic.Stack[object]]::new()
    $entries = [Collections.Generic.List[object]]::new()
    $links = @{}
    $directories.Push(@{ Path = $Build; Depth = 0 })
    try {
        while ($directories.Count -ne 0) {
            $parent = $directories.Pop()
            if ($parent.Depth -ge 64) { throw 'Read/Diff build tree exceeds its depth bound.' }
            foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($parent.Path)) {
                if ($entries.Count -ge 4096) { throw 'Read/Diff build tree exceeds its entry bound.' }
                $directory = ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::Directory) -ne 0
                $pin = [ExaCopyQualification.ReadDiffCustody]::HoldNode($path, $directory, $false)
                $entry = [pscustomobject]@{ Path = $path; Pin = $pin; Guard = $null; Directory = $directory; Node = $null }
                $entries.Add($entry)
                $node = [ExaCopyQualification.ReadDiffCustody]::Observe($pin, $directory)
                Assert-StageSameVolume $BuildIdentity $node.FileId
                Assert-ReadDiffTreeSecurity $path $Owner
                Assert-ExaCopyNoNamedStreams $path -IncludeHidden:$IncludeHidden
                $entry.Node = $node
                if ($directory) {
                    $entry.Guard = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($path)
                    Assert-StageSameIdentity $node.FileId ([ExaCopyQualification.DirectoryCustody]::Observe($entry.Guard))
                    $directories.Push(@{ Path = $path; Depth = $parent.Depth + 1 })
                } else {
                    $links[$node.FileId] = 1 + [int]$links[$node.FileId]
                }
            }
        }

        # Cargo may hard-link its owned build outputs. Every link must be inside
        # the admitted tree before any effect, including a link outside this build.
        foreach ($entry in $entries) {
            if (!$entry.Directory -and $entry.Node.Links -ne $links[$entry.Node.FileId]) {
                throw 'A Read/Diff build artifact has a hard link outside the inspected tree.'
            }
        }
        # Ordinary disposition can defer unlink while another alias has an
        # open handle. The protected, held parents and file IDs still govern
        # selection; release only our redundant multi-link observation pins.
        foreach ($entry in $entries) {
            if (!$entry.Directory -and $entry.Node.Links -gt 1) { $entry.Pin.Dispose() }
        }
        for ($index = $entries.Count - 1; $index -ge 0; $index--) {
            $entry = $entries[$index]
            Assert-ReadDiffTreeSecurity $entry.Path $Owner
            Assert-ExaCopyNoNamedStreams $entry.Path -IncludeHidden:$IncludeHidden
            if ($entry.Directory) {
                Assert-ExaCopyExactEntries $entry.Path @()
                $entry.Guard.Dispose()
            }
            $selected = [ExaCopyQualification.ReadDiffCustody]::HoldNode($entry.Path, $entry.Directory, $true)
            try {
                $current = [ExaCopyQualification.ReadDiffCustody]::Observe($selected, $entry.Directory)
                Assert-StageSameIdentity $entry.Node.FileId $current.FileId
                if (!$entry.Directory -and $current.Links -ne $links[$current.FileId]) {
                    throw 'The Read/Diff build artifact link count changed.'
                }
                [ExaCopyQualification.DirectoryCustody]::MarkForDeletion($selected)
                if (!$entry.Directory) { $links[$current.FileId]-- }
            } finally {
                $selected.Dispose()
            }
            $entry.Pin.Dispose()
            if (Get-ExaCopyNodeExists $entry.Path) {
                throw 'Read/Diff build entry absence was not confirmed.'
            }
        }
    } finally {
        foreach ($entry in $entries) {
            if ($null -ne $entry.Guard) { $entry.Guard.Dispose() }
            $entry.Pin.Dispose()
        }
    }
}

function Remove-HeldReadDiffFixture {
    param([string] $Fixture, [string] $Build, $Pin, $Guard, [string] $Identity, $BuildPin,
        [string] $BuildIdentity, [string] $Volume, $Ancestors, [switch] $IncludeHiddenBuildEntries)
    if ($null -eq $Pin -or $null -eq $Guard -or $null -eq $BuildPin) {
        throw 'Read/Diff fixture custody was not established.'
    }
    Confirm-StageAncestorCustody $Ancestors
    if ([ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($Ancestors.Held[0].Handle) -ine $Volume) {
        throw 'The original held NTFS volume identity changed.'
    }
    Assert-ReadDiffTreeSecurity $Fixture $Ancestors.Owner
    Assert-StageSameIdentity $Identity ([ExaCopyQualification.DirectoryCustody]::Observe($Pin))
    Assert-StageSameIdentity $Identity ([ExaCopyQualification.DirectoryCustody]::Observe($Guard))
    Assert-ExaCopyExactEntries $Fixture @([IO.Path]::GetFileName($Build))
    Assert-ExaCopyNoNamedStreams $Fixture
    Assert-ReadDiffTreeSecurity $Build $Ancestors.Owner
    Assert-ExaCopyNoNamedStreams $Build
    Assert-StageSameIdentity $BuildIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($BuildPin))
    $buildGuard = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($Build)
    try {
        Assert-StageSameIdentity $BuildIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($buildGuard))
        Remove-ReadDiffBuildChildren $Build $BuildIdentity $Ancestors.Owner -IncludeHidden:$IncludeHiddenBuildEntries
    } finally {
        $buildGuard.Dispose()
    }
    $namedBuild = [ExaCopyQualification.DirectoryCustody]::OpenForDisposition($Build)
    try {
        Assert-StageSameIdentity $BuildIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($namedBuild))
        Assert-ExaCopyExactEntries $Build @()
        Assert-ReadDiffTreeSecurity $Build $Ancestors.Owner
        Assert-ExaCopyNoNamedStreams $Build
        [ExaCopyQualification.DirectoryCustody]::MarkForDeletion($namedBuild)
    } finally {
        $namedBuild.Dispose()
    }
    $BuildPin.Dispose()
    Assert-ExaCopyExactEntries $Fixture @()
    $Guard.Dispose()
    $disposition = [ExaCopyQualification.DirectoryCustody]::OpenForDisposition($Fixture)
    try {
        Confirm-StageAncestorCustody $Ancestors
        Assert-StageSameIdentity $Identity ([ExaCopyQualification.DirectoryCustody]::Observe($Pin))
        Assert-StageSameIdentity $Identity ([ExaCopyQualification.DirectoryCustody]::Observe($disposition))
        Assert-ExaCopyExactEntries $Fixture @()
        Assert-ExaCopyNoNamedStreams $Fixture
        [ExaCopyQualification.DirectoryCustody]::MarkForDeletion($disposition)
    } finally {
        $disposition.Dispose()
    }
    $Pin.Dispose()
}

function Get-ReadDiffProfile {
    param([ValidateSet('Read', 'Diff')] [string] $Mode)
    if ($Mode -eq 'Read') {
        return @{
            Package = 'exacopy-platform'
            Manifest = 'crates/platform/exacopy-platform/Cargo.toml'
            Target = 'windows_read'
            Features = 'windows-read-fixture,experimental-windows-read'
            Ordinary = @(
                'directory_entries::tests::matches_exact_units_without_using_case_or_lossy_text'
                'directory_entries::tests::refuses_multiple_exact_observations_across_batches'
                'directory_entries::tests::refuses_truncated_odd_or_malformed_entry_boundaries'
                'directory_entries::tests::refuses_zero_ntfs_identifiers_and_the_object_id_namespace'
            )
            Native = @(
                'cases::ordinary_ntfs_opens_existing_child_by_component_and_reads_at_explicit_offsets'
                'cases::ordinary_ntfs_refuses_non_disk_and_existing_non_regular_child'
                'cases::ordinary_ntfs_refuses_an_existing_writer_with_shared_read_access'
                'cases::ordinary_ntfs_resolves_against_held_directory_after_its_path_is_reused'
                'cases::ordinary_ntfs_opens_an_exact_child_by_observed_ntfs_reference'
                'cases::ordinary_ntfs_rejects_a_file_moved_out_of_the_held_parent_before_open_by_id'
                'cases::refuses_reparse_leaf_and_parent'
                'native::comparison::tests::ordinary_ntfs_exact_comparison_uses_the_held_ntfs_views'
                'native::by_id::qualification::ordinary_ntfs_native_id_and_guid_match_the_independent_path_oracle'
                'native::by_id::qualification::ordinary_ntfs_native_case_and_surrogate_units_are_preserved'
                'native::by_id::qualification::ordinary_ntfs_native_renamed_parent_keeps_identity_when_old_path_becomes_junction'
                'native::by_id::qualification::ordinary_ntfs_native_held_parent_refuses_junction_during_each_raw_observation'
                'production::production_reader_refuses_changed_live_observation'
            )
        }
    }
    return @{
        Package = 'exacopy-cli'
        Manifest = 'apps/exacopy-cli/Cargo.toml'
        Target = 'windows_diff'
        Features = 'experimental-windows-diff'
        Ordinary = @('ntfs_profile_refuses_unavailable_or_unadmitted_input')
        Native = @(
            'native::ordinary_ntfs_compares_and_preserves_regular_files'
            'native::refuses_native_reparse_leaf_and_parent'
            'native::ordinary_ntfs_compares_hard_link_aliases_read_only'
            'native::ordinary_ntfs_refuses_raw_stream_dot_and_verbatim_operands'
        )
    }
}

function Assert-ReadDiffExactResult {
    param([string] $Name, [int] $ExitCode, [string] $Output)
    $escaped = [regex]::Escape($Name)
    $cases = [regex]::Matches($Output, '(?m)^test .+ \.\.\. [^\r\n]+\r?$')
    if ($ExitCode -ne 0 -or $cases.Count -ne 1 -or
        $cases[0].Value -cnotmatch "^test $escaped \.\.\. ok\r?$" -or
        $Output -cnotmatch '(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;') {
        throw "Exact native selector did not pass: $Name"
    }
}

function Convert-ReadDiffExecutableSeparators {
    param([string] $Reported)
    return $Reported.Replace([char]47, [char]92)
}

function Resolve-ReadDiffExecutablePath {
    param([string] $Reported, [string] $Build)
    # Cargo can mix separators in the hashed build directory. Preserve all
    # other spelling so the canonical and containment checks still refuse it.
    $path = Convert-ReadDiffExecutableSeparators $Reported
    if ($path -cnotmatch '\A[A-Za-z]:\\[^:]*\z' -or ![IO.Path]::IsPathFullyQualified($path) -or
        [IO.Path]::GetFullPath($path) -cne $path -or !(Test-ExaCopyUnderPath $path $Build)) {
        throw 'A selected executable escaped the private build directory.'
    }
    return $path
}

function Invoke-ExactReadDiff {
    param([string] $Mode, [string] $Build, [string] $EvidencePath, [string] $Repository)
    $selection = Get-ReadDiffProfile $Mode
    $arguments = @('+1.100.0', 'test', '--locked', '--offline', '--jobs', '2',
        '--target', 'x86_64-pc-windows-msvc', '-p', $selection.Package, '--test',
        $selection.Target, '--features', $selection.Features, '--no-run', '--message-format=json')
    if ((Invoke-Lane -Name 'exact_build' -Program 'cargo' -Arguments $arguments -QuietStdout) -ne 0) {
        throw 'The pinned Read/Diff build failed.'
    }
    $events = @(Get-Content -LiteralPath (Join-Path $EvidencePath 'exact_build.stdout.log') |
        ForEach-Object { ConvertFrom-Json -InputObject $_ -Depth 32 } |
        Where-Object { $_.reason -ceq 'compiler-artifact' -and $_.executable })
    $manifest = [IO.Path]::GetFullPath((Join-Path $Repository $selection.Manifest))
    $features = $selection.Features.Split(',') | Sort-Object -CaseSensitive
    $events = @($events | Where-Object {
        $_.manifest_path -and [IO.Path]::GetFullPath($_.manifest_path) -ieq $manifest -and
        ((@($_.features) | Sort-Object -CaseSensitive) -join ',') -ceq ($features -join ',')
    })
    $harness = @($events | Where-Object { $_.target.name -ceq $selection.Target -and
        $_.target.kind.Count -eq 1 -and $_.target.kind[0] -ceq 'test' -and $_.profile.test })
    if ($harness.Count -ne 1) { throw 'Expected exactly one selected Cargo test executable.' }
    $binary = Resolve-ReadDiffExecutablePath $harness[0].executable $Build
    $executables = @($binary)
    if ($Mode -eq 'Diff') {
        $cli = @($events | Where-Object { $_.target.name -ceq 'exacopy' -and
            $_.target.kind.Count -eq 1 -and $_.target.kind[0] -ceq 'bin' -and !$_.profile.test })
        if ($cli.Count -ne 1) { throw 'Expected exactly one selected Cargo CLI executable.' }
        $executables += Resolve-ReadDiffExecutablePath $cli[0].executable $Build
    }
    $fingerprints = [ordered]@{}
    foreach ($path in $executables) {
        [void](Confirm-ExaCopyPath $path -File)
        $fingerprints[$path] = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
    }
    $fingerprints | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidencePath 'executables.json')
    if ($Mode -eq 'Diff') { $env:EXACOPY_WINDOWS_QUALIFIED_CLI = $executables[1] }

    $tests = @($selection.Ordinary) + @($selection.Native)
    if ((Invoke-Lane -Name 'exact_inventory' -Program $binary -Arguments @('--list', '--format', 'terse')) -ne 0) {
        throw 'The selected native test inventory was unavailable.'
    }
    $inventory = Get-Content -LiteralPath (Join-Path $EvidencePath 'exact_inventory.stdout.log')
    foreach ($name in $tests) {
        if (@($inventory | Where-Object { $_ -ceq "${name}: test" }).Count -ne 1) {
            throw "Expected exactly one declared native test: $Name"
        }
    }
    $failed = 0
    foreach ($name in $tests) {
        $label = 'case-' + ($name -replace '::', '-')
        $arguments = @('--exact', $name, '--nocapture', '--test-threads=1')
        if ($name -cin $selection.Native) { $arguments += '--ignored' }
        try {
            $exitCode = Invoke-Lane -Name $label -Program $binary -Arguments $arguments
            $output = Get-Content -Raw -LiteralPath (Join-Path $EvidencePath ($label + '.stdout.log'))
            Assert-ReadDiffExactResult $name $exitCode $output
        } catch {
            Add-Content -LiteralPath (Join-Path $EvidencePath 'qualification-failures.txt') -Value $_
            $failed++
        }
    }
    foreach ($path in $executables) {
        [void](Confirm-ExaCopyPath $path -File)
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -cne $fingerprints[$path]) {
            throw 'A selected native executable changed during qualification.'
        }
    }
    return $failed
}
