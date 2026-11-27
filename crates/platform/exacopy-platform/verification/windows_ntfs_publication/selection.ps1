function Assert-PublicationApplicationAttributes {
    param([int] $Attributes)
    # RECALL_ON_OPEN and RECALL_ON_DATA_ACCESS are not FileAttributes enum names.
    $unavailable = [int][IO.FileAttributes]'Directory, Device, ReparsePoint, Offline' -bor 0x00440000
    if (($Attributes -band $unavailable) -ne 0) {
        throw 'The selected application is not an available regular file.'
    }
}

function Read-PublicationApplicationRecord {
    param([string] $Path, [IO.FileStream] $HeldImage)
    [void](Confirm-ExaCopyPath $Path -File)
    Assert-PublicationApplicationAttributes ([IO.File]::GetAttributes($Path))
    $image = if ($null -ne $HeldImage) {
        $HeldImage
    } else {
        [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    try {
        $size = $image.Length
        if ($size -le 0 -or $size -gt 128MB) {
            throw 'The selected application is empty or exceeds the fingerprint bound.'
        }
        [ordered]@{
            path = $Path
            bytes = $size
            sha256 = (Get-FileHash -InputStream $image -Algorithm SHA256).Hash
        }
    } finally {
        if ($null -eq $HeldImage) { $image.Dispose() }
    }
}

function Resolve-PublicationApplication {
    param([string] $Name)
    if ($Name -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]*\.[Ee][Xx][Ee]\z') {
        throw 'Resolve only an exact executable name.'
    }
    # Get-Command -All returns execution precedence order. Select an object
    # before reading Source, and fail closed if that first object is inadmissible.
    $commands = @(Get-Command -Name $Name -CommandType Application -All -ErrorAction Stop)
    if ($commands.Count -eq 0 -or $commands[0] -isnot [Management.Automation.ApplicationInfo]) {
        throw "The first PATH match is not an application: $Name"
    }
    $path = $commands[0].Source
    if ($path -isnot [string] -or $path.Length -gt 260 -or
        $path -cnotmatch '\A[A-Za-z]:\\[^:/<>"|?*\x00-\x1f]+\z' -or
        ($path -split '\\')[-1] -ine $Name -or (Resolve-ExaCopyWindowsPath $path) -cne $path) {
        throw "The first PATH match has no exact absolute executable path: $Name"
    }
    Read-PublicationApplicationRecord $path
}

function Resolve-PublicationCompiler {
    param([string] $RustupHome)
    # Match the hosted provisioning root and the fixed native toolchain. A
    # rustup proxy or another PATH image is never a candidate for this probe.
    $path = $RustupHome + '\toolchains\1.100.0-x86_64-pc-windows-msvc\bin\rustc.exe'
    if ($path.Length -gt 260 -or (Resolve-ExaCopyWindowsPath $path) -cne $path) {
        throw 'The provisioned compiler has no exact absolute executable path.'
    }
    [void](Confirm-ExaCopyPath $path -File)
    return $path
}

function Confirm-PublicationSource {
    param([string] $Repository, [string] $SelectedRevision)
    $revision = @(& git -C $Repository rev-parse --verify HEAD)
    if ($LASTEXITCODE -ne 0 -or $revision.Count -ne 1 -or $revision[0] -cne $SelectedRevision) {
        throw 'The checked-out source is not the selected event revision.'
    }
    $status = @(& git -C $Repository status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
        throw 'The exact qualification checkout must be clean.'
    }
}

function Get-PublicationCases {
    $prefix = 'windows::stage::publication::'
    return @{
        Ordinary = @(
            $prefix + 'native::tests::rename_buffer_has_counted_units_and_zero_replacement'
            $prefix + 'native::tests::native_refusals_keep_unknown_effects_distinct'
        )
        Native = @(
            $prefix + 'tests::absent_target_moves_original_closed_stage'
            $prefix + 'tests::late_incumbent_and_case_alias_are_preserved'
            $prefix + 'tests::writer_and_changed_stage_refuse_before_rename'
            $prefix + 'tests::bound_target_and_metadata_refusals_preserve_entries'
            $prefix + 'tests::native_success_with_observation_failure_requires_reconciliation'
        )
    }
}

function Select-PublicationExecutable {
    param([string[]] $Lines, [string] $Manifest, [string] $Source)
    $events = @($Lines | ForEach-Object { ConvertFrom-Json -InputObject $_ -Depth 32 -ErrorAction Stop } |
        Where-Object {
            $event = $_
            $_.reason -ceq 'compiler-artifact' -and $_.executable -and $_.fresh -is [bool] -and !$_.fresh -and
            $_.profile.test -is [bool] -and $_.profile.test -and
            $_.target.name -ceq 'exacopy_platform' -and
            $_.target.kind.Count -eq 1 -and $_.target.kind[0] -ceq 'lib' -and
            $_.target.crate_types.Count -eq 1 -and $_.target.crate_types[0] -ceq 'lib' -and
            $_.features.Count -eq 1 -and $_.features[0] -ceq 'experimental-windows-copy' -and
            $_.manifest_path -and $_.target.src_path -and
            (Convert-ReadDiffExecutableSeparators $_.manifest_path) -ceq $Manifest -and
            (Convert-ReadDiffExecutableSeparators $_.target.src_path) -ceq $Source -and
            @($_.filenames | Where-Object {
                (Convert-ReadDiffExecutableSeparators $_) -ceq
                    (Convert-ReadDiffExecutableSeparators $event.executable)
            }).Count -eq 1
        })
    if ($events.Count -ne 1) {
        throw 'Expected exactly one fresh experimental Windows platform library test image.'
    }
    return $events[0].executable
}

function Assert-PublicationInventory {
    param([string[]] $All, [string[]] $Ignored)
    $selection = Get-PublicationCases
    $prefix = 'windows::stage::publication::'
    foreach ($inventory in @(
        @{ Actual = $All; Expected = @($selection.Ordinary) + @($selection.Native) },
        @{ Actual = $Ignored; Expected = @($selection.Native) }
    )) {
        $actual = @($inventory.Actual | Where-Object {
            $_.StartsWith($prefix, [StringComparison]::Ordinal)
        } | Sort-Object -CaseSensitive)
        $expected = @($inventory.Expected | ForEach-Object { "${_}: test" } | Sort-Object -CaseSensitive)
        if (($actual -join [char]0) -cne ($expected -join [char]0)) {
            throw 'The held image inventory differs from the closed publication selectors or declared ignore state.'
        }
    }
}

function Assert-PublicationResult {
    param([string] $Name, [Nullable[uint32]] $ExitCode, [string] $Output)
    if ($null -eq $ExitCode) { throw "No process exit was obtained for $Name" }
    Assert-ReadDiffExactResult $Name $ExitCode $Output
    if ([regex]::Matches($Output, '(?m)^test result:').Count -ne 1 -or
        $Output -cnotmatch '(?m)^running 1 test\r?$') {
        throw "The held executable did not report a single independent test: $Name"
    }
}
