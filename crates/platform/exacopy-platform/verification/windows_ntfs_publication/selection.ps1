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

function Confirm-PublicationVendorPath {
    param([string] $Path, [switch] $File)
    if ($Path.Length -gt 260 -or $Path -cnotmatch '\A[A-Za-z]:\\[^:/;<>"|?*\x00-\x1f]+\z' -or
        (Resolve-ExaCopyWindowsPath $Path) -cne $Path) {
        throw 'The selected Visual Studio or SDK path is not a canonical local path.'
    }
    [void](Confirm-ExaCopyPath $Path -File:$File)
}

function Assert-PublicationVendorSignature {
    param([string] $Status, [string] $Signer)
    if ($Status -cne 'Valid' -or $Signer -cne 'Microsoft Corporation') {
        throw 'The selected Visual Studio tool lacks a valid Microsoft Corporation signature.'
    }
}

function Get-PublicationMsvcCatalogEnvironment {
    param([string] $CommonApplicationData, [string] $SystemVolume)
    if ([string]::IsNullOrWhiteSpace($CommonApplicationData) -or
        !$CommonApplicationData.StartsWith($SystemVolume, [StringComparison]::OrdinalIgnoreCase) -or
        $CommonApplicationData -ieq $SystemVolume) {
        throw 'The Visual Studio machine catalog root is outside the hosted system volume.'
    }
    Confirm-PublicationVendorPath $CommonApplicationData
    # Both Windows names designate the same machine-wide known folder.
    "ProgramData=$CommonApplicationData"
    "ALLUSERSPROFILE=$CommonApplicationData"
}

function Select-PublicationVisualStudio {
    param([string[]] $Lines, [string] $ProgramFiles, [string] $ProgramFilesX86)
    if ($Lines.Count -eq 0) { throw 'Visual Studio discovery returned no matching x64 Visual C++ instance.' }
    if ($Lines.Count -ne 1) { throw 'Expected exactly one installed x64 Visual C++ instance.' }
    $path = $Lines[0]
    if (!$path.StartsWith($ProgramFiles + '\Microsoft Visual Studio\', [StringComparison]::OrdinalIgnoreCase) -and
        !$path.StartsWith($ProgramFilesX86 + '\Microsoft Visual Studio\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Visual Studio discovery reported an installation outside the hosted program directories.'
    }
    Confirm-PublicationVendorPath $path
    $path
}

function Select-PublicationMsvc {
    param([string[]] $Lines, [string] $VisualStudio, [string] $ProgramFilesX86)
    if ($Lines.Count -ne 1 -or $Lines[0].Length -gt 4096) {
        throw 'Expected one bounded Visual C++ toolset record.'
    }
    $facts = ConvertFrom-Json -InputObject $Lines[0] -AsHashtable -Depth 3
    if ($facts -isnot [System.Collections.IDictionary] -or $facts.Count -ne 3 -or
        $facts.vc -isnot [string] -or $facts.sdk -isnot [string] -or $facts.sdk_version -isnot [string]) {
        throw 'Visual Studio did not return the expected compiler and Windows SDK fields.'
    }
    $vc = $facts.vc.TrimEnd([char]92)
    $sdk = $facts.sdk.TrimEnd([char]92)
    $version = $facts.sdk_version.TrimEnd([char]92)
    $prefix = $VisualStudio + '\VC\Tools\MSVC\'
    if (!$vc.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        $vc.Substring($prefix.Length) -cnotmatch '\A[0-9]+(?:\.[0-9]+){2,3}\z' -or
        !$sdk.StartsWith($ProgramFilesX86 + '\Windows Kits\', [StringComparison]::OrdinalIgnoreCase) -or
        $version -cnotmatch '\A[0-9]+(?:\.[0-9]+){3}\z') {
        throw 'Visual Studio reported an unexpected VC toolset or Windows SDK layout.'
    }

    $bin = $vc + '\bin\Hostx64\x64'
    $linker = $bin + '\link.exe'
    $sdkLib = $sdk + '\Lib\' + $version
    $libraries = @($vc + '\lib\x64'; $sdkLib + '\ucrt\x64'; $sdkLib + '\um\x64')
    Confirm-PublicationVendorPath $vc
    Confirm-PublicationVendorPath $sdk
    foreach ($library in $libraries) { Confirm-PublicationVendorPath $library }
    Confirm-PublicationVendorPath $linker -File
    @{ linker = $linker; bin = $bin; libraries = $libraries; vc = $vc; sdk = $sdk; sdk_version = $version }
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

function Assert-PreparedCargoConfiguration {
    param([string] $Repository, [string] $CargoHome, [string[]] $Environment)
    if ((Resolve-ExaCopyWindowsPath $Repository) -cne $Repository -or
        (Resolve-ExaCopyWindowsPath $CargoHome) -cne $CargoHome) {
        throw 'The prepared build requires canonical local Cargo configuration roots.'
    }
    $homeEntries = @($Environment | Where-Object { $_ -imatch '\ACARGO_HOME=' })
    if ($homeEntries.Count -ne 1 -or $homeEntries[0].Substring(11) -cne $CargoHome) {
        throw 'The prepared build environment does not bind the inspected Cargo home.'
    }
    $cargoKeys = @('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR', 'CARGO_TERM_COLOR',
        'CARGO_INCREMENTAL', 'CARGO_CACHE_RUSTC_INFO', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER')
    foreach ($entry in $Environment) {
        $key = $entry.Split('=', 2)[0]
        if (($key.StartsWith('CARGO_', [StringComparison]::OrdinalIgnoreCase) -and $key -notin $cargoKeys) -or
            $key -imatch '\A(?:RUSTC_.+|RUSTDOC.*|RUSTFLAGS)\z') {
            throw 'The prepared build environment contains an unauthorized executable or flag override.'
        }
    }

    $roots = [Collections.Generic.List[string]]::new()
    $roots.Add($CargoHome)
    $directory = [IO.DirectoryInfo]::new($Repository)
    while ($null -ne $directory) {
        $roots.Add([IO.Path]::Combine($directory.FullName, '.cargo'))
        $directory = $directory.Parent
    }
    foreach ($root in $roots) {
        if (!(Confirm-ExaCopyPath $root -AllowMissing)) { continue }
        foreach ($name in @('config', 'config.toml')) {
            if (Confirm-ExaCopyPath ([IO.Path]::Combine($root, $name)) -File -AllowMissing) {
                throw 'The prepared build found an unreviewed Cargo configuration file.'
            }
        }
    }
}

function Assert-UniquePublicationJsonNames {
    param([Text.Json.JsonElement] $Value)
    if ($Value.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Value.EnumerateObject()) {
            if (!$names.Add($property.Name)) { throw 'Cargo JSON contains a duplicate object member.' }
            Assert-UniquePublicationJsonNames $property.Value
        }
    } elseif ($Value.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($element in $Value.EnumerateArray()) { Assert-UniquePublicationJsonNames $element }
    }
}

function Read-PreparedCargoJsonObject {
    param([string] $Text)
    $options = [Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 32
    $document = [Text.Json.JsonDocument]::Parse($Text, $options)
    try {
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw 'The captured Cargo record is not a JSON object.'
        }
        Assert-UniquePublicationJsonNames $document.RootElement
    } finally {
        $document.Dispose()
    }
    ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 32 -ErrorAction Stop
}

function Assert-PublicationCompilerGraph {
    param([byte[]] $Bytes, [string] $Manifest, [string] $Source, [string] $Repository)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 8MB) { throw 'Cargo metadata exceeds the admitted extent.' }
    $strict = [Text.UTF8Encoding]::new($false, $true)
    $metadata = Read-PreparedCargoJsonObject ($strict.GetString($Bytes))
    $resolve = $metadata['resolve']
    if (($metadata['version'] -isnot [long] -and $metadata['version'] -isnot [int]) -or $metadata['version'] -ne 1 -or
        $metadata['workspace_root'] -isnot [string] -or
        (Convert-ReadDiffExecutableSeparators $metadata['workspace_root']) -cne $Repository -or
        $metadata['packages'] -isnot [array] -or $metadata['packages'].Count -gt 1024 -or
        $resolve -isnot [Collections.IDictionary] -or
        $resolve['nodes'] -isnot [array] -or $resolve['nodes'].Count -gt 1024) {
        throw 'Cargo metadata does not describe the bounded selected workspace.'
    }

    $local = @{
        'exacopy-platform' = 'crates\platform\exacopy-platform'
        'exacopy-core' = 'crates\foundation\exacopy-core'
        'exacopy-model' = 'crates\foundation\exacopy-model'
        'exacopy-endpoint' = 'crates\interfaces\exacopy-endpoint'
        'exacopy-diff' = 'crates\engines\exacopy-diff'
    }
    $versions = @{ 'uuid' = '1.29.3'; 'windows-sys' = '0.61.2'; 'windows-link' = '0.2.1' }
    $edges = @{
        'exacopy-platform' = @('normal:exacopy-endpoint', 'normal:exacopy-model', 'normal:windows-sys', 'dev:exacopy-diff', 'dev:exacopy-endpoint', 'dev:windows-sys')
        'exacopy-core' = @('normal:uuid')
        'exacopy-model' = @('normal:exacopy-core')
        'exacopy-endpoint' = @('normal:exacopy-core', 'normal:exacopy-model')
        'exacopy-diff' = @('normal:exacopy-endpoint')
        'uuid' = @()
        'windows-sys' = @('normal:windows-link')
        'windows-link' = @()
    }
    $packageById = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $nodeById = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($package in $metadata['packages']) {
        if ($package['id'] -isnot [string] -or !$package['id'] -or !$packageById.TryAdd($package['id'], $package)) {
            throw 'Cargo metadata contains an invalid or ambiguous package identity.'
        }
    }
    foreach ($node in $resolve['nodes']) {
        if ($node['id'] -isnot [string] -or !$node['id'] -or !$nodeById.TryAdd($node['id'], $node)) {
            throw 'Cargo metadata contains an invalid or ambiguous resolve node.'
        }
    }
    $rootPath = "$Repository\$($local['exacopy-platform'])"
    if ($Manifest -cne "$rootPath\Cargo.toml" -or $Source -cne "$rootPath\src\lib.rs") {
        throw 'The requested compiler graph is outside the admitted publication package.'
    }
    $roots = @($packageById.Values | Where-Object {
        $_['manifest_path'] -is [string] -and (Convert-ReadDiffExecutableSeparators $_['manifest_path']) -ceq $Manifest
    })
    if ($roots.Count -ne 1 -or ($null -ne $resolve['root'] -and $resolve['root'] -cne $roots[0]['id'])) {
        throw 'Cargo metadata did not bind exactly the selected publication package.'
    }

    $root = $roots[0]['id']
    $pending = [Collections.Generic.Queue[string]]::new()
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pending.Enqueue($root)
    [void]$visited.Add($root)
    while ($pending.Count -gt 0) {
        $id = $pending.Dequeue()
        if (!$packageById.ContainsKey($id) -or !$nodeById.ContainsKey($id)) {
            throw 'Cargo metadata has an unresolved selected compiler edge.'
        }
        $package = $packageById[$id]
        $node = $nodeById[$id]
        $name = $package['name']
        if ($name -isnot [string] -or !$name -or !$edges.ContainsKey($name) -or !$names.Add($name) -or
            $package['targets'] -isnot [array] -or $package['targets'].Count -gt 32 -or
            $node['deps'] -isnot [array] -or $node['deps'].Count -gt 128 -or
            $node['features'] -isnot [array]) {
            throw 'Cargo metadata left the closed publication compiler graph.'
        }

        if ($local.ContainsKey($name)) {
            $directory = "$Repository\$($local[$name])"
            if ($null -ne $package['source'] -or $package['version'] -cne '0.1.0' -or
                $package['manifest_path'] -isnot [string] -or
                (Convert-ReadDiffExecutableSeparators $package['manifest_path']) -cne "$directory\Cargo.toml") {
                throw 'A local compiler input has an unexpected manifest or package source.'
            }
        } elseif ($package['source'] -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            $package['version'] -cne $versions[$name]) {
            throw 'A registry compiler input has an unexpected source or version.'
        }

        $libraries = @($package['targets'] | Where-Object {
            $_['kind'] -is [array] -and $_['kind'].Count -eq 1 -and $_['kind'][0] -ceq 'lib' -and
            $_['crate_types'] -is [array] -and $_['crate_types'].Count -eq 1 -and $_['crate_types'][0] -ceq 'lib'
        })
        if ($libraries.Count -ne 1 -or @($package['targets'] | Where-Object {
            $_['kind'] -isnot [array] -or $_['crate_types'] -isnot [array] -or
            'custom-build' -cin $_['kind'] -or 'proc-macro' -cin $_['kind'] -or 'proc-macro' -cin $_['crate_types']
        }).Count -ne 0) {
            throw 'A selected package introduces a build script, proc macro, or unexpected library target.'
        }

        if ($id -ceq $root -and ($name -cne 'exacopy-platform' -or
            $libraries[0]['src_path'] -isnot [string] -or
            (Convert-ReadDiffExecutableSeparators $libraries[0]['src_path']) -cne $Source -or
            $node['features'].Count -ne 1 -or $node['features'][0] -cne 'experimental-windows-copy')) {
            throw 'The resolve root did not select the exact publication source and feature.'
        }

        $expectedEdges = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($expected in $edges[$name]) { [void]$expectedEdges.Add($expected) }
        foreach ($dependency in $node['deps']) {
            $child = $dependency['pkg']
            if ($child -isnot [string] -or !$child -or $dependency['dep_kinds'] -isnot [array] -or
                $dependency['dep_kinds'].Count -eq 0 -or $dependency['dep_kinds'].Count -gt 16) {
                throw 'Cargo metadata contains an ambiguous dependency shape.'
            }
            foreach ($entry in $dependency['dep_kinds']) {
                $kind = $entry['kind']
                if ($kind -ceq 'dev' -and $id -cne $root) { continue }
                if ($null -ne $kind -and $kind -cne 'dev') { throw 'The compiler graph includes an unsupported dependency kind.' }
                if (!$packageById.ContainsKey($child)) { throw 'A selected dependency package is missing.' }
                $role = if ($null -eq $kind) { 'normal' } else { 'dev' }
                if (!$expectedEdges.Remove("${role}:$($packageById[$child]['name'])")) {
                    throw 'Cargo metadata contains an unexpected selected compiler edge.'
                }
                if ($visited.Add($child)) { $pending.Enqueue($child) }
            }
        }
        if ($expectedEdges.Count -ne 0) { throw 'Cargo metadata omitted required compiler edges.' }
    }
    if ($visited.Count -ne $edges.Count) { throw 'Cargo metadata omitted a selected compiler input.' }
    $root
    foreach ($id in $visited) {
        if ($id -cne $root) { $id }
    }
}

function Select-PreparedPublicationExecutable {
    param([byte[]] $Bytes, [string] $Manifest, [string] $Source, [string] $Build, [string[]] $PackageIds)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 8MB -or $Bytes[-1] -ne 10) {
        throw 'The prepared Cargo stream lacks a complete bounded JSON Lines extent.'
    }
    $strict = [Text.UTF8Encoding]::new($false, $true)
    $records = $strict.GetString($Bytes).Split([char]10)
    if ($records.Length -gt 1025) { throw 'The prepared Cargo stream has too many records.' }
    $pending = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $PackageIds) {
        if (!$id -or !$pending.Add($id)) { throw 'The prepared Cargo graph has duplicate or empty identities.' }
    }
    $seen = [Collections.Generic.HashSet[string]]::new($pending, [StringComparer]::Ordinal)
    if ($pending.Count -ne 8) { throw 'The prepared Cargo stream needs the closed compiler graph.' }

    $selected = $null
    for ($i = 0; $i -lt $records.Length - 1; ++$i) {
        $line = $records[$i]
        if ($line.Length -eq 0 -or $strict.GetByteCount($line) -gt 256KB) { throw 'A Cargo record exceeds its admitted bounds.' }
        $event = Read-PreparedCargoJsonObject $line
        $reason = $event['reason']
        if ($i -eq $records.Length - 2) {
            if ($reason -cne 'build-finished' -or $event.Count -ne 2 -or
                $event['success'] -isnot [bool] -or !$event['success']) {
                throw 'The last Cargo record is not an exact successful build-finished event.'
            }
            break
        }

        $package = $event['package_id']
        if ($package -isnot [string] -or !$seen.Contains($package)) {
            throw 'A captured Cargo record is outside the admitted compiler graph.'
        }
        if ($reason -ceq 'compiler-message') {
            if ($event['message'] -isnot [Collections.IDictionary] -or
                $event['message']['level'] -cnotin @('warning', 'note', 'help')) {
                throw 'A captured Cargo compiler message was not admitted.'
            }
            continue
        }
        $profile = $event['profile']
        $target = $event['target']
        if ($reason -cne 'compiler-artifact' -or !$pending.Remove($package) -or
            $event['fresh'] -isnot [bool] -or $event['fresh'] -or
            $profile -isnot [Collections.IDictionary] -or $profile['test'] -isnot [bool] -or
            $profile['opt_level'] -isnot [string] -or $profile['opt_level'] -cne '0' -or ($profile['debuginfo'] -isnot [long] -and $profile['debuginfo'] -isnot [int]) -or $profile['debuginfo'] -ne 2 -or
            $profile['debug_assertions'] -isnot [bool] -or !$profile['debug_assertions'] -or
            $profile['overflow_checks'] -isnot [bool] -or !$profile['overflow_checks'] -or
            $target -isnot [Collections.IDictionary] -or
            $target['kind'] -isnot [array] -or $target['kind'].Count -ne 1 -or $target['kind'][0] -cne 'lib' -or
            $target['crate_types'] -isnot [array] -or $target['crate_types'].Count -ne 1 -or $target['crate_types'][0] -cne 'lib') {
            throw 'A captured Cargo artifact was duplicate, stale, or outside the admitted profile.'
        }

        if ($package -cne $PackageIds[0] -and $null -eq $event['executable'] -and !$profile['test']) { continue }
        if ($package -cne $PackageIds[0] -or $null -ne $selected -or
            !$profile['test'] -or $target['name'] -cne 'exacopy_platform' -or
            $event['features'] -isnot [array] -or $event['features'].Count -ne 1 -or
            $event['features'][0] -cne 'experimental-windows-copy' -or
            $event['manifest_path'] -isnot [string] -or
            (Convert-ReadDiffExecutableSeparators $event['manifest_path']) -cne $Manifest -or
            $target['src_path'] -isnot [string] -or
            (Convert-ReadDiffExecutableSeparators $target['src_path']) -cne $Source -or
            $event['executable'] -isnot [string] -or !$event['executable'].EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase) -or
            $event['filenames'] -isnot [array] -or $event['filenames'].Count -gt 32) {
            throw 'Cargo did not emit exactly the selected publication test executable.'
        }
        $selected = Resolve-ReadDiffExecutablePath $event['executable'] "$Build\x86_64-pc-windows-msvc"
        $matches = @($event['filenames'] | Where-Object {
            $_ -is [string] -and (Convert-ReadDiffExecutableSeparators $_) -ceq $selected
        })
        if ($matches.Count -ne 1) { throw 'The selected executable does not bind to one Cargo output name.' }
    }
    if (!$selected -or $pending.Count -ne 0) { throw 'The prepared build did not emit its full closed artifact inventory.' }
    $selected
}

function Assert-PreparedPublicationPe {
    param([IO.Stream] $Image)
    if (!$Image.CanRead -or !$Image.CanSeek -or $Image.Length -lt 64 -or $Image.Length -gt 128MB) {
        throw 'The selected image does not have a bounded readable PE extent.'
    }
    $position = $Image.Position
    $reader = [IO.BinaryReader]::new($Image, [Text.Encoding]::UTF8, $true)
    try {
        $Image.Position = 0
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'The selected image does not have an MZ header.' }
        $Image.Position = 0x3C
        $pe = [long]$reader.ReadUInt32()
        if ($pe -lt 64 -or $pe -gt $Image.Length - 24) { throw 'The PE header is outside the held image.' }
        $Image.Position = $pe
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'The selected image does not contain an AMD64 PE header.'
        }
        $sections = $reader.ReadUInt16()
        $Image.Position = $pe + 20
        $optionalSize = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        $optional = $Image.Position
        $sectionTable = $optional + $optionalSize
        if ($sections -lt 1 -or $sections -gt 96 -or $optionalSize -lt 112 -or
            $sectionTable + 40 * $sections -gt $Image.Length -or
            ($characteristics -band 0x0002) -eq 0 -or ($characteristics -band 0x3100) -ne 0 -or
            $reader.ReadUInt16() -ne 0x020B) {
            throw 'The selected image is not a bounded PE32+ AMD64 non-DLL executable.'
        }
        $Image.Position = $optional + 16
        $entry = [long]$reader.ReadUInt32()
        $Image.Position = $optional + 56
        $imageSize = [long]$reader.ReadUInt32()
        $headerSize = [long]$reader.ReadUInt32()
        if ($entry -eq 0 -or $entry -ge $imageSize -or
            $headerSize -lt $sectionTable + 40 * $sections -or $headerSize -gt $Image.Length) {
            throw 'The selected PE image has an invalid entry point or header extent.'
        }
        $executableEntry = $false
        for ($i = 0; $i -lt $sections; ++$i) {
            $Image.Position = $sectionTable + 40 * $i + 8
            $virtualSize = [long]$reader.ReadUInt32()
            $virtualAddress = [long]$reader.ReadUInt32()
            $rawSize = [long]$reader.ReadUInt32()
            $rawOffset = [long]$reader.ReadUInt32()
            $Image.Position = $sectionTable + 40 * $i + 36
            $flags = $reader.ReadUInt32()
            if ($rawSize -gt 0 -and ($rawOffset -lt $headerSize -or $rawOffset + $rawSize -gt $Image.Length)) {
                throw 'A PE section extends outside the held image.'
            }
            $entryOffset = $entry - $virtualAddress
            if (($flags -band 0x20000000) -ne 0 -and $entryOffset -ge 0 -and
                $entryOffset -lt $virtualSize -and $entryOffset -lt $rawSize) { $executableEntry = $true }
        }
        if (!$executableEntry) { throw 'The PE entry point is outside file-backed executable code.' }
    } finally {
        $reader.Dispose()
        $Image.Position = $position
    }
}
