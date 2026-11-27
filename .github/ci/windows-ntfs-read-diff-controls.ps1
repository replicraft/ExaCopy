$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-ntfs-read-diff.ps1')

# Use the Cargo layout observed in the hosted failure. These are lexical
# controls and require no files, even when run with Windows path semantics.
$build = 'C:\synthetic\cargo-target'
$mixed = 'C:\synthetic\cargo-target\x86_64-pc-windows-msvc\debug\build\exacopy-platform/b70e99174945499b\out\windows_read-b70e99174945499b.exe'
$expected = 'C:\synthetic\cargo-target\x86_64-pc-windows-msvc\debug\build\exacopy-platform\b70e99174945499b\out\windows_read-b70e99174945499b.exe'
if ((Convert-ReadDiffExecutableSeparators $mixed) -cne $expected -or
    (Convert-ReadDiffExecutableSeparators 'C:/synthetic/./x/../native.exe:stream') -cne
        'C:\synthetic\.\x\..\native.exe:stream') {
    throw 'A reported executable spelling changed beyond separator translation.'
}

if ([OperatingSystem]::IsWindows()) {
    . (Join-Path $PSScriptRoot '../../tools/install/windows/paths.ps1')
    if ((Resolve-ReadDiffExecutablePath $mixed $build) -cne $expected -or
        (Resolve-ReadDiffExecutablePath $expected $build) -cne $expected) {
        throw 'The private build executable was refused or rewritten.'
    }
    $unqualified = @(
        'cargo-target/windows_read.exe'
        'C:synthetic/cargo-target/windows_read.exe'
        'C:/synthetic/cargo-target/./windows_read.exe'
        'C:/synthetic/cargo-target/sub/../windows_read.exe'
        'C:/synthetic/cargo-target/../windows_read.exe'
        'C:/synthetic/cargo-target-other/windows_read.exe'
        '//server/share/cargo-target/windows_read.exe'
        '//?/C:/synthetic/cargo-target/windows_read.exe'
        'C:/synthetic/cargo-target/windows_read.exe:stream'
    )
    foreach ($path in $unqualified) {
        $rejected = $false
        try { [void](Resolve-ReadDiffExecutablePath $path $build) }
        catch {
            if ($_.Exception.Message -cne 'A selected executable escaped the private build directory.') { throw }
            $rejected = $true
        }
        if (!$rejected) { throw "An unqualified Cargo executable spelling was accepted: $path" }
    }
}

$selector = 'native::valid_control'
$newline = [Environment]::NewLine
$pass = "test $selector ... ok${newline}test result: ok. 1 passed; 0 failed; 0 ignored;"
Assert-ReadDiffExactResult $selector 0 $pass
$refusals = @(
    @{ Exit = 0; Report = 'test result: ok. 0 passed; 0 failed; 0 ignored;' }
    @{ Exit = 1; Report = $pass }
    @{ Exit = 0; Report = $pass.Replace('native::valid_control', 'native::wrong_test') }
    @{ Exit = 0; Report = $pass.Replace('0 ignored;', '1 ignored;') }
    @{ Exit = 0; Report = "test native::extra_control ... FAILED${newline}$pass" }
    @{ Exit = 0; Report = "test $selector ... ok${newline}$pass" }
)
foreach ($case in $refusals) {
    $rejected = $false
    try {
        Assert-ReadDiffExactResult $selector $case.Exit $case.Report
    } catch {
        $rejected = $_.Exception.Message -ceq "Exact native selector did not pass: $selector"
    }
    if (!$rejected) { throw 'A malformed or unsuccessful native result was accepted.' }
}

foreach ($mode in @('Read', 'Diff')) {
    $profile = Get-ReadDiffProfile $mode
    $selectors = @($profile.Ordinary) + @($profile.Native)
    if (@($selectors | Sort-Object -Unique).Count -ne $selectors.Count) {
        throw "Duplicate test selectors in $mode."
    }
}

# The shared lane borrows its caller's DirectoryInfo through PowerShell's
# dynamic scope. The exact builder must not shadow that object with a string.
& {
    $evidence = [IO.DirectoryInfo]::new((Join-Path ([IO.Path]::GetTempPath()) 'exacopy-read-diff-scope-control'))
    $expectedDirectory = $evidence.FullName
    $observedDirectories = [Collections.Generic.List[string]]::new()
    function Invoke-Lane {
        param([string] $Name, [string] $Program, [string[]] $Arguments, [switch] $QuietStdout)
        if ($evidence -isnot [IO.DirectoryInfo]) {
            throw 'The nested lane lost the original evidence directory object.'
        }
        $observedDirectories.Add($evidence.FullName)
        return 1
    }
    $buildRefused = $false
    try { Invoke-ExactReadDiff 'Read' 'unused-build' $expectedDirectory 'unused-repository' }
    catch {
        if ($_.Exception.Message -cne 'The pinned Read/Diff build failed.') { throw }
        $buildRefused = $true
    }
    if (!$buildRefused -or $observedDirectories.Count -ne 1 -or
        $observedDirectories[0] -cne $expectedDirectory) {
        throw 'The exact builder did not retain its caller evidence directory.'
    }
}
Write-Output 'Read/Diff exact attendance controls passed.'
