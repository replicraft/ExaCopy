$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-ntfs-read-diff.ps1')

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
Write-Output 'Read/Diff exact attendance controls passed.'
