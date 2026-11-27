[CmdletBinding()]
param(
    [string] $Helper = (Join-Path $PSScriptRoot 'process.cs'),
    [string] $NativeOutputDirectory,
    [switch] $ObserveHostedJobProcesses,
    [switch] $OwnerDeathController
)

$ErrorActionPreference = 'Stop'
if (-not ('ExaCopyQualification.PublicationProcess' -as [type])) {
    Add-Type -Path $Helper
}

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) {
        throw 'Process supervision control did not return the expected exact value.'
    }
}

function Assert-Refusal([scriptblock] $Action) {
    try {
        & $Action | Out-Null
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause -is [ArgumentException]) { return }
        throw
    }
    throw 'An invalid process input was accepted.'
}

Assert-Equal ([ExaCopyQualification.PublicationProcess]::ValidateAbi()) $true
foreach ($case in @(
    @{ Input = ''; Quoted = '""' }
    @{ Input = 'with spaces'; Quoted = '"with spaces"' }
    @{ Input = 'a"b'; Quoted = '"a\"b"' }
    @{ Input = 'a\"b'; Quoted = '"a\\\"b"' }
    @{ Input = 'C:\a b\'; Quoted = '"C:\a b\\"' }
    @{ Input = "a`tb"; Quoted = "`"a`tb`"" }
)) {
    Assert-Equal ([ExaCopyQualification.PublicationProcess]::QuoteArgument($case.Input)) $case.Quoted
}
$zero = [char]0
$environment = [string[]] @('z=last', 'A=first=still-a-value', 'systemroot=C:\Windows')
Assert-Equal ([ExaCopyQualification.PublicationProcess]::EnvironmentBlock($environment)) (
    "A=first=still-a-value${zero}systemroot=C:\Windows${zero}z=last${zero}${zero}"
)
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::QuoteArgument("a${zero}b") }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::QuoteArgument(('x' * 32767)) }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::EnvironmentBlock([string[]] @()) }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::EnvironmentBlock([string[]] @('Path=a', 'PATH=b')) }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::EnvironmentBlock([string[]] @('=C:=C:\')) }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::EnvironmentBlock([string[]] @('missing_equals')) }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::EnvironmentBlock([string[]] @("A=x${zero}b")) }
Assert-Refusal { [ExaCopyQualification.PublicationProcess]::EnvironmentBlock([string[]] @(
    ('A=' + ('x' * 18000)), ('B=' + ('x' * 18000))
)) }

Add-Type -TypeDefinition @'
using System.IO;
public sealed class PublicationPartialWriteControl : MemoryStream
{
    public int Writes { get; private set; }
    public override void Write(byte[] buffer, int offset, int count)
    {
        Writes++;
        base.Write(buffer, offset, (count + 1) / 2);
        throw new IOException("synthetic partial write");
    }
}
'@
$type = [ExaCopyQualification.PublicationProcess].GetNestedType('Capture', 'NonPublic')
$captureBytes = $type.GetMethod('CaptureBytes', [Reflection.BindingFlags] 'NonPublic,Instance')
$normal = [IO.MemoryStream]::new()
$faulty = [PublicationPartialWriteControl]::new()
try {
    $good = [Activator]::CreateInstance($type, [object[]] @($null, $normal))
    $bad = [Activator]::CreateInstance($type, [object[]] @($null, $faulty))
    $receipt = [ExaCopyQualification.PublicationProcess+Receipt]::new()
    $cap = [ExaCopyQualification.PublicationProcess]::StreamLimitBytes
    $parameters = [object[]]::new(3)
    $parameters[0] = [byte[]]::new($cap + 1)
    $parameters[1] = $cap
    $parameters[2] = $receipt
    $captureBytes.Invoke($good, $parameters)
    $parameters[1] = 5
    $refused = $false
    try {
        $captureBytes.Invoke($bad, $parameters)
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause -isnot [IO.IOException] -or $cause.Message -cne 'synthetic partial write') { throw }
        $refused = $true
    }
    Assert-Equal $refused $true
    Assert-Equal ($type.GetProperty('Written').GetValue($good)) $cap
    Assert-Equal ($type.GetProperty('Written').GetValue($bad)) 3
    $captureBytes.Invoke($bad, $parameters)
    $captureBytes.Invoke($good, $parameters)
    Assert-Equal $faulty.Writes 1
    Assert-Equal $faulty.Length 3
    Assert-Equal $normal.Length $cap
    Assert-Equal $receipt.OutputLimitExceeded $true
} finally {
    $faulty.Dispose()
    $normal.Dispose()
}

if (!$NativeOutputDirectory) {
    'Process ABI, quoting, Unicode environment, input bounds, and failed-sink controls passed.'
    return
}

# The owning runner supplies a newly acquired, trusted directory for these effects.
if (!$IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'Process containment controls require the native Windows x64 runner.'
}
$directory = (Get-Item -LiteralPath $NativeOutputDirectory).FullName
$Helper = (Get-Item -LiteralPath $Helper).FullName
$application = Join-Path $PSHOME 'pwsh.exe'
$allowed = [string[]] @(
    "SystemRoot=$env:SystemRoot"
    "WINDIR=$env:WINDIR"
    "TEMP=$directory"
    "TMP=$directory"
    "PATH=$PSHOME"
    'POWERSHELL_TELEMETRY_OPTOUT=1'
)

function Quote-Literal([string] $Value) {
    "'" + $Value.Replace("'", "''") + "'"
}

function Encode-Script([string] $ScriptText) {
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ScriptText))
}

function New-FixturePidObservation([string] $Name, [string] $ChildPid) {
    if (!$ObserveHostedJobProcesses) { return }
    $path = Quote-Literal (Join-Path $directory "$Name.pid-observation")
    @"
try {
    `$image = [IO.Path]::GetFileName([Environment]::ProcessPath)
    if (`$image.Length -gt 255 -or `$image.Contains(' ')) {
        throw 'Unrepresentable synthetic image basename.'
    }
    `$file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        `$bytes = [Text.Encoding]::UTF8.GetBytes("`$PID `$image $ChildPid")
        `$file.Write(`$bytes, 0, `$bytes.Length)
    } finally {
        `$file.Dispose()
    }
} catch {
    # The receipt reports unavailable observation independently of the fixture.
}
"@
}

function Read-FixturePidObservation([string] $Name) {
    try {
        $path = Join-Path $directory "$Name.pid-observation"
        $info = Get-Item -LiteralPath $path
        if ($info.Length -gt 1024) { throw 'Oversized synthetic observation.' }
        $text = [IO.File]::ReadAllText($path)
        $atoms = $text.Split(' ')
        if ($atoms.Length -ne 3 -or $atoms[0] -cnotmatch '\A[1-9][0-9]{0,9}\z' -or
            $atoms[1] -ine [IO.Path]::GetFileName($application) -or
            $atoms[2] -cnotmatch '\A(0|[1-9][0-9]{0,9})\z') {
            throw 'Malformed synthetic observation.'
        }
        return @{ pid = [uint32]$atoms[0]; image = $atoms[1]; child_pid = [uint32]$atoms[2] }
    } catch {
        return @{ error = "$($_.Exception.GetType().Name)" }
    }
}

function New-GrandchildLaunch([string] $ChildScript, [string] $Observation) {
    $encoded = Encode-Script $ChildScript
    $selected = Quote-Literal $application
    $observe = if ($Observation) { New-FixturePidObservation $Observation '$($child.Id)' }
    @"
`$start = [Diagnostics.ProcessStartInfo]::new($selected)
`$start.UseShellExecute = `$false
`$start.CreateNoWindow = `$true
`$start.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded'
`$child = [Diagnostics.Process]::Start(`$start)
$observe
`$child.Dispose()
"@
}

function Invoke-ContainmentControl([string] $Name, [string] $ScriptText, [int] $Timeout,
    [switch] $ObserveJob, [switch] $RefuseObserver) {
    $arguments = [string[]] @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', (Encode-Script $ScriptText))
    $stdout = Join-Path $directory "$Name.stdout.log"
    $stderr = Join-Path $directory "$Name.stderr.log"
    if ($RefuseObserver) {
        $method = [ExaCopyQualification.PublicationProcess].GetMethod('Run',
            [Reflection.BindingFlags]'NonPublic,Static')
        # MethodInfo.Invoke does not use the PowerShell method binder. Pass the
        # underlying values in fixed slots so neither string array is expanded.
        $parameters = [object[]]@(
            $application.PSObject.BaseObject, $arguments.PSObject.BaseObject,
            $directory.PSObject.BaseObject, $allowed.PSObject.BaseObject,
            $stdout.PSObject.BaseObject, $stderr.PSObject.BaseObject, $Timeout, $true, $true)
        if ($parameters[0] -isnot [string] -or $parameters[1] -isnot [string[]] -or
            $parameters[2] -isnot [string] -or $parameters[3] -isnot [string[]] -or
            $parameters[4] -isnot [string] -or $parameters[5] -isnot [string]) {
            throw 'Observer refusal controls require the selected application, paths, and typed launch vectors.'
        }
        $result = $method.Invoke($null, $parameters)
    } else {
        $result = [ExaCopyQualification.PublicationProcess]::Run(
            $application, $arguments, $directory, $allowed, $stdout, $stderr, $Timeout, [bool]$ObserveJob)
    }
    if ($ObserveJob) {
        $root = Read-FixturePidObservation "$Name-launch"
        $leaf = Read-FixturePidObservation "$Name-child"
        $finish = if ($Name -ceq 'nested-completed') { Read-FixturePidObservation "$Name-finish" }
        $sameChild = $root.pid -eq $result.ProcessId -and $root.child_pid -gt 0 -and
            $root.child_pid -ne $root.pid -and $root.child_pid -eq $leaf.pid
        $result | Add-Member -NotePropertyName FixtureObservation -NotePropertyValue @{
            root = $root; child = $leaf; finish = $finish; same_child = $sameChild
            finish_matches_child = $sameChild -and $null -ne $finish -and $leaf.pid -eq $finish.pid
        }
    }
    $receipt = Join-Path $directory "$Name.json"
    $output = [IO.File]::Open($receipt, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress -Depth 5))
        $output.Write($bytes)
    } finally {
        $output.Dispose()
    }
    if (!$result.JobListConfigured -or !$result.CreationAttempted -or !$result.Started -or !$result.Assigned -or !$result.Resumed -or !$result.RootSignaled -or
        !$result.Drained -or $result.ActiveProcesses -ne 0 -or $null -ne $result.Error -or
        $null -ne $result.CleanupError) {
        throw 'The owned native process-control job did not drain with complete evidence.'
    }
    return $result
}

function Write-SyntheticPidScript([string] $Name) {
    $path = Quote-Literal (Join-Path $directory $Name)
    @"
`$file = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
try {
    `$writer = [IO.StreamWriter]::new(`$file)
    `$writer.Write(`$PID.ToString([Globalization.CultureInfo]::InvariantCulture))
    `$writer.Flush()
} finally {
    `$file.Dispose()
}
"@
}

if ($OwnerDeathController) {
    # This controller is the sole holder of the unnamed inner Job handle.
    $grandchildScript = (Write-SyntheticPidScript 'owner-death-leaf.pid') + "`nStart-Sleep -Seconds 45"
    $testScript = (Write-SyntheticPidScript 'owner-death-root.pid') + "`n" +
        (New-GrandchildLaunch $grandchildScript) + "`nStart-Sleep -Seconds 45"
    [void](Invoke-ContainmentControl 'owner-death-controller-result' $testScript 55000)
    throw 'The owner-death controller was expected to be externally terminated.'
}

function Open-SyntheticProcess([string] $Marker, [Diagnostics.Process] $Parent) {
    $path = Join-Path $directory $Marker
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.ElapsedMilliseconds -lt 12000) {
        try {
            $pidText = [IO.File]::ReadAllText($path)
        } catch [IO.IOException] {
            Start-Sleep -Milliseconds 25
            continue
        }
        if ($pidText -ceq '') {
            Start-Sleep -Milliseconds 25
            continue
        }
        if ($pidText -cnotmatch '\A[1-9][0-9]{0,9}\z') { throw 'Invalid synthetic process marker.' }
        $selected = [Diagnostics.Process]::GetProcessById([int] $pidText)
        try {
            # Force .NET to retain a process handle before any controller termination.
            $held = $selected.SafeHandle
            if ($held.IsInvalid -or $selected.HasExited -or $selected.StartTime -lt $Parent.StartTime -or
                $selected.MainModule.FileName -ine $application -or $selected.Id -eq $Parent.Id) {
                throw 'The marked synthetic process does not match the live controlled launch.'
            }
            return $selected
        } catch {
            $selected.Dispose()
            throw
        }
    }
    throw 'The live synthetic process marker did not arrive before the owner-death deadline.'
}

# The outer profile job drains the controller and every inherited descendant.
# Inside it, kill only the exact controller and wait on independent process
# handles. Keeping an inner Job handle here would prevent the last-close test.
$controllerStart = [Diagnostics.ProcessStartInfo]::new($application)
$controllerStart.UseShellExecute = $false
$controllerStart.WorkingDirectory = $directory
$controllerStart.Environment.Clear()
foreach ($entry in $allowed) {
    $equals = $entry.IndexOf('=')
    $controllerStart.Environment[$entry.Substring(0, $equals)] = $entry.Substring($equals + 1)
}
foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
    '-Helper', $Helper, '-NativeOutputDirectory', $directory, '-OwnerDeathController')) {
    $controllerStart.ArgumentList.Add($argument)
}
$controller = [Diagnostics.Process]::Start($controllerStart)
$testProcess = $null
$leaf = $null
try {
    $controllerHandle = $controller.SafeHandle
    if ($controllerHandle.IsInvalid -or $controller.HasExited) { throw 'The exact controller is unavailable.' }
    $testProcess = Open-SyntheticProcess 'owner-death-root.pid' $controller
    $leaf = Open-SyntheticProcess 'owner-death-leaf.pid' $testProcess
    if ($controller.HasExited -or $testProcess.HasExited -or $leaf.HasExited) {
        throw 'The owner-death fixture processes were not all active before termination.'
    }
    $controller.Kill($false)
    if (!$controller.WaitForExit(10000) -or !$testProcess.WaitForExit(10000) -or !$leaf.WaitForExit(10000)) {
        throw 'The held synthetic controller or its nested processes did not signal.'
    }
    "Controller death observed on held processes: controller=$($controller.Id) root=$($testProcess.Id) leaf=$($leaf.Id)."
} finally {
    # On earlier refusal stop only this held controller. The outer supervisor
    # handles any unconfirmed descendants and retains their failure evidence.
    if (!$controller.HasExited) { $controller.Kill($false) }
    if ($leaf) { $leaf.Dispose() }
    if ($testProcess) { $testProcess.Dispose() }
    $controller.Dispose()
}

if ($ObserveHostedJobProcesses) {
    $refused = Invoke-ContainmentControl 'observer-refusal-completed' 'exit 0' 15000 -RefuseObserver
    Assert-Equal $refused.ExitCode 0
    Assert-Equal $refused.TimedOut $false
    Assert-Equal $refused.JobProcessObservationError 'Job observer setup: Synthetic job observer setup refusal.'
    $refused = Invoke-ContainmentControl 'observer-refusal-timeout' 'Start-Sleep -Seconds 20' 3000 -RefuseObserver
    Assert-Equal $refused.TimedOut $true
    Assert-Equal $refused.JobProcessObservationError 'Job observer setup: Synthetic job observer setup refusal.'
}

# The launcher must wait for the job even after the original process exits.
$done = Join-Path $directory 'grandchild-finished'
$doneLiteral = Quote-Literal $done
$childStart = New-FixturePidObservation 'nested-completed-child' '0'
$childFinish = New-FixturePidObservation 'nested-completed-finish' '0'
$child = @"
$childStart
Start-Sleep -Milliseconds 1000
`$file = [IO.File]::Open($doneLiteral, [IO.FileMode]::CreateNew)
`$file.Dispose()
$childFinish
"@
$oldSentinel = [Environment]::GetEnvironmentVariable('EXACOPY_FIXTURE_UNSELECTED_ENVIRONMENT')
[Environment]::SetEnvironmentVariable('EXACOPY_FIXTURE_UNSELECTED_ENVIRONMENT', 'synthetic-not-selected')
try {
    $launch = New-GrandchildLaunch $child 'nested-completed-launch'
    $script = @"
if (`$null -ne `$env:EXACOPY_FIXTURE_UNSELECTED_ENVIRONMENT) { exit 89 }
$launch
"@
    $completed = Invoke-ContainmentControl 'nested-completed' $script 15000 -ObserveJob:$ObserveHostedJobProcesses
} finally {
    [Environment]::SetEnvironmentVariable('EXACOPY_FIXTURE_UNSELECTED_ENVIRONMENT', $oldSentinel)
}

# The delayed descendant belongs to the job. It must be stopped before cleanup.
$late = Join-Path $directory 'grandchild-unexpected-write'
$lateLiteral = Quote-Literal $late
$childStart = New-FixturePidObservation 'nested-timeout-child' '0'
$child = @"
$childStart
Start-Sleep -Seconds 20
`$file = [IO.File]::Open($lateLiteral, [IO.FileMode]::CreateNew)
`$file.Dispose()
"@
$launch = New-GrandchildLaunch $child 'nested-timeout-launch'
$timed = Invoke-ContainmentControl 'nested-timeout' $launch 6000 -ObserveJob:$ObserveHostedJobProcesses

# Preserve both receipts before reporting a nested accounting mismatch.
Assert-Equal $completed.ExitCode 0
Assert-Equal $completed.TimedOut $false
if ($completed.RootSignaledWithActiveMilliseconds -lt 100) {
    throw 'The job did not show a sustained active descendant after the held root signaled.'
}
Assert-Equal ([IO.File]::Exists($done)) $true
Assert-Equal $timed.TimedOut $true
Assert-Equal ([IO.File]::Exists($late)) $false
if ($completed.TotalProcesses -ne 2 -or $timed.TotalProcesses -ne 2) {
    throw "Expected exactly two processes in each nested job. Completion observed $($completed.TotalProcesses), timeout observed $($timed.TotalProcesses)."
}

$limit = [ExaCopyQualification.PublicationProcess]::StreamLimitBytes
$flood = @"
`$out = [Console]::OpenStandardOutput()
`$out.Write([byte[]]::new($($limit + 1)))
Start-Sleep -Seconds 20
"@
$capped = Invoke-ContainmentControl 'output-cap' $flood 15000
Assert-Equal $capped.OutputLimitExceeded $true
Assert-Equal $capped.StdoutBytes $limit
Assert-Equal ((Get-Item -LiteralPath (Join-Path $directory 'output-cap.stdout.log')).Length) $limit
'Native creation-time job membership, suspended launch, descendant drain, timeout, environment, and output cap passed.'
