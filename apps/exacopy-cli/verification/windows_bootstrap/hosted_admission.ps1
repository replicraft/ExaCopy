# Admission helpers for the one bootstrap workflow. Loading this file performs no I/O.
function Assert-BootstrapHostedContext {
    param($Context)

    $repository = 'replicraft/ExaCopy'
    $workflow = '.github/workflows/windows-ntfs-bootstrap.yml'
    $revision = $Context.GITHUB_SHA
    if ($Context.GITHUB_ACTIONS -cne 'true' -or $Context.RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $Context.RUNNER_OS -cne 'Windows' -or $Context.RUNNER_ARCH -cne 'X64' -or
        $Context.GITHUB_SERVER_URL -cne 'https://github.com' -or $Context.GITHUB_API_URL -cne 'https://api.github.com' -or
        $Context.GITHUB_REPOSITORY -cne $repository -or $Context.GITHUB_REF -cne 'refs/heads/main' -or
        $Context.GITHUB_EVENT_NAME -cne 'push' -or $Context.GITHUB_JOB -cne 'qualify' -or
        $Context.GITHUB_WORKFLOW_REF -cne "$repository/${workflow}@refs/heads/main" -or
        $revision -cnotmatch '\A[0-9a-f]{40}\z' -or $Context.GITHUB_WORKFLOW_SHA -cne $revision -or
        $Context.GITHUB_RUN_ID -cnotmatch '\A[1-9][0-9]{0,15}\z' -or
        $Context.GITHUB_RUN_ATTEMPT -cnotmatch '\A[1-9][0-9]{0,7}\z' -or
        $Context.GITHUB_REPOSITORY_ID -cnotmatch '\A[1-9][0-9]{0,15}\z' -or
        $Context.RUNNER_NAME -cnotmatch '\A[\x20-\x7e]{1,128}\z') {
        throw 'The process is outside the canonical hosted bootstrap job.'
    }
}

function Assert-BootstrapRunIdentity {
    param($Context, $Event, $Attempt, $JobPage, [string] $Tree)

    $repository = 'replicraft/ExaCopy'
    $workflow = '.github/workflows/windows-ntfs-bootstrap.yml'
    $revision = $Context.GITHUB_SHA
    Assert-BootstrapHostedContext $Context
    if ($Tree -cnotmatch '\A[0-9a-f]{40}\z') { throw 'The selected Git tree identity is invalid.' }
    if ($Event.ref -cne 'refs/heads/main' -or $Event.after -cne $revision -or
        $Event.deleted -isnot [bool] -or $Event.deleted -or
        $Event.repository.full_name -cne $repository -or [string]$Event.repository.id -cne $Context.GITHUB_REPOSITORY_ID -or
        [string]$Attempt.id -cne $Context.GITHUB_RUN_ID -or [string]$Attempt.run_attempt -cne $Context.GITHUB_RUN_ATTEMPT -or
        [string]$Attempt.repository.id -cne $Context.GITHUB_REPOSITORY_ID -or
        [string]$Attempt.head_repository.id -cne $Context.GITHUB_REPOSITORY_ID -or
        $Attempt.repository.full_name -cne $repository -or $Attempt.event -cne 'push' -or
        $Attempt.path -cne $workflow -or $Attempt.head_sha -cne $revision -or
        $Attempt.head_branch -cne 'main' -or $Attempt.status -cne 'in_progress') {
        throw 'The push payload or authenticated run attempt differs from the selected source.'
    }
    if (($JobPage.total_count -isnot [long] -and $JobPage.total_count -isnot [int]) -or $JobPage.total_count -ne 1 -or @($JobPage.jobs).Count -ne 1) {
        throw 'The canonical bootstrap attempt must have exactly one job.'
    }
    $job = $JobPage.jobs[0]
    if ($job.name -cne 'Windows bootstrap history (fixed NTFS)' -or $job.status -cne 'in_progress' -or
        $job.head_sha -cne $revision -or $job.runner_name -cne $Context.RUNNER_NAME -or
        [string]$job.run_id -cne $Context.GITHUB_RUN_ID -or [string]$job.run_attempt -cne $Context.GITHUB_RUN_ATTEMPT -or
        [string]$job.id -cnotmatch '\A[1-9][0-9]{0,15}\z' -or
        @($job.labels).Count -ne 1 -or $job.labels[0] -cne 'windows-2025') {
        throw 'The authenticated job record differs from the running bootstrap job.'
    }
    return [ordered]@{
        profile = 'windows-hosted-server2025-fixed-ntfs-bootstrap-history-v1'
        workflow = $workflow
        source = $revision
        tree = $Tree
        run_id = $Context.GITHUB_RUN_ID
        run_attempt = $Context.GITHUB_RUN_ATTEMPT
        job_id = [string]$job.id
    }
}

function Select-BootstrapExecutable {
    param([byte[]] $Bytes, [string] $Repository, [string] $Build)

    $limit = [ExaCopyQualification.PublicationProcess]::StreamLimitBytes
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt $limit -or $Bytes[-1] -ne 10) { throw 'Invalid bounded Cargo capture.' }
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $lines = $encoding.GetString($Bytes).Split([char]10)
    if ($lines.Length -gt 4097) { throw 'Too many bounded Cargo messages.' }
    $manifest = Join-Path $Repository 'apps\exacopy-cli\Cargo.toml'
    $source = Join-Path $Repository 'apps\exacopy-cli\tests\windows_bootstrap.rs'
    $events = @(for ($index = 0; $index -lt $lines.Length - 1; $index++) {
        $line = $lines[$index].TrimEnd([char]13)
        if ($line.Length -eq 0 -or $encoding.GetByteCount($line) -gt 256KB) {
            throw 'A Cargo message exceeds its admitted record bounds.'
        }
        $entry = Read-PreparedCargoJsonObject $line
        if ($entry -isnot [Collections.IDictionary] -or $entry.reason -isnot [string]) {
            throw 'A Cargo message is not a keyed compiler event.'
        }
        $entry
    })
    $final = @($events | Where-Object { $_.reason -ceq 'build-finished' })
    if ($final.Count -ne 1 -or $final[0].success -isnot [bool] -or !$final[0].success -or
        $events[-1].reason -cne 'build-finished') {
        throw 'Cargo did not retain one terminal successful build message.'
    }
    $matches = @($events | Where-Object {
        $_.reason -ceq 'compiler-artifact' -and $_.Contains('target') -and $_.target.name -ceq 'windows_bootstrap'
    })
    if ($matches.Count -ne 1) { throw 'Cargo did not report exactly one bootstrap test target.' }
    $event = $matches[0]
    if ((Convert-ReadDiffExecutableSeparators $event.manifest_path) -cne $manifest -or
        (Convert-ReadDiffExecutableSeparators $event.target.src_path) -cne $source -or
        $event.target.kind.Count -ne 1 -or $event.target.kind[0] -cne 'test' -or
        $event.target.crate_types.Count -ne 1 -or $event.target.crate_types[0] -cne 'bin' -or
        $event.target['required-features'].Count -ne 1 -or
        $event.target['required-features'][0] -cne 'windows-bootstrap-fixture' -or
        $event.profile.test -isnot [bool] -or !$event.profile.test -or
        $event.fresh -isnot [bool] -or $event.fresh -or
        $event.features.Count -ne 1 -or $event.features[0] -cne 'windows-bootstrap-fixture' -or
        $event.executable -isnot [string] -or [string]::IsNullOrEmpty($event.executable)) {
        throw 'Cargo reported the wrong manifest, source, features or build profile.'
    }
    $path = Resolve-ReadDiffExecutablePath $event.executable $Build
    $prefix = [regex]::Escape((Join-Path $Build 'x86_64-pc-windows-msvc\debug'))
    $ordinary = '\\deps\\windows_bootstrap-[0-9a-f]{16}\.exe'
    $separated = '\\build\\exacopy-cli\\(?<hash>[0-9a-f]{16})\\out\\windows_bootstrap-\k<hash>\.exe'
    if ($path -cnotmatch ('\A' + $prefix + '(?:' + $ordinary + '|' + $separated + ')\z') -or
        @($event.filenames | Where-Object { (Convert-ReadDiffExecutableSeparators $_) -ceq $path }).Count -ne 1) {
        throw 'The exact Cargo bootstrap image escaped the selected target layout.'
    }
    return $path
}

function Read-BootstrapAdmissionJson {
    param([IO.Stream] $InputStream, [Threading.CancellationToken] $Cancel)

    $limit = 1MB
    $data = [byte[]]::new($limit + 1)
    $written = 0
    while ($written -lt $data.Length) {
        $read = $InputStream.ReadAsync($data, $written, $data.Length - $written, $Cancel).GetAwaiter().GetResult()
        if ($read -eq 0) { break }
        $written += $read
    }
    if ($written -eq 0 -or $written -gt $limit) { throw 'Invalid bounded bootstrap admission JSON.' }
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $object = ConvertFrom-Json -InputObject ($encoding.GetString($data, 0, $written)) -Depth 24 -AsHashtable
    if ($object -isnot [Collections.IDictionary]) { throw 'Bootstrap admission JSON is not an object.' }
    return $object
}

function Confirm-HostedBootstrapJob {
    param([string] $Repository)

    $context = [Environment]::GetEnvironmentVariables()
    $run = $context.GITHUB_RUN_ID
    $attempt = $context.GITHUB_RUN_ATTEMPT
    if (!$IsWindows -or ![Environment]::Is64BitProcess) { throw 'Requires 64-bit Windows PowerShell.' }
    Assert-BootstrapHostedContext $context
    # Remove this credential before any command that could start a descendant.
    $tokenName = 'EXACOPY_BOOTSTRAP_ACTIONS_READ_TOKEN'
    $token = [Environment]::GetEnvironmentVariable($tokenName)
    [Environment]::SetEnvironmentVariable($tokenName, $null)
    $context.Remove($tokenName)
    # Accept the bounded RFC 6750 bearer alphabet without inspecting token claims.
    if (!$token -or $token.Length -gt 4096 -or
        ![regex]::IsMatch($token, '\A[A-Za-z0-9._~+/-]+=*\z')) {
        throw 'The scoped hosted job metadata credential is unavailable.'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.Caption -cnotmatch 'Windows Server 2025' -or
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne 'X64') {
        throw 'Bootstrap expects Windows Server 2025 x64.'
    }
    Confirm-PublicationSource $Repository $context.GITHUB_SHA
    $origin = @(& git -C $Repository remote get-url origin)
    if ($LASTEXITCODE -ne 0 -or $origin.Count -ne 1 -or
        $origin[0] -cnotin @('https://github.com/replicraft/ExaCopy', 'https://github.com/replicraft/ExaCopy.git')) {
        throw 'The canonical source checkout remote did not match.'
    }
    $trees = @(& git -C $Repository rev-parse --verify 'HEAD^{tree}')
    if ($LASTEXITCODE -ne 0 -or $trees.Count -ne 1) { throw 'The bootstrap source tree is unavailable.' }
    $eventPath = Resolve-ExaCopyWindowsPath $context.GITHUB_EVENT_PATH
    [void](Confirm-ExaCopyPath $eventPath -File)
    $eventFile = [IO.File]::Open($eventPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $push = Read-BootstrapAdmissionJson $eventFile ([Threading.CancellationToken]::None)
    } finally {
        $eventFile.Dispose()
    }

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    try {
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('ExaCopy-bootstrap-admission/1')
        $client.DefaultRequestHeaders.Accept.ParseAdd('application/vnd.github+json')
        $client.DefaultRequestHeaders.Add('X-GitHub-Api-Version', '2022-11-28')
        $endpoint = "https://api.github.com/repos/replicraft/ExaCopy/actions/runs/$run/attempts/$attempt"
        $records = @(foreach ($uri in @($endpoint, "$endpoint/jobs?per_page=2")) {
            $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(20))
            try {
                $reply = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
                try {
                    if ($reply.StatusCode -ne [Net.HttpStatusCode]::OK -or $reply.Content.Headers.ContentLength -gt 1MB) {
                        throw 'Hosted bootstrap run metadata was refused or oversized.'
                    }
                    $body = $reply.Content.ReadAsStream()
                    try { Read-BootstrapAdmissionJson $body $deadline.Token } finally { $body.Dispose() }
                } finally {
                    $reply.Dispose()
                }
            } finally {
                $deadline.Dispose()
            }
        })
    } finally {
        $client.Dispose()
    }
    $identity = Assert-BootstrapRunIdentity $context $push $records[0] $records[1] $trees[0]
    $identity.lock_sha256 = (Get-FileHash -LiteralPath (Join-Path $Repository 'Cargo.lock') -Algorithm SHA256).Hash
    $identity.windows = $os.Caption
    $identity.windows_build = $os.BuildNumber
    return $identity
}

function Assert-BootstrapUpperAcl {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Actor)

    # An independent launcher precheck. The platform re-observes its own
    # held native descriptors with the existing stricter binary predicate.
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($Path))
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    $trusted = @($Actor.Value, 'S-1-5-18', 'S-1-5-32-544')
    if ($null -eq $raw.Owner -or $raw.Owner.Value -cnotin $trusted -or
        $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -gt 256 -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]'DiscretionaryAclPresent, SelfRelative') -ne
            [Security.AccessControl.ControlFlags]'DiscretionaryAclPresent, SelfRelative') {
        throw 'The hosted data-volume ancestor lacks an admissible owner or DACL.'
    }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceQualifier -cnotin @([Security.AccessControl.AceQualifier]::AccessAllowed,
                [Security.AccessControl.AceQualifier]::AccessDenied) -or ($ace.AceFlags -band 0xe0) -ne 0) {
            throw 'The hosted data-volume ancestor has an unsupported access entry.'
        }
        $access = ([long]$ace.AccessMask) -band 0xffffffffL
        if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            $ace.SecurityIdentifier.Value -cnotin $trusted -and
            ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -eq 0 -and
            ($access -band (0xffffffffL -bxor 0xa01200afL)) -ne 0) {
            throw 'The hosted data-volume ancestor permits competing non-actor access.'
        }
    }
}

function Open-BootstrapHostedDataParent {
    param([string] $Repository, [Security.Principal.SecurityIdentifier] $Actor)

    $checkout = Resolve-ExaCopyWindowsPath $Repository
    if ($checkout -cne $env:GITHUB_WORKSPACE -or
        $checkout -cnotmatch '\A[A-Z]:\\a\\ExaCopy\\ExaCopy\z' -or
        $env:SystemDrive -cnotmatch '\A[A-Z]:\z') {
        throw 'The canonical hosted data-volume checkout is unavailable.'
    }
    $drive = [IO.Path]::GetPathRoot($checkout)
    if ($drive -ieq ($env:SystemDrive + '\')) { throw 'The bootstrap data drive is the system drive.' }
    Assert-BootstrapUpperAcl $drive $Actor
    $parent = [IO.Directory]::GetParent($checkout).FullName
    $ancestors = New-StageAncestorCustody $parent $Actor -BeforeAdmission {
        param($Held)

        if ($Held[0].Path -cne $drive) { throw 'Bootstrap data-volume ancestry changed.' }
        foreach ($item in $Held) { Assert-BootstrapUpperAcl $item.Path $Actor }
        [void][ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($Held[0].Handle)
    }
    try {
        $volume = [ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($ancestors.Held[0].Handle)
        $system = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($env:SystemDrive + '\')
        try {
            $systemVolume = [ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($system)
            if ($volume -ieq $systemVolume) { throw 'The hosted data drive aliases the system volume.' }
        } finally {
            $system.Dispose()
        }
        return @{ Ancestors = $ancestors; VolumeGuidRoot = $volume; Parent = $parent }
    } catch {
        Close-StageAncestorCustody $ancestors.Held
        throw
    }
}
