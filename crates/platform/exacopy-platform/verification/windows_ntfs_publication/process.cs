using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace ExaCopyQualification
{
    public static class PublicationProcess
    {
        private const int ShutdownMilliseconds = 10000;
        public const int StreamLimitBytes = 8 * 1024 * 1024;
        private const uint Suspended = 0x4;
        private const uint UnicodeEnvironment = 0x400;
        private const uint ExtendedStartup = 0x80000;
        private const uint NoWindow = 0x08000000;
        private const uint StandardHandles = 0x100;
        private const uint KillOnClose = 0x2000;
        private const uint HandleInheritable = 1;
        private const int BrokenPipe = 109;
        private const int InsufficientBuffer = 122;
        private const uint WaitObject = 0;
        private const uint WaitTimeout = 258;
        private const int BasicAccounting = 1;
        private const int BasicProcessIdList = 3;
        private const int ProcessIdListHeaderBytes = 8;
        private const int ProcessIdBytes = 8;
        private const int ActiveSampleLimit = 32;
        private const int ActiveSampleIntervalMilliseconds = 1000;
        private const int ActiveSampleReserveMilliseconds = 25;
        private const int AssociateCompletionPort = 7;
        private const int ExtendedLimits = 9;
        private const uint JobActiveProcessZero = 4;
        private const uint JobNewProcess = 6;
        private const uint JobExitProcess = 7;
        private const uint JobAbnormalExitProcess = 8;
        private const uint QueryLimitedInformation = 0x1000;
        private const int JobEventLimit = 64;
        private const int JobEventBatch = 16;
        private const int ProcessHandleList = 0x00020002;
        private const int ProcessJobList = 0x0002000d;
        private const int Server2025Build = 26100;
        private const int FileIdInfo = 18;
        private const string PinnedCargoPathSuffix = @"\toolchains\1.100.0-x86_64-pc-windows-msvc\bin\cargo.exe";

        [StructLayout(LayoutKind.Sequential)]
        private struct Security
        {
            internal uint Size;
            internal IntPtr Descriptor;
            internal int Inherit;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Startup
        {
            internal uint Size;
            internal IntPtr Reserved, Desktop, Title;
            internal uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
            internal ushort ShowWindow, ReservedCount;
            internal IntPtr ReservedData, Input, Output, Error;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupExtended
        {
            internal Startup Startup;
            internal IntPtr Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            internal IntPtr Process, Thread;
            internal uint ProcessId, ThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobBasicLimits
        {
            internal long ProcessTime, JobTime;
            internal uint Flags;
            internal UIntPtr MinimumWorkingSet, MaximumWorkingSet;
            internal uint ActiveLimit;
            internal UIntPtr Affinity;
            internal uint Priority, Scheduling;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobExtendedLimits
        {
            internal JobBasicLimits Basic;
            internal ulong ReadOperations, WriteOperations, OtherOperations;
            internal ulong ReadBytes, WriteBytes, OtherBytes;
            internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobAccounting
        {
            internal long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
            internal uint Faults, Processes, Active, Terminated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobCompletionPort
        {
            internal IntPtr Key, Port;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessBasicInformation
        {
            internal int ExitStatus;
            internal IntPtr Peb, Affinity;
            internal int Priority;
            internal UIntPtr ProcessId, ParentProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SinkFileIdentity
        {
            internal ulong Volume, Low, High;
        }

        public sealed class JobProcessEvent
        {
            public string Kind { get; internal set; }
            public uint ProcessId { get; internal set; }
            public uint? ParentProcessId { get; internal set; }
            public string Image { get; internal set; }
            public bool SelectedImage { get; internal set; }
            public bool SystemConsoleHost { get; internal set; }
            public string LookupFailure { get; internal set; }
        }

        public sealed class ActiveJobProcessSample
        {
            public long ObservedMilliseconds { get; internal set; }
            public List<JobProcessEvent> Processes { get; internal set; }
        }

        public sealed class Receipt
        {
            internal string ObservedProgram { get; set; }
            internal bool SampleActiveAfterRoot { get; set; }
            public bool JobListConfigured { get; internal set; }
            public bool CreationAttempted { get; internal set; }
            public bool Started { get; internal set; }
            public bool Assigned { get; internal set; }
            public bool Resumed { get; internal set; }
            public bool RootSignaled { get; internal set; }
            public long RootSignaledWithActiveMilliseconds { get; internal set; }
            public bool Drained { get; internal set; }
            public bool TimedOut { get; internal set; }
            public bool OutputLimitExceeded { get; internal set; }
            public uint? ProcessId { get; internal set; }
            public uint? ActiveProcesses { get; internal set; }
            public uint? TotalProcesses { get; internal set; }
            public uint? TotalProcessesBeforeResume { get; internal set; }
            public uint? LimitTerminations { get; internal set; }
            public List<JobProcessEvent> JobProcessEvents { get; internal set; }
            public bool JobProcessEventsCapped { get; internal set; }
            public string JobProcessObservationError { get; internal set; }
            public string JobProcessBaselineError { get; internal set; }
            public string JobProcessDetachError { get; internal set; }
            public ActiveJobProcessSample LastPostRootActiveSample { get; internal set; }
            public long? LastPostRootSampleAttemptMilliseconds { get; internal set; }
            public string LastPostRootSampleError { get; internal set; }
            public uint? ExitCode { get; internal set; }
            public int StdoutBytes { get; internal set; }
            public int StderrBytes { get; internal set; }
            public bool StdoutExtentUnconfirmed { get; internal set; }
            public bool StderrExtentUnconfirmed { get; internal set; }
            public int? NativeError { get; internal set; }
            public string Error { get; internal set; }
            public int? CleanupNativeError { get; internal set; }
            public string CleanupError { get; internal set; }
        }

        public enum BuildPreparationDisposition
        {
            PreparationFailed,
            PreparationTimedOut,
            PreparationUncertain,
            QuiescedAfterRootExit
        }

        public sealed class BuildPreparationReceipt
        {
            internal BuildPreparationReceipt(int budgetMilliseconds)
            {
                BuildBudgetMilliseconds = budgetMilliseconds;
            }

            public string InvocationId { get; } = Guid.NewGuid().ToString("N");
            public int BuildBudgetMilliseconds { get; }
            public Receipt Process { get; internal set; }
            public BuildPreparationDisposition Disposition { get; internal set; }
            public uint? RootExitCodeBeforeRetirement { get; internal set; }
            public bool StopRequested { get; internal set; }
            public bool? StopSucceeded { get; internal set; }
            public int? StopNativeError { get; internal set; }
            public long? RootExitObservedMilliseconds { get; internal set; }
            public long? StopRequestedMilliseconds { get; internal set; }
            public long? StopReturnedMilliseconds { get; internal set; }
            public long? DrainObservedMilliseconds { get; internal set; }
            public long? SinkEvidenceObservedMilliseconds { get; internal set; }
            public bool StdoutEof { get; internal set; }
            public bool StderrEof { get; internal set; }
            public string StdoutSinkIdentity { get; internal set; }
            public string StderrSinkIdentity { get; internal set; }
            public string StdoutSinkSha256 { get; internal set; }
            public string StderrSinkSha256 { get; internal set; }
        }

        public static bool ValidateAbi()
        {
            return IntPtr.Size == 8 && Marshal.SizeOf<Security>() == 24 &&
                Marshal.SizeOf<Startup>() == 104 && Marshal.OffsetOf<Startup>(nameof(Startup.Input)).ToInt32() == 80 &&
                Marshal.SizeOf<StartupExtended>() == 112 && Marshal.SizeOf<ProcessInformation>() == 24 &&
                Marshal.SizeOf<JobBasicLimits>() == 64 && Marshal.SizeOf<JobExtendedLimits>() == 144 &&
                Marshal.SizeOf<JobAccounting>() == 48 &&
                Marshal.SizeOf<JobCompletionPort>() == 16 &&
                Marshal.SizeOf<ProcessBasicInformation>() == 48 &&
                Marshal.OffsetOf<ProcessBasicInformation>(nameof(ProcessBasicInformation.ParentProcessId)).ToInt32() == 40;
        }

        // Windows CRT argument encoding. Always quote, even when no escaping is needed.
        public static string QuoteArgument(string value)
        {
            RequireBoundedText(value, 32766, nameof(value));
            var result = new StringBuilder().Append('"');
            int slashes = 0;
            foreach (char codeUnit in value)
            {
                if (codeUnit == '\\')
                {
                    slashes++;
                    continue;
                }
                result.Append('\\', codeUnit == '"' ? slashes * 2 + 1 : slashes);
                slashes = 0;
                result.Append(codeUnit);
            }
            return result.Append('\\', slashes * 2).Append('"').ToString();
        }

        public static string EnvironmentBlock(string[] entries)
        {
            if (entries == null || entries.Length == 0 || entries.Length > 256)
                throw new ArgumentException("Supply a bounded, explicit process environment.", nameof(entries));
            var sorted = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string entry in entries)
            {
                RequireBoundedText(entry, 32765, nameof(entries));
                int equals = entry.IndexOf('=');
                if (equals <= 0 || !sorted.TryAdd(entry.Substring(0, equals), entry))
                    throw new ArgumentException("Environment names need one unique ordinary assignment.", nameof(entries));
            }
            var block = new StringBuilder();
            foreach (string entry in sorted.Values)
            {
                if (block.Length + entry.Length + 2 > 32767)
                    throw new ArgumentException("The explicit environment is too large.", nameof(entries));
                block.Append(entry).Append('\0');
            }
            return block.Append('\0').ToString();
        }

        public static Receipt Run(string program, string[] arguments, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds)
        {
            return Run(program, arguments, workDirectory, environment, stdout, stderr, timeoutMilliseconds, false);
        }

        public static Receipt Run(string program, string[] arguments, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds, bool observeJobProcesses)
        {
            return Run(program, arguments, workDirectory, environment, stdout, stderr, timeoutMilliseconds, observeJobProcesses, false);
        }

        // Called by the hosted diagnostic negative control through reflection.
        private static Receipt Run(string program, string[] arguments, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds, bool observeJobProcesses,
            bool refuseDiagnosticSetup)
        {
            return RunOwned(program, arguments, workDirectory, environment, stdout, stderr, timeoutMilliseconds,
                observeJobProcesses, refuseDiagnosticSetup, false);
        }

        public static Receipt RunWithActiveProcessObservation(string program, string[] arguments, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds)
        {
            return RunOwned(program, arguments, workDirectory, environment, stdout, stderr, timeoutMilliseconds,
                true, false, true);
        }

        public static BuildPreparationReceipt PreparePublicationBuild(string program, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds)
        {
            // The caller holds and authenticates the actual toolchain file.
            RequirePinnedCargoProgram(program, environment);
            var arguments = new[]
            {
                "test", "--locked", "--offline", "--jobs", "2", "--target", "x86_64-pc-windows-msvc",
                "-p", "exacopy-platform", "--lib", "--no-default-features",
                "--features", "experimental-windows-copy", "--no-run", "--message-format=json"
            };
            var preparation = new BuildPreparationReceipt(timeoutMilliseconds);
            try
            {
                RunOwned(program, arguments, workDirectory, environment, stdout, stderr, timeoutMilliseconds,
                    true, false, true, preparation);
            }
            catch (Exception failure) when (preparation.Process != null)
            {
                // Sink open/disposal failures outside the owned job scope also
                // prevent preparation, including after the job has drained.
                RecordFailure(preparation.Process, failure, false);
            }
            preparation.Disposition = ClassifyBuildPreparation(preparation);
            return preparation;
        }

        // Separate fixed Cargo invocation for the Windows bootstrap fixture.
        // Publication v2 retains its original scope.
        public static BuildPreparationReceipt PrepareBootstrapBuild(string program, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds)
        {
            RequirePinnedCargoProgram(program, environment);
            var arguments = new[]
            {
                "test", "--locked", "--offline", "--jobs", "2", "--target", "x86_64-pc-windows-msvc",
                "-p", "exacopy-cli", "--test", "windows_bootstrap", "--no-default-features",
                "--features", "windows-bootstrap-fixture", "--no-run", "--message-format=json"
            };
            var preparation = new BuildPreparationReceipt(timeoutMilliseconds);
            try
            {
                RunOwned(program, arguments, workDirectory, environment, stdout, stderr, timeoutMilliseconds,
                    true, false, true, preparation);
            }
            catch (Exception failure) when (preparation.Process != null)
            {
                RecordFailure(preparation.Process, failure, false);
            }
            preparation.Disposition = ClassifyBuildPreparation(preparation);
            return preparation;
        }

        // The fixed bootstrap provider supplies its admitted PowerShell image,
        // exact tracked runner and held fixture/image selections. No caller
        // supplies a token; derive it from the controller's own primary token.
        public static Receipt RunBootstrapActor(string program, string[] arguments, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds)
        {
            using var impersonation = WindowsIdentity.GetCurrent(true);
            if (impersonation != null)
                throw new IOException("The bootstrap controller must not impersonate.");
            using var current = WindowsIdentity.GetCurrent();
            string sid = current.User?.Value;
            if (String.IsNullOrEmpty(sid) || current.IsSystem ||
                !new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator))
                throw new IOException("An admitted hosted bootstrap controller token is required.");
            const uint tokenQueryDuplicateAssignPrimary = 0x0008 | 0x0002 | 0x0001;
            // DISABLE_MAX_PRIVILEGE and LUA_TOKEN are documented Win32 flags.
            const uint disableMaxPrivilegeAndLuaToken = 0x0001 | 0x0004;
            using var original = OpenBootstrapToken(GetCurrentProcess(), tokenQueryDuplicateAssignPrimary);
            Require(CreateRestrictedToken(original, disableMaxPrivilegeAndLuaToken,
                0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out var restricted),
                "CreateRestrictedToken(bootstrap)");
            using (restricted)
            {
                uint session = BootstrapTokenValue(original, 12); // TokenSessionId
                ConfirmBootstrapToken(restricted, sid, session);
                return RunOwned(program, arguments, workDirectory, environment, stdout, stderr,
                    timeoutMilliseconds, false, false, false, null, restricted, sid, session);
            }
        }

        private static SafeFileHandle OpenBootstrapToken(IntPtr process, uint access)
        {
            Require(OpenProcessToken(process, access, out var token), "OpenProcessToken(bootstrap)");
            if (token.IsInvalid)
            {
                token.Dispose();
                throw new IOException("The bootstrap process token is unavailable.");
            }
            return token;
        }

        private static uint BootstrapTokenValue(SafeFileHandle token, int informationClass)
        {
            Require(GetTokenInformation(token, informationClass, out uint value, 4, out uint written),
                "GetTokenInformation(bootstrap)");
            if (written != 4)
                throw new IOException("The bootstrap token response has unexpected extent.");
            return value;
        }

        private static void ConfirmBootstrapToken(SafeFileHandle token, string sid, uint session)
        {
            const int tokenType = 8, tokenSessionId = 12, tokenElevation = 20, tokenHasRestrictions = 21;
            using var identity = new WindowsIdentity(token.DangerousGetHandle());
            if (identity.User?.Value != sid || BootstrapTokenValue(token, tokenType) != 1 ||
                BootstrapTokenValue(token, tokenSessionId) != session ||
                BootstrapTokenValue(token, tokenElevation) != 0 ||
                BootstrapTokenValue(token, tokenHasRestrictions) == 0 ||
                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new IOException("The bootstrap actor is not a same-session restricted standard primary token.");

            // TOKEN_PRIVILEGES contains a DWORD count and inline 12-byte
            // LUID_AND_ATTRIBUTES records. The held adapter repeats this check.
            const int tokenPrivileges = 3, header = 4, entry = 12, maxEntries = 256;
            var privileges = new byte[header + maxEntries * entry];
            if (Marshal.SizeOf<BootstrapLuid>() != 8)
                throw new IOException("The bootstrap LUID ABI is unsupported.");
            Require(GetBootstrapTokenBytes(token, tokenPrivileges, privileges, (uint)privileges.Length, out uint written),
                "GetTokenInformation(TokenPrivileges)");
            if (written < header || written > privileges.Length)
                throw new IOException("The bootstrap token privilege response has unexpected extent.");
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(privileges);
            if (count > maxEntries || written != header + entry * count)
                throw new IOException("The bootstrap token privilege membership has unexpected extent.");
            foreach (string name in new[] { "SeBackupPrivilege", "SeRestorePrivilege",
                "SeTakeOwnershipPrivilege", "SeManageVolumePrivilege" })
            {
                Require(LookupPrivilegeValueW(null, name, out var value), "LookupPrivilegeValueW(bootstrap)");
                for (int index = 0; index < count; index++)
                {
                    int offset = header + index * entry;
                    if (BinaryPrimitives.ReadUInt32LittleEndian(privileges.AsSpan(offset)) == value.Low &&
                        BinaryPrimitives.ReadInt32LittleEndian(privileges.AsSpan(offset + 4)) == value.High &&
                        (BinaryPrimitives.ReadUInt32LittleEndian(privileges.AsSpan(offset + 8)) & 2) != 0)
                        throw new IOException("The bootstrap actor has an enabled storage privilege.");
                }
            }
        }

        private static void RequirePinnedCargoProgram(string program, string[] environment)
        {
            RequireBoundedText(program, 32766, nameof(program));
            if (!program.EndsWith(PinnedCargoPathSuffix, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Preparation requires Cargo in the pinned native toolchain.", nameof(program));
            string rustupHome = program.Substring(0, program.Length - PinnedCargoPathSuffix.Length);
            string rootAssignment = "RUSTUP_HOME=" + rustupHome;
            if (rustupHome.Length == 0 || environment == null || environment.Length is < 1 or > 256 ||
                Array.FindIndex(environment, entry => StringComparer.OrdinalIgnoreCase.Equals(entry, rootAssignment)) < 0)
                throw new ArgumentException("Preparation requires the selected toolchain root.", nameof(environment));
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BootstrapLuid
        {
            public uint Low;
            public int High;
        }

        private static Receipt RunOwned(string program, string[] arguments, string workDirectory,
            string[] environment, string stdout, string stderr, int timeoutMilliseconds, bool observeJobProcesses,
            bool refuseDiagnosticSetup, bool sampleActiveAfterRoot, BuildPreparationReceipt preparation = null,
            SafeFileHandle bootstrapToken = null, string bootstrapSid = null, uint bootstrapSession = 0)
        {
            // The owning runner separately establishes the Windows Server 2025 SKU.
            if (!OperatingSystem.IsWindows() || Environment.OSVersion.Version.Build != Server2025Build ||
                RuntimeInformation.ProcessArchitecture != Architecture.X64 || !ValidateAbi())
                throw new PlatformNotSupportedException("The job supervisor requires the Windows Server 2025 x64 profile.");
            RequireExactPath(program);
            RequireExactPath(workDirectory);
            RequireExactPath(stdout);
            RequireExactPath(stderr);
            if (StringComparer.OrdinalIgnoreCase.Equals(stdout, stderr) ||
                timeoutMilliseconds < 1 || timeoutMilliseconds > 1800000)
                throw new ArgumentException("Supply separate output paths and a bounded timeout.");
            if (arguments == null || arguments.Length > 128)
                throw new ArgumentException("Supply bounded process arguments.", nameof(arguments));
            var command = new StringBuilder(QuoteArgument(program));
            foreach (string argument in arguments)
            {
                string quoted = QuoteArgument(argument);
                if (command.Length + quoted.Length + 2 > 32767)
                    throw new ArgumentException("The command line is too large.", nameof(arguments));
                command.Append(' ').Append(quoted);
            }
            if (command.Length + 1 > 32767)
                throw new ArgumentException("The command line is too large.", nameof(arguments));
            string environmentBlock = EnvironmentBlock(environment);
            var receipt = new Receipt
            {
                ObservedProgram = observeJobProcesses ? program : null,
                SampleActiveAfterRoot = sampleActiveAfterRoot
            };

            if (preparation != null)
                preparation.Process = receipt;
            FileAccess sinkAccess = preparation == null ? FileAccess.Write : FileAccess.ReadWrite;
            var preparationClock = preparation == null ? null : Stopwatch.StartNew();
            using var outputFile = new FileStream(stdout, FileMode.CreateNew, sinkAccess, FileShare.Read, 1);
            using var errorFile = new FileStream(stderr, FileMode.CreateNew, sinkAccess, FileShare.Read, 1);
            try
            {
                using var job = CreateJobObjectW(IntPtr.Zero, null);
                Require(!job.IsInvalid, "CreateJobObjectW");
                var limits = new JobExtendedLimits { Basic = new JobBasicLimits { Flags = KillOnClose } };
                Require(SetInformationJobObject(job, ExtendedLimits, ref limits,
                    (uint)Marshal.SizeOf<JobExtendedLimits>()), "SetInformationJobObject");

                using var trace = observeJobProcesses ? OpenJobObservation(job, receipt, refuseDiagnosticSetup) : null;
                using var input = new Pipe();
                using var output = new Pipe();
                using var error = new Pipe();
                input.Writer.Dispose();
                MakePrivate(output.Reader);
                MakePrivate(error.Reader);
                using var attributes = new Attributes(input.Reader, output.Writer, error.Writer, job);
                receipt.JobListConfigured = true;
                var startup = new StartupExtended
                {
                    Startup = new Startup
                    {
                        Size = (uint)Marshal.SizeOf<StartupExtended>(), Flags = StandardHandles,
                        Input = input.Reader.DangerousGetHandle(), Output = output.Writer.DangerousGetHandle(),
                        Error = error.Writer.DangerousGetHandle()
                    },
                    Attributes = attributes.List
                };
                ProcessInformation created;
                var pinnedEnvironment = GCHandle.Alloc(environmentBlock, GCHandleType.Pinned);
                try
                {
                    // Associate the job as part of process creation. There is no
                    // returned, unassociated suspended child between native calls.
                    receipt.CreationAttempted = true;
                    if (bootstrapToken == null)
                    {
                        Require(CreateProcessW(program, command, IntPtr.Zero, IntPtr.Zero, true,
                            Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow,
                            pinnedEnvironment.AddrOfPinnedObject(), workDirectory, ref startup, out created), "CreateProcessW");
                    }
                    else
                    {
                        Require(CreateProcessAsUserW(bootstrapToken, program, command,
                            IntPtr.Zero, IntPtr.Zero, true, Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow,
                            pinnedEnvironment.AddrOfPinnedObject(), workDirectory, ref startup, out created),
                            "CreateProcessAsUserW(bootstrap)");
                    }
                }
                finally
                {
                    pinnedEnvironment.Free();
                }
                using var process = new SafeFileHandle(created.Process, true);
                using var thread = new SafeFileHandle(created.Thread, true);
                receipt.Started = true;
                receipt.ProcessId = created.ProcessId;
                // Delete the attribute list while all its handles remain live.
                // Then release the parent copies for independent pipe EOF.
                attributes.Dispose();
                input.Reader.Dispose();
                output.Writer.Dispose();
                error.Writer.Dispose();

                var capturedOutput = new Capture(output.Reader, outputFile);
                var capturedError = new Capture(error.Reader, errorFile);
                try
                {
                    Require(IsProcessInJob(process, job, out bool member), "IsProcessInJob");
                    if (!member)
                        throw new IOException("The suspended process was not in the exact creation-time job.");
                    receipt.Assigned = true;
                    if (bootstrapToken != null)
                    {
                        using var childToken = OpenBootstrapToken(process.DangerousGetHandle(), 0x0008 | 0x0002);
                        ConfirmBootstrapToken(childToken, bootstrapSid, bootstrapSession);
                    }
                    if (trace != null)
                        RecordJobBaseline(job, receipt);
                    uint suspendCount = ResumeThread(thread);
                    if (suspendCount == uint.MaxValue)
                        throw LastError("ResumeThread");
                    if (suspendCount != 1)
                        throw new IOException("The exact primary thread did not have one suspension.");
                    receipt.Resumed = true;
                    if (preparation == null)
                        Observe(job, process, capturedOutput, capturedError, receipt, timeoutMilliseconds, trace);
                    else
                        ObserveBuildPreparation(job, process, capturedOutput, capturedError, preparation, preparationClock, trace);
                }
                catch (Exception failure)
                {
                    RecordFailure(receipt, failure, false);
                }
                if (!receipt.Drained)
                {
                    StopAndDrain(job, process, capturedOutput, capturedError, receipt, trace,
                        stopAlreadyRequested: preparation?.StopRequested == true);
                }
                receipt.StdoutBytes = capturedOutput.Written;
                receipt.StderrBytes = capturedError.Written;
                receipt.StdoutExtentUnconfirmed = capturedOutput.ExtentUnconfirmed;
                receipt.StderrExtentUnconfirmed = capturedError.ExtentUnconfirmed;
                if (receipt.RootSignaled)
                {
                    try
                    {
                        Require(GetExitCodeProcess(process, out uint exitCode), "GetExitCodeProcess");
                        receipt.ExitCode = exitCode;
                    }
                    catch (Exception failure)
                    {
                        RecordFailure(receipt, failure, true);
                    }
                }
                if (preparation != null)
                {
                    preparation.StdoutEof = capturedOutput.Eof;
                    preparation.StderrEof = capturedError.Eof;
                    if (preparation.DrainObservedMilliseconds.HasValue &&
                        receipt.Error == null && receipt.CleanupError == null)
                        MeasurePreparationSinks(outputFile, errorFile, preparation, preparationClock);
                }
            }
            catch (Exception failure)
            {
                RecordFailure(receipt, failure, false);
            }
            return receipt;
        }

        private static void Observe(SafeFileHandle job, SafeFileHandle process, Capture stdout,
            Capture stderr, Receipt receipt, int budgetMilliseconds, SafeFileHandle trace)
        {
            var stopwatch = Stopwatch.StartNew();
            byte[] buffer = new byte[16384];
            long? rootExitedWhileActive = null;
            while (true)
            {
                UpdateProcessObservations(job, process, receipt);
                if (receipt.RootSignaled && receipt.ActiveProcesses > 0)
                {
                    long observed = stopwatch.ElapsedMilliseconds;
                    rootExitedWhileActive ??= observed;
                    receipt.RootSignaledWithActiveMilliseconds = observed - rootExitedWhileActive.Value;
                }
                bool progress = stdout.Pump(buffer, receipt);
                progress |= stderr.Pump(buffer, receipt);
                if (receipt.RootSignaled && receipt.ActiveProcesses == 0 && stdout.Eof && stderr.Eof)
                {
                    receipt.Drained = true;
                    ReadJobObservation(job, trace, receipt, stopwatch, budgetMilliseconds);
                    break;
                }
                if (receipt.OutputLimitExceeded)
                    break;
                if (stopwatch.ElapsedMilliseconds >= budgetMilliseconds)
                {
                    receipt.TimedOut = true;
                    break;
                }
                ReadJobObservation(job, trace, receipt, stopwatch, budgetMilliseconds);
                if (receipt.SampleActiveAfterRoot && receipt.RootSignaled && receipt.ActiveProcesses > 0)
                    MaybeSampleActiveJobProcesses(job, receipt, stopwatch, budgetMilliseconds);
                if (!progress)
                    Thread.Sleep(10);
            }
        }

        private static void ObserveBuildPreparation(SafeFileHandle job, SafeFileHandle process, Capture stdout,
            Capture stderr, BuildPreparationReceipt preparation, Stopwatch clock, SafeFileHandle trace)
        {
            Receipt receipt = preparation.Process;
            int buildBudget = preparation.BuildBudgetMilliseconds;
            int observationDeadline = buildBudget;
            byte[] buffer = new byte[16384];
            while (true)
            {
                UpdateProcessObservations(job, process, receipt);
                bool progress = stdout.Pump(buffer, receipt);
                progress |= stderr.Pump(buffer, receipt);

                long observed = clock.ElapsedMilliseconds;
                if (observed >= observationDeadline)
                {
                    receipt.TimedOut = true;
                    return;
                }
                if (receipt.OutputLimitExceeded || stdout.ExtentUnconfirmed || stderr.ExtentUnconfirmed)
                    return;

                if (!preparation.StopRequested && receipt.RootSignaled)
                {
                    Require(GetExitCodeProcess(process, out uint exitCode), "Read held Cargo exit before retirement");
                    preparation.RootExitCodeBeforeRetirement = exitCode;
                    preparation.RootExitObservedMilliseconds = clock.ElapsedMilliseconds;
                    if (exitCode != 0)
                        return;

                    long stopAt = clock.ElapsedMilliseconds;
                    if (stopAt >= buildBudget)
                    {
                        receipt.TimedOut = true;
                        return;
                    }
                    preparation.StopRequested = true;
                    preparation.StopRequestedMilliseconds = stopAt;
                    bool stopped = TerminateJobObject(job, 1);
                    int? nativeError = stopped ? null : Marshal.GetLastWin32Error();
                    preparation.StopSucceeded = stopped;
                    preparation.StopNativeError = nativeError;
                    preparation.StopReturnedMilliseconds = clock.ElapsedMilliseconds;
                    observationDeadline = (int)Math.Min(buildBudget, stopAt + ShutdownMilliseconds);
                    if (preparation.StopReturnedMilliseconds.Value >= observationDeadline)
                        receipt.TimedOut = true;
                    if (!stopped || receipt.TimedOut)
                        return;

                    // Read a new accounting and EOF sample after the native stop
                    // return. The pre-stop sample cannot establish retirement.
                    continue;
                }
                if (preparation.StopSucceeded == true && receipt.RootSignaled &&
                    receipt.ActiveProcesses == 0 && stdout.Eof && stderr.Eof)
                {
                    preparation.DrainObservedMilliseconds = observed;
                    receipt.Drained = true;
                    ReadJobObservation(job, trace, receipt, clock, observationDeadline);
                    return;
                }

                ReadJobObservation(job, trace, receipt, clock, observationDeadline);
                if (receipt.RootSignaled && receipt.ActiveProcesses > 0)
                    MaybeSampleActiveJobProcesses(job, receipt, clock, observationDeadline);
                if (!progress)
                    Thread.Sleep(10);
            }
        }

        private static void MeasurePreparationSinks(FileStream stdout, FileStream stderr,
            BuildPreparationReceipt preparation, Stopwatch clock)
        {
            (preparation.StdoutSinkIdentity, preparation.StdoutSinkSha256) =
                MeasurePreparationSink(stdout, preparation.Process.StdoutBytes);
            (preparation.StderrSinkIdentity, preparation.StderrSinkSha256) =
                MeasurePreparationSink(stderr, preparation.Process.StderrBytes);
            preparation.SinkEvidenceObservedMilliseconds = clock.ElapsedMilliseconds;
            if (preparation.SinkEvidenceObservedMilliseconds.Value >= preparation.BuildBudgetMilliseconds ||
                preparation.SinkEvidenceObservedMilliseconds.Value - preparation.StopRequestedMilliseconds.Value >= ShutdownMilliseconds)
                preparation.Process.TimedOut = true;
        }

        private static (string Identity, string Sha256) MeasurePreparationSink(FileStream sink, int expectedBytes)
        {
            sink.Flush();
            if (sink.Length != expectedBytes)
                throw new IOException("The held preparation sink extent changed.");
            Require(GetFileInformationByHandleEx(sink.SafeFileHandle, FileIdInfo, out SinkFileIdentity id,
                (uint)Marshal.SizeOf<SinkFileIdentity>()), "Identify held preparation sink");
            if (id.Volume == 0 || (id.Low | id.High) == 0)
                throw new IOException("The held preparation sink lacks native identity.");
            sink.Position = 0;
            string digest = Convert.ToHexString(SHA256.HashData(sink));
            if (sink.Position != expectedBytes || sink.Length != expectedBytes)
                throw new IOException("The held preparation sink read-back disagreed with its extent.");
            return (FormattableString.Invariant($"{id.Volume:X16}:{id.High:X16}{id.Low:X16}"), digest);
        }

        private static BuildPreparationDisposition ClassifyBuildPreparation(BuildPreparationReceipt preparation)
        {
            Receipt process = preparation.Process;
            if (process.TimedOut)
                return BuildPreparationDisposition.PreparationTimedOut;
            if ((process.CreationAttempted && !process.Drained) || process.CleanupError != null ||
                process.StdoutExtentUnconfirmed || process.StderrExtentUnconfirmed ||
                (preparation.StopRequested && !preparation.StopSucceeded.HasValue))
                return BuildPreparationDisposition.PreparationUncertain;
            if (!process.JobListConfigured || !process.Started || !process.Assigned || !process.Resumed ||
                !process.RootSignaled || !process.Drained || process.ActiveProcesses != 0 ||
                process.Error != null || process.OutputLimitExceeded || process.ExitCode != 0 ||
                preparation.RootExitCodeBeforeRetirement != 0 ||
                !preparation.StopRequested || preparation.StopSucceeded != true || preparation.StopNativeError != null ||
                !preparation.StdoutEof || !preparation.StderrEof ||
                preparation.StdoutSinkIdentity == null || preparation.StderrSinkIdentity == null ||
                StringComparer.Ordinal.Equals(preparation.StdoutSinkIdentity, preparation.StderrSinkIdentity) ||
                preparation.StdoutSinkSha256 == null || preparation.StderrSinkSha256 == null)
                return BuildPreparationDisposition.PreparationFailed;
            if (preparation.RootExitObservedMilliseconds is not long rootAt ||
                preparation.StopRequestedMilliseconds is not long stopAt ||
                preparation.StopReturnedMilliseconds is not long stoppedAt ||
                preparation.DrainObservedMilliseconds is not long drainedAt ||
                preparation.SinkEvidenceObservedMilliseconds is not long measuredAt ||
                rootAt < 0 || rootAt > stopAt || stopAt > stoppedAt || stoppedAt > drainedAt || drainedAt > measuredAt ||
                measuredAt >= preparation.BuildBudgetMilliseconds || measuredAt - stopAt >= ShutdownMilliseconds)
                return BuildPreparationDisposition.PreparationUncertain;
            return BuildPreparationDisposition.QuiescedAfterRootExit;
        }

        private static void StopAndDrain(SafeFileHandle job, SafeFileHandle process,
            Capture stdout, Capture stderr, Receipt receipt, SafeFileHandle trace, bool stopAlreadyRequested)
        {
            if (!stopAlreadyRequested)
            {
                try
                {
                    Require(TerminateJobObject(job, 1), "TerminateJobObject");
                }
                catch (Exception failure)
                {
                    RecordFailure(receipt, failure, true);
                }
            }

            if (!receipt.Assigned)
            {
                try
                {
                    // The membership check failed before resume. Retire the held
                    // suspended process even if it was not associated as requested.
                    if (!IsSignaled(process))
                        Require(TerminateProcess(process, 1), "TerminateProcess");
                }
                catch (Exception failure)
                {
                    RecordFailure(receipt, failure, true);
                }
            }

            var stopwatch = Stopwatch.StartNew();
            byte[] buffer = new byte[16384];
            try
            {
                while (true)
                {
                    UpdateProcessObservations(job, process, receipt);
                    stdout.Pump(buffer, receipt);
                    stderr.Pump(buffer, receipt);
                    if (receipt.RootSignaled && receipt.ActiveProcesses == 0 && stdout.Eof && stderr.Eof)
                    {
                        receipt.Drained = true;
                        ReadJobObservation(job, trace, receipt, stopwatch, ShutdownMilliseconds);
                        return;
                    }
                    if (stopwatch.ElapsedMilliseconds >= ShutdownMilliseconds)
                        throw new IOException("The process and output pipes did not drain within the cleanup budget.");
                    ReadJobObservation(job, trace, receipt, stopwatch, ShutdownMilliseconds);
                    Thread.Sleep(10);
                }
            }
            catch (Exception failure)
            {
                RecordFailure(receipt, failure, true);
            }
        }

        private static void UpdateProcessObservations(SafeFileHandle job, SafeFileHandle process, Receipt receipt)
        {
            receipt.RootSignaled = IsSignaled(process);
            Require(QueryInformationJobObject(job, BasicAccounting, out JobAccounting accounting,
                (uint)Marshal.SizeOf<JobAccounting>(), IntPtr.Zero), "QueryInformationJobObject");
            receipt.ActiveProcesses = accounting.Active;
            receipt.TotalProcesses = accounting.Processes;
            if (receipt.JobProcessEvents != null)
                receipt.LimitTerminations = accounting.Terminated;
        }

        private static SafeFileHandle OpenJobObservation(SafeFileHandle job, Receipt receipt, bool refuse)
        {
            SafeFileHandle port = null;
            try
            {
                receipt.JobProcessEvents = new List<JobProcessEvent>();
                if (refuse)
                    throw new IOException("Synthetic job observer setup refusal.");
                port = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, UIntPtr.Zero, 1);
                Require(!port.IsInvalid, "CreateIoCompletionPort");
                var association = new JobCompletionPort { Key = job.DangerousGetHandle(), Port = port.DangerousGetHandle() };
                Require(SetInformationJobObject(job, AssociateCompletionPort, ref association,
                    (uint)Marshal.SizeOf<JobCompletionPort>()), "Associate job completion port");
                return port;
            }
            catch (Exception failure)
            {
                receipt.JobProcessObservationError = "Job observer setup: " + DescribeObservationFailure(failure);
                port?.Dispose();
                return null;
            }
        }

        private static void RecordJobBaseline(SafeFileHandle job, Receipt receipt)
        {
            try
            {
                Require(QueryInformationJobObject(job, BasicAccounting, out JobAccounting accounting,
                    (uint)Marshal.SizeOf<JobAccounting>(), IntPtr.Zero), "Baseline job accounting");
                receipt.TotalProcessesBeforeResume = accounting.Processes;
            }
            catch (Exception failure)
            {
                receipt.JobProcessBaselineError = DescribeObservationFailure(failure);
            }
        }

        private static void ReadJobObservation(SafeFileHandle job, SafeFileHandle port, Receipt receipt,
            Stopwatch stopwatch, int budgetMilliseconds)
        {
            if (port == null || port.IsClosed)
                return;

            try
            {
                // Notification delivery is best effort. PID reuse can make
                // lookup resolve a later process even inside this exact job.
                for (int read = 0; read < JobEventBatch && stopwatch.ElapsedMilliseconds < budgetMilliseconds; read++)
                {
                    if (!GetQueuedCompletionStatus(port, out uint message, out UIntPtr key, out UIntPtr value, 0))
                    {
                        if (Marshal.GetLastWin32Error() != WaitTimeout)
                            throw LastError("Read job completion port");
                        return;
                    }
                    if (key.ToUInt64() != (ulong)job.DangerousGetHandle().ToInt64())
                        throw new IOException("Unexpected job completion key.");

                    string kind;
                    switch (message)
                    {
                        case JobActiveProcessZero: kind = "active-zero"; break;
                        case JobNewProcess: kind = "new-process"; break;
                        case JobExitProcess: kind = "exit-process"; break;
                        case JobAbnormalExitProcess: kind = "abnormal-exit-process"; break;
                        default: continue;
                    }
                    if (receipt.JobProcessEvents.Count == JobEventLimit)
                    {
                        receipt.JobProcessEventsCapped = true;
                        DetachJobObservation(job, port, receipt);
                        return;
                    }
                    ulong pid = message == JobActiveProcessZero ? 0 : value.ToUInt64();
                    if (pid > uint.MaxValue || (message != JobActiveProcessZero && pid == 0))
                        throw new IOException("Unexpected job completion process identifier.");

                    var entry = new JobProcessEvent { Kind = kind, ProcessId = (uint)pid };
                    receipt.JobProcessEvents.Add(entry);
                    if (message == JobNewProcess)
                        TryResolveJobProcess(job, entry, receipt.ObservedProgram, stopwatch, budgetMilliseconds);
                }
            }
            catch (Exception failure)
            {
                receipt.JobProcessObservationError = "Job observer read: " + DescribeObservationFailure(failure);
                DetachJobObservation(job, port, receipt);
            }
        }

        private static void DetachJobObservation(SafeFileHandle job, SafeFileHandle port, Receipt receipt)
        {
            try
            {
                var association = new JobCompletionPort();
                Require(SetInformationJobObject(job, AssociateCompletionPort, ref association,
                    (uint)Marshal.SizeOf<JobCompletionPort>()), "Detach job completion port");
            }
            catch (Exception failure)
            {
                receipt.JobProcessDetachError = DescribeObservationFailure(failure);
            }
            finally
            {
                port.Dispose();
            }
        }

        private static void MaybeSampleActiveJobProcesses(SafeFileHandle job, Receipt receipt,
            Stopwatch stopwatch, int budgetMilliseconds)
        {
            long observed = stopwatch.ElapsedMilliseconds;
            if (observed >= budgetMilliseconds - ActiveSampleReserveMilliseconds ||
                (receipt.LastPostRootSampleAttemptMilliseconds is long previous &&
                    observed - previous < ActiveSampleIntervalMilliseconds))
                return;

            receipt.LastPostRootSampleAttemptMilliseconds = observed;
            try
            {
                var buffer = new byte[ProcessIdListHeaderBytes + ActiveSampleLimit * ProcessIdBytes];
                Require(QueryInformationJobObject(job, BasicProcessIdList, buffer, (uint)buffer.Length,
                    out uint returned), "Query active job process IDs");
                uint[] pids = DecodeActiveJobProcessIds(buffer, returned);
                if (pids.Length == 0)
                {
                    // The earlier accounting sample may race with a normal exit.
                    receipt.LastPostRootSampleError = "The listed job was empty when sampled.";
                    return;
                }

                var processes = new List<JobProcessEvent>(pids.Length);
                foreach (uint pid in pids)
                {
                    var entry = new JobProcessEvent { Kind = "post-root-active-sample", ProcessId = pid };
                    TryResolveJobProcess(job, entry, receipt.ObservedProgram, stopwatch,
                        budgetMilliseconds - ActiveSampleReserveMilliseconds);
                    processes.Add(entry);
                }
                receipt.LastPostRootActiveSample = new ActiveJobProcessSample
                {
                    ObservedMilliseconds = observed,
                    Processes = processes
                };
                receipt.LastPostRootSampleError = null;
            }
            catch (Exception failure)
            {
                receipt.LastPostRootSampleError = failure is InvalidDataException
                    ? failure.Message
                    : DescribeObservationFailure(failure);
            }
        }

        private static uint[] DecodeActiveJobProcessIds(byte[] buffer, uint returned)
        {
            // Server 2025 x64 uses two DWORDs followed by an array of ULONG_PTR.
            if (returned < ProcessIdListHeaderBytes || returned > buffer.Length)
                throw new InvalidDataException("Invalid active job process list extent.");
            uint assigned = BitConverter.ToUInt32(buffer, 0);
            uint listed = BitConverter.ToUInt32(buffer, 4);
            if (assigned != listed || listed > ActiveSampleLimit ||
                returned < ProcessIdListHeaderBytes + listed * ProcessIdBytes)
                throw new InvalidDataException("The active job process list was incomplete or exceeded its bound.");

            var pids = new uint[(int)listed];
            for (int index = 0; index < pids.Length; index++)
            {
                ulong pid = BitConverter.ToUInt64(buffer, ProcessIdListHeaderBytes + index * ProcessIdBytes);
                if (pid == 0 || pid > uint.MaxValue || Array.IndexOf(pids, (uint)pid, 0, index) >= 0)
                    throw new InvalidDataException("Invalid or duplicate active job process identifier.");
                pids[index] = (uint)pid;
            }
            return pids;
        }

        private static void TryResolveJobProcess(SafeFileHandle job, JobProcessEvent entry,
            string program, Stopwatch stopwatch, int budgetMilliseconds)
        {
            try
            {
                if (stopwatch.ElapsedMilliseconds >= budgetMilliseconds)
                {
                    entry.LookupFailure = "Observation budget expired.";
                    return;
                }
                using var process = OpenProcess(QueryLimitedInformation, false, entry.ProcessId);
                Require(!process.IsInvalid, "OpenProcess");
                Require(IsProcessInJob(process, job, out bool member), "IsProcessInJob");
                if (!member)
                {
                    entry.LookupFailure = "PID no longer resolves to a member of this job.";
                    return;
                }
                RecordProcessIdentity(process, entry, program);
            }
            catch (Exception failure)
            {
                entry.LookupFailure = DescribeObservationFailure(failure);
            }
        }

        private static string DescribeObservationFailure(Exception failure)
        {
            if (failure is Win32Exception native)
                return failure.Message + " (Win32 " + native.NativeErrorCode + ")";
            if (failure is IOException)
                return failure.Message;
            return failure.GetType().Name;
        }

        private static void RecordProcessIdentity(SafeFileHandle process, JobProcessEvent entry, string program)
        {
            uint length = 1024;
            var image = new StringBuilder((int)length);
            if (QueryFullProcessImageNameW(process, 0, image, ref length))
            {
                string imagePath = image.ToString();
                entry.Image = Path.GetFileName(imagePath);
                entry.SelectedImage = StringComparer.OrdinalIgnoreCase.Equals(imagePath, program);
                entry.SystemConsoleHost = StringComparer.OrdinalIgnoreCase.Equals(imagePath,
                    Path.Combine(Environment.SystemDirectory, "conhost.exe"));
            }
            else
                entry.LookupFailure = "QueryFullProcessImageNameW: " + Marshal.GetLastWin32Error();

            uint size = (uint)Marshal.SizeOf<ProcessBasicInformation>();
            int status = NtQueryInformationProcess(process, 0, out ProcessBasicInformation identity, size, out uint returned);
            if (status == 0 && returned == size && identity.ProcessId.ToUInt64() == entry.ProcessId &&
                identity.ParentProcessId.ToUInt64() <= uint.MaxValue)
                entry.ParentProcessId = identity.ParentProcessId.ToUInt32();
            else
                entry.LookupFailure = (entry.LookupFailure ?? "") +
                    " ProcessBasicInformation: status=" + status + ", bytes=" + returned;
        }

        private static bool IsSignaled(SafeFileHandle process)
        {
            uint state = WaitForSingleObject(process, 0);
            if (state == WaitObject)
                return true;
            if (state == WaitTimeout)
                return false;
            throw LastError("WaitForSingleObject");
        }

        // Stream state remains committed independently, including when the
        // other stream or its sink fails in the same observation.
        private sealed class Capture
        {
            private readonly SafeFileHandle pipe;
            private readonly Stream sink;
            private bool writesDisabled;
            public int Written { get; private set; }
            public bool Eof { get; private set; }
            public bool ExtentUnconfirmed { get; private set; }

            public Capture(SafeFileHandle pipe, Stream sink)
            {
                this.pipe = pipe;
                this.sink = sink;
            }

            public bool Pump(byte[] buffer, Receipt receipt)
            {
                if (Eof)
                    return false;
                if (!PeekNamedPipe(pipe, IntPtr.Zero, 0, IntPtr.Zero, out uint available, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != BrokenPipe)
                        throw new Win32Exception(error, "PeekNamedPipe");
                    Eof = true;
                    return false;
                }
                if (available == 0)
                    return false;
                // No other reader can consume the observed bytes.
                uint requested = Math.Min(available, (uint)buffer.Length);
                Require(ReadFile(pipe, buffer, requested, out uint received, IntPtr.Zero), "ReadFile");
                if (received == 0 || received > requested)
                    throw new IOException("Pipe read disagreed with its bounded availability.");
                CaptureBytes(buffer, (int)received, receipt);
                return true;
            }

            private void CaptureBytes(byte[] buffer, int received, Receipt receipt)
            {
                if (writesDisabled)
                    return;
                int keep = Math.Min(received, StreamLimitBytes - Written);
                try
                {
                    if (keep > 0)
                    {
                        sink.Write(buffer, 0, keep);
                        Written += keep;
                    }
                }
                catch
                {
                    // A throwing file write can have advanced the extent. Never
                    // issue a second write to this sink, including during drain.
                    writesDisabled = true;
                    try
                    {
                        long observed = sink.Length;
                        if (observed >= Written && observed <= StreamLimitBytes)
                            Written = checked((int)observed);
                        else
                            ExtentUnconfirmed = true;
                    }
                    catch (Exception)
                    {
                        ExtentUnconfirmed = true;
                    }
                    throw;
                }
                if (keep != received)
                    receipt.OutputLimitExceeded = true;
            }
        }

        private static void RequireExactPath(string path)
        {
            RequireBoundedText(path, 32766, nameof(path));
            if (!Path.IsPathFullyQualified(path) || !StringComparer.Ordinal.Equals(path, Path.GetFullPath(path)))
                throw new ArgumentException("Supply an exact, fully qualified path.", nameof(path));
        }

        private static void RequireBoundedText(string value, int maximum, string parameter)
        {
            if (value == null || value.Length > maximum || value.IndexOf('\0') >= 0)
                throw new ArgumentException("Input contains a NUL or exceeds its bound.", parameter);
        }

        private static void MakePrivate(SafeFileHandle handle)
        {
            Require(SetHandleInformation(handle, HandleInheritable, 0), "SetHandleInformation");
        }

        private static void Require(bool success, string operation)
        {
            if (!success)
                throw LastError(operation);
        }

        private static Win32Exception LastError(string operation)
        {
            return new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        private static void RecordFailure(Receipt receipt, Exception failure, bool cleanup)
        {
            int? code = (failure as Win32Exception)?.NativeErrorCode;
            if (cleanup)
            {
                receipt.CleanupNativeError ??= code;
                receipt.CleanupError = receipt.CleanupError == null ? failure.Message :
                    receipt.CleanupError + "; " + failure.Message;
            }
            else
            {
                receipt.NativeError ??= code;
                receipt.Error ??= failure.Message;
            }
        }

        private sealed class Pipe : IDisposable
        {
            public SafeFileHandle Reader { get; }
            public SafeFileHandle Writer { get; }

            public Pipe()
            {
                Security attributes = new Security { Size = (uint)Marshal.SizeOf<Security>(), Inherit = 1 };
                // On failure, Windows leaves both returned values indeterminate.
                // Only a successful creation transfers handles into managed ownership.
                Require(CreatePipe(out IntPtr reader, out IntPtr writer, ref attributes, 0), "CreatePipe");
                Reader = new SafeFileHandle(reader, true);
                Writer = new SafeFileHandle(writer, true);
            }

            public void Dispose()
            {
                Writer.Dispose();
                Reader.Dispose();
            }
        }

        private sealed class Attributes : IDisposable
        {
            public IntPtr List { get; private set; }
            private IntPtr handles;
            private IntPtr jobs;
            private bool initialized;

            public Attributes(SafeFileHandle input, SafeFileHandle output, SafeFileHandle error,
                SafeFileHandle job)
            {
                try
                {
                    UIntPtr bytes = UIntPtr.Zero;
                    bool unexpected = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref bytes);
                    int code = Marshal.GetLastWin32Error();
                    if (unexpected || code != InsufficientBuffer || bytes.ToUInt64() == 0 || bytes.ToUInt64() > 65536)
                        throw new IOException("Unexpected process attribute list size query.");
                    List = Marshal.AllocHGlobal(checked((int)bytes.ToUInt64()));
                    Require(InitializeProcThreadAttributeList(List, 2, 0, ref bytes), "InitializeProcThreadAttributeList");
                    initialized = true;
                    handles = Marshal.AllocHGlobal(3 * IntPtr.Size);
                    Marshal.WriteIntPtr(handles, 0, input.DangerousGetHandle());
                    Marshal.WriteIntPtr(handles, IntPtr.Size, output.DangerousGetHandle());
                    Marshal.WriteIntPtr(handles, 2 * IntPtr.Size, error.DangerousGetHandle());
                    Require(UpdateProcThreadAttribute(List, 0, new UIntPtr(ProcessHandleList), handles,
                        new UIntPtr((uint)(3 * IntPtr.Size)), IntPtr.Zero, IntPtr.Zero),
                        "UpdateProcThreadAttribute(HANDLE_LIST)");
                    // Keep the attribute values alive through deletion of the list.
                    // The noninheritable job itself is never in HANDLE_LIST.
                    jobs = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
                    Require(UpdateProcThreadAttribute(List, 0, new UIntPtr(ProcessJobList), jobs,
                        new UIntPtr((uint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero),
                        "UpdateProcThreadAttribute(JOB_LIST)");
                }
                catch
                {
                    Dispose();
                    throw;
                }
            }

            public void Dispose()
            {
                if (initialized)
                {
                    DeleteProcThreadAttributeList(List);
                    initialized = false;
                }
                Marshal.FreeHGlobal(jobs);
                jobs = IntPtr.Zero;
                Marshal.FreeHGlobal(handles);
                handles = IntPtr.Zero;
                Marshal.FreeHGlobal(List);
                List = IntPtr.Zero;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string name);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
            out SinkFileIdentity identity, uint length);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref JobExtendedLimits limits, uint length);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out JobAccounting accounting, uint length, IntPtr actualLength);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, [Out] byte[] buffer,
            uint length, out uint actualLength);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref JobCompletionPort port, uint length);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateIoCompletionPort(IntPtr file, IntPtr port, UIntPtr key, uint threads);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetQueuedCompletionStatus(SafeFileHandle port, out uint bytes, out UIntPtr key,
            out UIntPtr value, uint milliseconds);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool QueryFullProcessImageNameW(SafeFileHandle process, uint flags,
            StringBuilder image, ref uint length);

        // Only the optional Windows Server 2025 diagnostic uses this layout.
        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtQueryInformationProcess(SafeFileHandle process, int kind, out ProcessBasicInformation identity,
            uint length, out uint returned);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool IsProcessInJob(SafeFileHandle process, SafeFileHandle job,
            [MarshalAs(UnmanagedType.Bool)] out bool member);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern uint ResumeThread(SafeFileHandle thread);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeFileHandle process, uint milliseconds);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr reader, out IntPtr writer, ref Security attributes, uint size);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool PeekNamedPipe(SafeFileHandle pipe, IntPtr buffer, uint length, IntPtr copied, out uint available, IntPtr remaining);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool ReadFile(SafeFileHandle pipe, [Out] byte[] buffer, uint length, out uint copied, IntPtr overlapped);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, uint count, uint flags, ref UIntPtr bytes);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, UIntPtr kind, IntPtr value, UIntPtr size, IntPtr oldValue, IntPtr length);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateRestrictedToken(SafeFileHandle existing, uint flags,
            uint disableSidCount, IntPtr sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete,
            uint restrictedSidCount, IntPtr restrictedSids, out SafeFileHandle token);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetTokenInformation(SafeFileHandle token, int informationClass,
            out uint value, uint length, out uint written);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool LookupPrivilegeValueW(string system, string name, out BootstrapLuid value);

        [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetBootstrapTokenBytes(SafeFileHandle token, int informationClass,
            [Out] byte[] bytes, uint length, out uint written);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateProcessAsUserW(SafeFileHandle token, string application,
            [In, Out] StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
            bool inherit, uint flags, IntPtr environment, string currentDirectory,
            ref StartupExtended startup, out ProcessInformation information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateProcessW(string application, [In, Out] StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string currentDirectory,
            ref StartupExtended startup, out ProcessInformation information);
    }
}
