using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
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

        public sealed class JobProcessEvent
        {
            public string Kind { get; internal set; }
            public uint ProcessId { get; internal set; }
            public uint? ParentProcessId { get; internal set; }
            public string Image { get; internal set; }
            public string LookupFailure { get; internal set; }
        }

        public sealed class Receipt
        {
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
            var receipt = new Receipt();

            using var outputFile = new FileStream(stdout, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1);
            using var errorFile = new FileStream(stderr, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1);
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
                    Require(CreateProcessW(program, command, IntPtr.Zero, IntPtr.Zero, true,
                        Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow,
                        pinnedEnvironment.AddrOfPinnedObject(), workDirectory, ref startup, out created), "CreateProcessW");
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
                    if (trace != null)
                        RecordJobBaseline(job, receipt);
                    uint suspendCount = ResumeThread(thread);
                    if (suspendCount == uint.MaxValue)
                        throw LastError("ResumeThread");
                    if (suspendCount != 1)
                        throw new IOException("The exact primary thread did not have one suspension.");
                    receipt.Resumed = true;
                    Observe(job, process, capturedOutput, capturedError, receipt, timeoutMilliseconds, trace);
                }
                catch (Exception failure)
                {
                    RecordFailure(receipt, failure, false);
                }
                if (!receipt.Drained)
                {
                    StopAndDrain(job, process, capturedOutput, capturedError, receipt, trace);
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
                if (!progress)
                    Thread.Sleep(10);
            }
        }

        private static void StopAndDrain(SafeFileHandle job, SafeFileHandle process,
            Capture stdout, Capture stderr, Receipt receipt, SafeFileHandle trace)
        {
            try
            {
                Require(TerminateJobObject(job, 1), "TerminateJobObject");
            }
            catch (Exception failure)
            {
                RecordFailure(receipt, failure, true);
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
                        TryResolveJobProcess(job, entry, stopwatch, budgetMilliseconds);
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

        private static void TryResolveJobProcess(SafeFileHandle job, JobProcessEvent entry,
            Stopwatch stopwatch, int budgetMilliseconds)
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
                RecordProcessIdentity(process, entry);
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

        private static void RecordProcessIdentity(SafeFileHandle process, JobProcessEvent entry)
        {
            uint length = 1024;
            var image = new StringBuilder((int)length);
            if (QueryFullProcessImageNameW(process, 0, image, ref length))
                entry.Image = Path.GetFileName(image.ToString());
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
        private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref JobExtendedLimits limits, uint length);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out JobAccounting accounting, uint length, IntPtr actualLength);

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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateProcessW(string application, [In, Out] StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string currentDirectory,
            ref StartupExtended startup, out ProcessInformation information);
    }
}
