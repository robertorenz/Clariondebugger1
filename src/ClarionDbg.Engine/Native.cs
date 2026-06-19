using System.Runtime.InteropServices;

namespace ClarionDbg.Engine;

internal static class Native
{
    public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    public const uint DBG_CONTINUE = 0x00010002;
    public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    public const uint INFINITE = 0xFFFFFFFF;

    // debug event codes
    public const uint EXCEPTION_DEBUG_EVENT = 1;
    public const uint CREATE_THREAD_DEBUG_EVENT = 2;
    public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    public const uint EXIT_THREAD_DEBUG_EVENT = 4;
    public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    public const uint LOAD_DLL_DEBUG_EVENT = 6;
    public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    public const uint OUTPUT_DEBUG_STRING_EVENT = 8;

    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;

    // x86 CONTEXT flags
    public const uint CONTEXT_I386 = 0x00010000;
    public const uint CONTEXT_FULL = CONTEXT_I386 | 0x1 | 0x2 | 0x4; // control|integer|segments
    public const uint CONTEXT_FLOATING_POINT = CONTEXT_I386 | 0x8;   // x87 FPU (FLOATING_SAVE_AREA)
    public const uint CONTEXT_EXTENDED_REGISTERS = CONTEXT_I386 | 0x20; // SSE/XMM (ExtendedRegisters)
    // Everything we must save/restore around a function-eval hijack: a getter may clobber the FPU/SSE
    // state, and the Clarion RTL relies on it (DECIMAL/REAL math) — leaving it drifted crashes the RTL.
    public const uint CONTEXT_ALL = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO { public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    // x86 CONTEXT (size 716). We address fields by explicit offsets.
    [StructLayout(LayoutKind.Explicit, Size = 716)]
    public struct CONTEXT
    {
        [FieldOffset(0)]   public uint ContextFlags;
        [FieldOffset(156)] public uint Edi;
        [FieldOffset(160)] public uint Esi;
        [FieldOffset(164)] public uint Ebx;
        [FieldOffset(168)] public uint Edx;
        [FieldOffset(172)] public uint Ecx;
        [FieldOffset(176)] public uint Eax;
        [FieldOffset(180)] public uint Ebp;
        [FieldOffset(184)] public uint Eip;
        [FieldOffset(188)] public uint SegCs;
        [FieldOffset(192)] public uint EFlags;
        [FieldOffset(196)] public uint Esp;
        [FieldOffset(200)] public uint SegSs;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(string? app, string? cmd, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string? dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    // DEBUG_EVENT is a variable union; we receive it into a raw buffer and parse offsets ourselves.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WaitForDebugEvent(byte[] lpDebugEvent, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int written);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr h, IntPtr addr, int size);

    // ThreadBasicInformation (class 0): the result's TebBaseAddress lets us read a thread's TLS slots
    // straight from its TEB — used to read the Clarion RTL per-thread instance block without any calls.
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(IntPtr hThread, int infoClass, byte[] buf, int len, out int retLen);

    // Suspend / resume other threads during a function-evaluation hijack so only the eval thread runs.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT ctx);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT ctx);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr h, uint code);

    // Resolve the on-disk path of a DLL from the hFile handed to us in a LOAD_DLL_DEBUG_EVENT,
    // so we can parse that module's own PE + TSWD blob off disk.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetFinalPathNameByHandle(IntPtr hFile, System.Text.StringBuilder buf, uint cch, uint flags);

    // Inject a breakpoint into the debuggee (on a throwaway OS thread) so a freely-running target
    // can be interrupted — the break arrives as an EXCEPTION_BREAKPOINT in the debug loop.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugBreakProcess(IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcess(uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcessStop(uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugSetProcessKillOnExit(bool kill);
}
