using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace ClarionDbg.Engine;

public sealed class DebugSession
{
    public record Breakpoint(string? Module, int Line);
    public record Frame(string Proc, uint Addr, string? Module, int? Line);
    public record VarValue(string Name, uint Addr, string TypeName, string Display);
    public record StopInfo(uint Eip, string? Module, int? Line, IReadOnlyList<Frame> Stack,
                           IReadOnlyList<VarValue> Globals, IReadOnlyList<VarValue> Locals, string Reason);

    public event Action<StopInfo>? Stopped;
    public event Action<int>? Exited;
    public event Action<string>? Log;

    readonly PeImage _pe;
    readonly TswdInfo _info;
    readonly string _exePath;

    IntPtr _hProcess, _hThread;
    uint _base;
    uint _pid;
    readonly Dictionary<uint, byte> _breakpoints = new();   // VA -> original byte
    uint? _reArm;                                            // VA pending re-arm after single-step
    readonly ConcurrentDictionary<uint, IntPtr> _threads = new();

    readonly AutoResetEvent _resume = new(false);
    volatile bool _terminate;
    Thread? _worker;

    public DebugSession(string exePath, PeImage pe, TswdInfo info)
    { _exePath = exePath; _pe = pe; _info = info; }

    public IReadOnlyList<Breakpoint> RequestedBreaks { get; private set; } = Array.Empty<Breakpoint>();

    public void Start(IEnumerable<Breakpoint> breaks)
    {
        RequestedBreaks = breaks.ToList();
        _worker = new Thread(Run) { IsBackground = true, Name = "ClarionDbg" };
        _worker.Start();
    }

    public void Continue() => _resume.Set();
    public void Terminate() { _terminate = true; _resume.Set(); }

    void Run()
    {
        var si = new Native.STARTUPINFO(); si.cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(si);
        if (!Native.CreateProcess(_exePath, null, IntPtr.Zero, IntPtr.Zero, false,
                Native.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero,
                Path.GetDirectoryName(_exePath), ref si, out var pi))
        {
            Log?.Invoke("CreateProcess failed: " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            return;
        }
        _pid = pi.dwProcessId;
        var buf = new byte[256];
        bool running = true;
        while (running)
        {
            if (!Native.WaitForDebugEvent(buf, Native.INFINITE)) break;
            uint code = U32(buf, 0);
            uint tid = U32(buf, 8);
            uint status = Native.DBG_CONTINUE;

            switch (code)
            {
                case Native.CREATE_PROCESS_DEBUG_EVENT:
                    _hProcess = (IntPtr)U32(buf, 16);
                    _hThread = (IntPtr)U32(buf, 20);
                    _base = U32(buf, 24);
                    _threads[tid] = _hThread;
                    Log?.Invoke($"Process created. image base = 0x{_base:X8}");
                    ArmBreakpoints();
                    break;

                case Native.CREATE_THREAD_DEBUG_EVENT:
                    _threads[tid] = (IntPtr)U32(buf, 12);
                    break;

                case Native.EXIT_PROCESS_DEBUG_EVENT:
                    Log?.Invoke($"Process exited (code {U32(buf, 12)}).");
                    Exited?.Invoke((int)U32(buf, 12));
                    running = false;
                    break;

                case Native.EXCEPTION_DEBUG_EVENT:
                    status = HandleException(buf, tid, ref running);
                    break;
            }
            if (running) Native.ContinueDebugEvent(_pid, tid, status);
        }
        if (_hProcess != IntPtr.Zero) Native.CloseHandle(_hProcess);
    }

    uint HandleException(byte[] buf, uint tid, ref bool running)
    {
        uint exCode = U32(buf, 12);
        uint exAddr = U32(buf, 24);

        if (exCode == Native.EXCEPTION_SINGLE_STEP && _reArm is uint rearm)
        {
            WriteByte(rearm, 0xCC);              // restore the breakpoint we stepped over
            _reArm = null;
            return Native.DBG_CONTINUE;
        }

        if (exCode == Native.EXCEPTION_BREAKPOINT && _breakpoints.ContainsKey(exAddr))
        {
            var hThread = _threads.TryGetValue(tid, out var h) ? h : _hThread;
            // restore original byte and rewind EIP onto the instruction
            WriteByte(exAddr, _breakpoints[exAddr]);
            var ctx = new Native.CONTEXT { ContextFlags = Native.CONTEXT_FULL };
            Native.GetThreadContext(hThread, ref ctx);
            ctx.Eip = exAddr;
            Native.SetThreadContext(hThread, ref ctx);

            ReportStop(ctx, "breakpoint");

            // wait for the UI to tell us to continue
            _resume.WaitOne();
            if (_terminate)
            {
                Native.TerminateProcess(_hProcess, 0);
                return Native.DBG_CONTINUE;
            }
            // single-step over the original instruction, then re-arm 0xCC
            ctx.ContextFlags = Native.CONTEXT_FULL;
            Native.GetThreadContext(hThread, ref ctx);
            ctx.EFlags |= 0x100; // trap flag
            Native.SetThreadContext(hThread, ref ctx);
            _reArm = exAddr;
            return Native.DBG_CONTINUE;
        }

        // not ours (e.g. initial loader breakpoint) — for the very first BP, swallow it
        if (exCode == Native.EXCEPTION_BREAKPOINT) return Native.DBG_CONTINUE;
        return Native.DBG_EXCEPTION_NOT_HANDLED;
    }

    void ArmBreakpoints()
    {
        foreach (var bp in RequestedBreaks)
        {
            var rva = _info.LineToRva(bp.Line, bp.Module);
            if (rva is not uint r) { Log?.Invoke($"No code for {bp.Module}:{bp.Line}."); continue; }
            uint va = _base + r;
            if (_breakpoints.ContainsKey(va)) continue;
            _breakpoints[va] = ReadByte(va);
            WriteByte(va, 0xCC);
            Log?.Invoke($"Breakpoint armed: {bp.Module}:{bp.Line} @ 0x{va:X8}");
        }
    }

    void ReportStop(Native.CONTEXT ctx, string reason)
    {
        uint eipRva = ctx.Eip - _base;
        var loc = _info.Locate(eipRva);

        // EBP call-stack walk
        var stack = new List<Frame> { new(FrameLabel(eipRva, ctx.Eip), ctx.Eip, loc?.Module, loc?.Line) };
        uint ebp = ctx.Ebp;
        for (int i = 0; i < 32 && ebp != 0; i++)
        {
            uint retAddr = ReadDword(ebp + 4);
            uint nextEbp = ReadDword(ebp);
            if (retAddr == 0) break;
            uint rRva = retAddr - _base;
            var floc = _pe.IsCodeRva(rRva) ? _info.Locate(rRva) : null;
            stack.Add(new Frame(FrameLabel(rRva, retAddr), retAddr, floc?.Module, floc?.Line));
            if (nextEbp <= ebp) break;
            ebp = nextEbp;
        }

        // globals (typed where possible, else raw hex+ascii sized by the next-symbol gap)
        var globals = new List<VarValue>();
        foreach (var g in _info.Globals)
            globals.Add(ReadVar(g.Name, _base + g.Rva, g.Type, g.DisplaySize, g.Threaded));

        // locals of the procedure we stopped in (EBP-relative)
        var locals = new List<VarValue>();
        var proc = _info.ProcContaining(eipRva);
        if (proc != null)
            foreach (var lv in proc.Locals.OrderBy(l => l.FrameOffset))
                locals.Add(ReadVar(lv.Name, (uint)((long)ctx.Ebp + lv.FrameOffset),
                                   lv.Type, lv.Type.Size > 0 ? lv.Type.Size : 4));

        Stopped?.Invoke(new StopInfo(ctx.Eip, loc?.Module, loc?.Line, stack, globals, locals, reason));
    }

    VarValue ReadVar(string name, uint va, ClaType type, int size, bool threaded = false)
    {
        int n = Math.Clamp(size, 1, 8192);   // guard against garbage sizes
        string disp;
        try
        {
            var raw = ReadBytes(va, n);
            disp = type.Kind == TypeKind.Unknown ? RenderRaw(raw) : type.Format(raw);
        }
        catch { disp = "<unreadable>"; }
        if (threaded) disp = "[tls] " + disp;
        string tn = type.Kind == TypeKind.Unknown ? $"<{n}b>" : type.Describe();
        return new VarValue(name, va, tn, disp);
    }

    /// <summary>Show undecoded data as hex with an ASCII gutter so values stay readable.</summary>
    static string RenderRaw(byte[] b)
    {
        int n = Math.Min(b.Length, 48);
        var hex = new System.Text.StringBuilder();
        for (int i = 0; i < Math.Min(n, 12); i++) hex.Append(b[i].ToString("X2")).Append(' ');
        var asc = new string(b.Take(n).Select(x => x >= 32 && x < 127 ? (char)x : '·').ToArray());
        return $"{hex.ToString().TrimEnd()}   '{asc}'";
    }

    string FrameLabel(uint rva, uint absAddr)
    {
        if (!_pe.IsCodeRva(rva)) return $"[runtime]  0x{absAddr:X8}";
        var p = _info.ProcContaining(rva);
        return p != null ? p.Name : $"0x{absAddr:X8}";
    }

    // ---- process memory helpers ----
    byte ReadByte(uint va) { var b = new byte[1]; Native.ReadProcessMemory(_hProcess, (IntPtr)va, b, 1, out _); return b[0]; }
    byte[] ReadBytes(uint va, int n) { var b = new byte[n]; Native.ReadProcessMemory(_hProcess, (IntPtr)va, b, n, out _); return b; }
    uint ReadDword(uint va) => BinaryPrimitives.ReadUInt32LittleEndian(ReadBytes(va, 4));
    void WriteByte(uint va, byte v)
    {
        Native.WriteProcessMemory(_hProcess, (IntPtr)va, new[] { v }, 1, out _);
        Native.FlushInstructionCache(_hProcess, (IntPtr)va, 1);
    }
    static uint U32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
}
