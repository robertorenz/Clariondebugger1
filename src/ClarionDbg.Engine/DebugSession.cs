using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace ClarionDbg.Engine;

public sealed class DebugSession
{
    public enum WriteKind { Int, UInt, Float, Str, Raw }
    public record Breakpoint(string? Module, int Line);
    public record Frame(string Proc, uint Addr, string? Module, int? Line, IReadOnlyList<VarValue> Locals);
    public record VarValue(string Name, uint Addr, string TypeName, string Display, string Full, int Size, WriteKind Kind);
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
    Thread? _worker;

    // ---- stepping ----
    enum Act { Continue, Into, Over, Out, Terminate }
    volatile Act _act = Act.Continue;
    enum StepKind { None, Into, Over }
    StepKind _stepping = StepKind.None;
    string? _stepModule; int _stepLine;
    uint _stepEbp, _stepLo, _stepHi;
    int _stepGuard;                                         // bound single-step count
    readonly Dictionary<uint, byte> _tempBps = new();       // one-shot step breakpoints
    readonly HashSet<uint> _overReturns = new();            // temp bps that are step-over-call returns

    public DebugSession(string exePath, PeImage pe, TswdInfo info)
    { _exePath = exePath; _pe = pe; _info = info; }

    public IReadOnlyList<Breakpoint> RequestedBreaks { get; private set; } = Array.Empty<Breakpoint>();

    public void Start(IEnumerable<Breakpoint> breaks)
    {
        RequestedBreaks = breaks.ToList();
        _worker = new Thread(Run) { IsBackground = true, Name = "ClarionDbg" };
        _worker.Start();
    }

    public void Continue() { _act = Act.Continue; _resume.Set(); }
    public void StepInto() { _act = Act.Into; _resume.Set(); }
    public void StepOver() { _act = Act.Over; _resume.Set(); }
    public void StepOut()  { _act = Act.Out;  _resume.Set(); }
    public void Terminate() { _act = Act.Terminate; _resume.Set(); }

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
        var hThread = _threads.TryGetValue(tid, out var h) ? h : _hThread;

        // ---- single-step (stepping or breakpoint re-arm) ----
        if (exCode == Native.EXCEPTION_SINGLE_STEP)
        {
            if (_reArm is uint rearm) { WriteByte(rearm, 0xCC); _reArm = null; }
            if (_stepping == StepKind.None) return Native.DBG_CONTINUE;
            var ctx = GetCtx(hThread);
            return HandleStep(ref ctx, hThread);
        }

        // ---- breakpoint ----
        if (exCode == Native.EXCEPTION_BREAKPOINT)
        {
            // one-shot stepping breakpoint (step-over call return, or step-out target)
            if (_tempBps.TryGetValue(exAddr, out byte torig))
            {
                WriteByte(exAddr, torig);
                _tempBps.Remove(exAddr);
                var ctx = GetCtx(hThread);
                ctx.Eip = exAddr; Native.SetThreadContext(hThread, ref ctx);
                if (_overReturns.Remove(exAddr)) { Trap(ref ctx, hThread); return Native.DBG_CONTINUE; }
                return Stop(ref ctx, hThread, 0);
            }
            // user breakpoint
            if (_breakpoints.TryGetValue(exAddr, out byte orig))
            {
                WriteByte(exAddr, orig);
                var ctx = GetCtx(hThread);
                ctx.Eip = exAddr; Native.SetThreadContext(hThread, ref ctx);
                return Stop(ref ctx, hThread, exAddr);
            }
            return Native.DBG_CONTINUE;   // initial loader breakpoint etc.
        }

        return Native.DBG_EXCEPTION_NOT_HANDLED;
    }

    /// <summary>Report the stop to the UI, wait for the next action, and set up the resume.</summary>
    uint Stop(ref Native.CONTEXT ctx, IntPtr hThread, uint userBpAddr)
    {
        _stepping = StepKind.None;
        ReportStop(ctx, userBpAddr != 0 ? "breakpoint" : "step");
        _resume.WaitOne();
        if (_act == Act.Terminate) { Native.TerminateProcess(_hProcess, 0); return Native.DBG_CONTINUE; }

        ctx = GetCtx(hThread);
        uint eipRva = ctx.Eip - _base;
        (_stepLo, _stepHi) = _info.ProcRange(eipRva);
        _stepEbp = ctx.Ebp; _stepGuard = 0;
        var l = _info.Locate(eipRva); _stepModule = l?.Module; _stepLine = l?.Line ?? -1;

        bool needReArm = userBpAddr != 0;
        if (needReArm) _reArm = userBpAddr;

        switch (_act)
        {
            case Act.Into: _stepping = StepKind.Into; Trap(ref ctx, hThread); break;
            case Act.Over: _stepping = StepKind.Over; Trap(ref ctx, hThread); break;
            case Act.Out:
                uint ret = ReadDword(ctx.Ebp + 4);
                if (ret != 0 && _pe.IsCodeRva(ret - _base)) SetTempBp(ret, false);
                if (needReArm) Trap(ref ctx, hThread);   // step past the bp, re-arm, then run to ret
                break;
            default:                                     // Continue
                if (needReArm) Trap(ref ctx, hThread);
                break;
        }
        return Native.DBG_CONTINUE;
    }

    /// <summary>Single-step driver: decide stop / keep-stepping / run-the-call.</summary>
    uint HandleStep(ref Native.CONTEXT ctx, IntPtr hThread)
    {
        if (++_stepGuard > 300000) return Stop(ref ctx, hThread, 0);   // safety bound
        uint eipRva = ctx.Eip - _base;
        bool inText = _pe.IsCodeRva(eipRva);
        bool inProc = inText && eipRva >= _stepLo && eipRva < _stepHi;
        var l = inText ? _info.Locate(eipRva) : null;
        bool newLine = l is { } x && (x.Module != _stepModule || x.Line != _stepLine);

        if (_stepping == StepKind.Over && !inProc)
        {
            // left the procedure (a call) — run it to completion, then resume stepping
            uint ret = ReadDword(ctx.Esp);
            if (RetInProc(ret)) { SetTempBp(ret, true); return Native.DBG_CONTINUE; }
            Trap(ref ctx, hThread); return Native.DBG_CONTINUE;
        }
        if (_stepping == StepKind.Into && !inText)
        {
            // stepped into runtime (ClaRUN) — run to return rather than single-step library code
            uint ret = ReadDword(ctx.Esp);
            if (ret != 0 && _pe.IsCodeRva(ret - _base)) { SetTempBp(ret, true); return Native.DBG_CONTINUE; }
            Trap(ref ctx, hThread); return Native.DBG_CONTINUE;
        }
        if (inText && newLine) return Stop(ref ctx, hThread, 0);
        Trap(ref ctx, hThread);
        return Native.DBG_CONTINUE;
    }

    bool RetInProc(uint ret) => ret != 0 && _pe.IsCodeRva(ret - _base)
                                && (ret - _base) >= _stepLo && (ret - _base) < _stepHi;

    Native.CONTEXT GetCtx(IntPtr hThread)
    { var c = new Native.CONTEXT { ContextFlags = Native.CONTEXT_FULL }; Native.GetThreadContext(hThread, ref c); return c; }

    void Trap(ref Native.CONTEXT ctx, IntPtr hThread)
    {
        ctx.ContextFlags = Native.CONTEXT_FULL;
        Native.GetThreadContext(hThread, ref ctx);
        ctx.EFlags |= 0x100;                     // trap flag → one single-step
        Native.SetThreadContext(hThread, ref ctx);
    }

    void SetTempBp(uint va, bool overReturn)
    {
        if (!_tempBps.ContainsKey(va)) { _tempBps[va] = ReadByte(va); WriteByte(va, 0xCC); }
        if (overReturn) _overReturns.Add(va);
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

        // EBP call-stack walk — each frame carries its own locals (read at that frame's EBP)
        _liveFrames.Clear();
        var stack = new List<Frame> { MakeFrame(ctx.Eip, ctx.Ebp) };
        uint ebp = ctx.Ebp;
        for (int i = 0; i < 32 && ebp != 0; i++)
        {
            uint retAddr = ReadDword(ebp + 4);
            uint nextEbp = ReadDword(ebp);
            if (retAddr == 0) break;
            stack.Add(MakeFrame(retAddr, nextEbp));   // caller frame: address = return addr, base = saved EBP
            if (nextEbp <= ebp) break;
            ebp = nextEbp;
        }

        // globals (typed where possible, else raw hex+ascii sized by the next-symbol gap)
        var globals = new List<VarValue>();
        foreach (var g in _info.Globals)
            globals.Add(ReadVar(g.Name, _base + g.Rva, g.Type, g.DisplaySize, g.Threaded));

        Stopped?.Invoke(new StopInfo(ctx.Eip, loc?.Module, loc?.Line, stack, globals, stack[0].Locals, reason));
    }

    readonly List<(uint Ebp, uint Rva)> _liveFrames = new();   // for live re-reading while running

    Frame MakeFrame(uint addr, uint frameEbp)
    {
        uint rva = addr - _base;
        bool code = _pe.IsCodeRva(rva);
        var l = code ? _info.Locate(rva) : null;
        _liveFrames.Add((frameEbp, rva));
        return new Frame(FrameLabel(rva, addr), addr, l?.Module, l?.Line, ReadProcLocals(frameEbp, rva));
    }

    List<VarValue> ReadProcLocals(uint frameEbp, uint rva)
    {
        var locals = new List<VarValue>();
        if (!_pe.IsCodeRva(rva)) return locals;
        var proc = _info.ProcContaining(rva);
        if (proc != null)
            foreach (var lv in proc.Locals)
            {
                uint va = lv.IsStatic ? _base + lv.Rva : (uint)((long)frameEbp + lv.FrameOffset);
                int sz = lv.Type.Size > 0 ? lv.Type.Size : lv.DisplaySize;
                locals.Add(ReadVar(lv.Name, va, lv.Type, sz, lv.Threaded));
            }
        return locals;
    }

    /// <summary>Re-read a frame's locals from CURRENT process memory (valid while running, as long
    /// as that frame is still alive). Returns empty if the process is gone.</summary>
    public IReadOnlyList<VarValue> RereadFrameLocals(int frameIndex)
    {
        if (_hProcess == IntPtr.Zero || frameIndex < 0 || frameIndex >= _liveFrames.Count)
            return Array.Empty<VarValue>();
        var (ebp, rva) = _liveFrames[frameIndex];
        return ReadProcLocals(ebp, rva);
    }

    public IReadOnlyList<VarValue> RereadGlobals()
    {
        if (_hProcess == IntPtr.Zero) return Array.Empty<VarValue>();
        var list = new List<VarValue>();
        foreach (var g in _info.Globals)
            list.Add(ReadVar(g.Name, _base + g.Rva, g.Type, g.DisplaySize, g.Threaded));
        return list;
    }

    VarValue ReadVar(string name, uint va, ClaType type, int size, bool threaded = false)
    {
        int n = Math.Clamp(size, 1, 8192);   // guard against garbage sizes
        string disp, full; WriteKind kind;
        try
        {
            var raw = ReadBytes(va, n);
            (disp, full, kind) = Render(raw, type);
        }
        catch { disp = full = "<unreadable>"; kind = WriteKind.Raw; }
        if (threaded) { disp = "[tls] " + disp; full = "(thread-local; shown from image template)\n" + full; }
        string tn = type.Kind == TypeKind.Unknown ? InferType(kind, n) : type.Describe();
        return new VarValue(name, va, tn, disp, full, n, kind);
    }

    /// <summary>Best-effort Clarion type for variables whose type record isn't decoded — inferred
    /// from byte size and content. Accurate for STRING/LONG/SHORT/BYTE/REAL; a DATE/CSTRING/&amp;ref
    /// will look like LONG/STRING.</summary>
    static string InferType(WriteKind kind, int n) => kind switch
    {
        WriteKind.Str => $"STRING({n})",
        WriteKind.Float => n <= 4 ? "SREAL" : "REAL",
        WriteKind.Int or WriteKind.UInt => n switch { 1 => "BYTE", 2 => "SHORT", 4 => "LONG", 8 => "REAL", _ => $"<{n}b>" },
        _ => $"<{n}b>"
    };

    /// <summary>Concise value + a complete tooltip + how to write it back. Undecoded data is shown
    /// as a string when it looks like text, as an integer for 4-byte fields, else hex.</summary>
    static (string Display, string Full, WriteKind Kind) Render(byte[] b, ClaType type)
    {
        if (type.Kind != TypeKind.Unknown)
        {
            string d = type.Format(b);
            WriteKind tk = type.Kind switch
            {
                TypeKind.Int => WriteKind.Int,
                TypeKind.UInt => WriteKind.UInt,
                TypeKind.Float => WriteKind.Float,
                TypeKind.String => WriteKind.Str,
                _ => WriteKind.Raw
            };
            return (d, $"{type.Describe()} = {d}", tk);
        }
        string ascii = new string(b.TakeWhile(x => x != 0).Select(x => x >= 32 && x < 127 ? (char)x : '·').ToArray());
        int printable = 0;
        foreach (var x in b) { if (x >= 32 && x < 127) printable++; else break; }

        string disp; WriteKind kind;
        if (printable >= 2)
        {
            string s = ascii.TrimEnd(' ', '·');   // drop Clarion's trailing space/null padding for readability
            disp = "'" + (s.Length > 48 ? s[..48] + "…" : s) + "'"; kind = WriteKind.Str;
        }
        else if (b.Length >= 4) { disp = BinaryPrimitives.ReadInt32LittleEndian(b).ToString(); kind = WriteKind.Int; }
        else if (b.Length == 2) { disp = BinaryPrimitives.ReadInt16LittleEndian(b).ToString(); kind = WriteKind.Int; }
        else { disp = b[0].ToString(); kind = WriteKind.Int; }

        var sb = new System.Text.StringBuilder();
        sb.Append("hex:   ").Append(BitConverter.ToString(b).Replace("-", " "));
        var allAscii = new string(b.Select(x => x >= 32 && x < 127 ? (char)x : '·').ToArray());
        sb.Append("\nascii: '").Append(allAscii).Append('\'');
        if (b.Length >= 4)
            sb.Append($"\nint32: {BinaryPrimitives.ReadInt32LittleEndian(b)}   uint32: {BinaryPrimitives.ReadUInt32LittleEndian(b)}   hex: 0x{BinaryPrimitives.ReadUInt32LittleEndian(b):X8}");
        if (b.Length >= 8)
            sb.Append($"\nreal8: {BitConverter.ToDouble(b, 0):0.######}");
        return (disp, sb.ToString(), kind);
    }

    /// <summary>Write a new value to a variable's address (works while stopped or running).</summary>
    public bool WriteVar(uint addr, WriteKind kind, int size, string input)
    {
        if (_hProcess == IntPtr.Zero || size <= 0) return false;
        input = input.Trim();
        byte[] bytes;
        try
        {
            switch (kind)
            {
                case WriteKind.Int:
                case WriteKind.UInt:
                    long v = input.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? Convert.ToInt64(input[2..], 16)
                        : long.Parse(input, System.Globalization.CultureInfo.InvariantCulture);
                    bytes = new byte[Math.Min(size, 8)];
                    for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(v >> (8 * i));
                    break;
                case WriteKind.Float:
                    double d = double.Parse(input, System.Globalization.CultureInfo.InvariantCulture);
                    bytes = size >= 8 ? BitConverter.GetBytes(d) : BitConverter.GetBytes((float)d);
                    break;
                case WriteKind.Str:
                    string s = input;
                    if (s.Length >= 2 && (s[0] == '\'' || s[0] == '"') && s[^1] == s[0]) s = s[1..^1];
                    var a = System.Text.Encoding.ASCII.GetBytes(s);
                    bytes = new byte[size];
                    for (int i = 0; i < size; i++) bytes[i] = i < a.Length ? a[i] : (byte)0x20;   // space-pad (Clarion STRING)
                    break;
                default:   // Raw: accept hex like "0A FF 00" or "0x0AFF00"
                    string hx = input.Replace("0x", "", StringComparison.OrdinalIgnoreCase).Replace(" ", "").Replace("-", "");
                    bytes = new byte[size];
                    for (int i = 0; i * 2 + 1 < hx.Length && i < size; i++) bytes[i] = Convert.ToByte(hx.Substring(i * 2, 2), 16);
                    break;
            }
        }
        catch { return false; }
        return Native.WriteProcessMemory(_hProcess, (IntPtr)addr, bytes, bytes.Length, out _);
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
