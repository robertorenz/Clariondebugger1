using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace ClarionDbg.Engine;

public sealed partial class DebugSession
{
    public enum WriteKind { Int, UInt, Float, Str, Raw }

    /// <summary>A breakpoint with optional condition, hit-count gate, and tracepoint logging.</summary>
    public sealed class Breakpoint
    {
        public string? Module { get; set; }
        public int Line { get; set; }
        public uint Rva { get; set; }              // direct RVA (e.g. procedure entry); else resolved from Module/Line
        public bool Enabled { get; set; } = true;
        public string? Condition { get; set; }     // e.g. "mylocalvar1 = 5", "count > 10"
        public string? HitCondition { get; set; }  // "=N" Nth hit, ">=N" from Nth, "%N" every Nth
        public string? LogMessage { get; set; }    // tracepoint: log this & continue (no stop); {var} interpolated
        public string? Label { get; set; }         // display label for proc-entry breakpoints
        public int HitCount;                       // runtime hit counter

        public Breakpoint() { }
        public Breakpoint(string? module, int line) { Module = module; Line = line; }

        public string Where => Label ?? (Module != null || Line != 0 ? $"{Module}:{Line}" : $"0x{Rva:X8}");
    }
    public record Frame(string Proc, uint Addr, string? Module, int? Line, IReadOnlyList<VarValue> Locals);
    public record VarValue(string Name, uint Addr, string TypeName, string Display, string Full, int Size, WriteKind Kind)
    {
        public bool Threaded { get; init; }   // lives in .cwtls; Addr is the template — resolve per-thread on demand
    }
    public record ThreadRef(uint Tid, string Label);
    public record StopInfo(uint Eip, string? Module, int? Line, IReadOnlyList<Frame> Stack,
                           IReadOnlyList<VarValue> Globals, IReadOnlyList<VarValue> Locals,
                           IReadOnlyList<ThreadRef> Threads, uint Tid, string Reason);

    public event Action<StopInfo>? Stopped;
    public event Action<int>? Exited;
    public event Action<string>? Log;

    readonly string _exePath;

    IntPtr _hProcess, _hThread;
    uint _pid;
    readonly Dictionary<uint, byte> _breakpoints = new();   // VA -> original byte
    readonly Dictionary<uint, Breakpoint> _bpByVa = new();  // VA -> breakpoint metadata
    readonly List<Breakpoint> _logical = new();             // every enabled logical bp (armed or pending)
    readonly Dictionary<Breakpoint, uint> _armedAt = new(); // bp -> VA it is currently planted at
    readonly object _bpLock = new();
    uint? _reArm;                                            // VA pending re-arm after single-step
    uint? _pendingTemp;                                      // run-to-cursor target, applied on next resume
    readonly ConcurrentDictionary<uint, IntPtr> _threads = new();

    readonly AutoResetEvent _resume = new(false);
    Thread? _worker;

    // ---- stepping ----
    enum Act { Continue, Into, Over, Out, Terminate, Eval }
    volatile Act _act = Act.Continue;
    enum StepKind { None, Into, Over }
    StepKind _stepping = StepKind.None;
    string? _stepModule; int _stepLine;
    uint _stepEbp, _stepLo, _stepHi;
    int _stepGuard;                                         // bound single-step count
    readonly Dictionary<uint, byte> _tempBps = new();       // one-shot step breakpoints
    readonly HashSet<uint> _overReturns = new();            // temp bps that are step-over-call returns

    public DebugSession(string exePath, PeImage pe, TswdInfo info)
    {
        _exePath = exePath;
        _exe = new LoadedModule
        {
            Path = exePath,
            Name = Path.GetFileName(exePath).ToLowerInvariant(),
            Pe = pe,
            Info = info,
            Size = pe.SizeOfImage,
            Preloaded = true,
        };
        _exe.ResolveThreadedInfo();
        _modules.Add(_exe);
        RebuildModSnapshot();
    }

    public IReadOnlyList<Breakpoint> RequestedBreaks { get; private set; } = Array.Empty<Breakpoint>();

    /// <summary>OS process id of the debuggee (0 until the process is created/attached).</summary>
    public uint Pid => _pid;

    /// <summary>True if the given OS thread id belongs to the debuggee.</summary>
    public bool HasThread(uint tid) => _threads.ContainsKey(tid);

    bool _attachMode;
    uint _attachPid;

    public void Start(IEnumerable<Breakpoint> breaks)
    {
        RequestedBreaks = breaks.ToList();
        _worker = new Thread(Run) { IsBackground = true, Name = "ClarionDbg" };
        _worker.Start();
    }

    /// <summary>Attach the debugger to an already-running process of the same EXE.</summary>
    public void Attach(uint pid, IEnumerable<Breakpoint> breaks)
    {
        _attachMode = true; _attachPid = pid;
        Start(breaks);
    }

    public void Continue() { _act = Act.Continue; _resume.Set(); }
    public void StepInto() { _act = Act.Into; _resume.Set(); }
    public void StepOver() { _act = Act.Over; _resume.Set(); }
    public void StepOut()  { _act = Act.Out;  _resume.Set(); }
    public void Terminate() { _act = Act.Terminate; _resume.Set(); }

    volatile bool _pauseRequested;

    /// <summary>Interrupt a freely-running debuggee (break into it). Injects a breakpoint via
    /// DebugBreakProcess; the debug loop catches it and stops on a thread that's in Clarion code.
    /// Safe to call from the UI thread while the program is running.</summary>
    public void Pause()
    {
        if (_hProcess == IntPtr.Zero) { Log?.Invoke("Pause: no running process."); return; }
        _pauseRequested = true;
        if (!Native.DebugBreakProcess(_hProcess))
        {
            _pauseRequested = false;
            Log?.Invoke("Pause failed: DebugBreakProcess error "
                        + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ".");
        }
    }

    void Run()
    {
        if (_attachMode)
        {
            if (!Native.DebugActiveProcess(_attachPid))
            {
                Log?.Invoke("DebugActiveProcess failed: " + System.Runtime.InteropServices.Marshal.GetLastWin32Error()
                            + " (try running the debugger as administrator).");
                return;
            }
            _pid = _attachPid;
            Log?.Invoke($"Attached to process {_attachPid}.");
        }
        else
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
        }
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
                    // union @+12: hFile(+12) hProcess(+16) hThread(+20) lpBaseOfImage(+24)
                    _hProcess = (IntPtr)U32(buf, 16);
                    _hThread = (IntPtr)U32(buf, 20);
                    SetExeBase(U32(buf, 24));
                    _threads[tid] = _hThread;
                    Log?.Invoke($"Process created. {_exe.Name} image base = 0x{_exe.LoadBase:X8}");
                    ArmBreakpoints();
                    break;

                case Native.LOAD_DLL_DEBUG_EVENT:
                    // union @+12: hFile(+12) lpBaseOfDll(+16)
                    OnDllLoaded((IntPtr)U32(buf, 12), U32(buf, 16));
                    break;

                case Native.UNLOAD_DLL_DEBUG_EVENT:
                    // union @+12: lpBaseOfDll(+12)
                    OnDllUnloaded(U32(buf, 12));
                    break;

                case Native.CREATE_THREAD_DEBUG_EVENT:
                    _threads[tid] = (IntPtr)U32(buf, 12);
                    break;

                case Native.EXIT_THREAD_DEBUG_EVENT:
                    _threads.TryRemove(tid, out _);
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
        _stoppedTid = tid;
        var hThread = _threads.TryGetValue(tid, out var h) ? h : _hThread;

        // ---- single-step (stepping or breakpoint re-arm) ----
        if (exCode == Native.EXCEPTION_SINGLE_STEP)
        {
            if (_reArm is uint rearm)   // only re-arm if still an active breakpoint (user may have cleared it while stopped)
            {
                bool keep; lock (_bpLock) keep = _breakpoints.ContainsKey(rearm);
                if (keep) WriteByte(rearm, 0xCC); _reArm = null;
            }
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

                Breakpoint? meta; lock (_bpLock) _bpByVa.TryGetValue(exAddr, out meta);
                if (meta != null)
                {
                    meta.HitCount++;
                    bool pass = CondOk(meta, ctx) && HitOk(meta);
                    if (pass && !string.IsNullOrEmpty(meta.LogMessage))   // tracepoint: log & keep going
                    { Log?.Invoke(FormatTrace(meta, ctx)); pass = false; }
                    if (!pass) { _reArm = exAddr; Trap(ref ctx, hThread); return Native.DBG_CONTINUE; }
                }
                return Stop(ref ctx, hThread, exAddr);
            }
            // a breakpoint we didn't plant: our injected pause (DebugBreakProcess), else loader/etc.
            if (_pauseRequested)
            {
                _pauseRequested = false;
                return HandlePause(tid);
            }
            return Native.DBG_CONTINUE;   // initial loader breakpoint etc.
        }

        // ---- a crash (GPF) — stop at the fault so the user can inspect, then let it propagate ----
        if (BreakOnException && IsFatalException(exCode))
        {
            uint firstChance = U32(buf, 92);   // dwFirstChance follows the 80-byte EXCEPTION_RECORD
            if (firstChance != 0)
            {
                var ctx = GetCtx(hThread);
                ReportStop(ctx, $"⚠ {ExceptionName(exCode)} (0x{exCode:X8}) at 0x{exAddr:X8}");
                _resume.WaitOne();
                if (_act == Act.Terminate) { Native.TerminateProcess(_hProcess, 0); return Native.DBG_CONTINUE; }
            }
        }
        return Native.DBG_EXCEPTION_NOT_HANDLED;   // let the app's handler run (likely terminates)
    }

    /// <summary>The injected pause breakpoint arrived (on a throwaway OS thread). Pick a thread that's
    /// actually in Clarion code and stop there. The whole process is frozen while we hold this event,
    /// so every thread's context is stable to read.</summary>
    uint HandlePause(uint breakTid)
    {
        uint tid = PickPauseThread(breakTid);
        var hThread = _threads.TryGetValue(tid, out var h) ? h : _hThread;
        _stoppedTid = tid;
        var ctx = GetCtx(hThread);
        return Stop(ref ctx, hThread, 0, "paused");
    }

    /// <summary>Prefer a thread whose EIP is in debuggable Clarion code; else the first readable
    /// thread; else the thread the break landed on.</summary>
    uint PickPauseThread(uint breakTid)
    {
        uint fallback = 0;
        foreach (var kv in _threads)
        {
            if (kv.Key == breakTid) continue;
            Native.CONTEXT c;
            try { c = GetCtx(kv.Value); } catch { continue; }
            if (fallback == 0) fallback = kv.Key;
            if (IsCode(c.Eip)) return kv.Key;
        }
        return fallback != 0 ? fallback : breakTid;
    }

    public bool BreakOnException { get; set; } = true;

    static bool IsFatalException(uint code) => code is
        0xC0000005 or  // access violation (GPF)
        0xC000001D or  // illegal instruction
        0xC0000096 or  // privileged instruction
        0xC0000094 or  // integer divide by zero
        0xC0000095 or  // integer overflow
        0xC00000FD or  // stack overflow
        0xC0000091 or  // float divide by zero
        0xC0000006;    // in-page error

    static string ExceptionName(uint code) => code switch
    {
        0xC0000005 => "Access violation (GPF)",
        0xC000001D => "Illegal instruction",
        0xC0000096 => "Privileged instruction",
        0xC0000094 => "Integer divide by zero",
        0xC0000095 => "Integer overflow",
        0xC00000FD => "Stack overflow",
        0xC0000091 => "Float divide by zero",
        0xC0000006 => "In-page error",
        _ => "Exception"
    };

    /// <summary>Report the stop to the UI, wait for the next action, and set up the resume.</summary>
    uint Stop(ref Native.CONTEXT ctx, IntPtr hThread, uint userBpAddr, string? reason = null)
    {
        _stepping = StepKind.None;
        _pauseRequested = false;   // any stop consumes a pending pause (a breakpoint may have fired first)
        ReportStop(ctx, reason ?? (userBpAddr != 0 ? "breakpoint" : "step"));
        _resume.WaitOne();
        if (_act == Act.Terminate) { Native.TerminateProcess(_hProcess, 0); return Native.DBG_CONTINUE; }

        ctx = GetCtx(hThread);
        (_stepLo, _stepHi) = ProcRangeAbs(ctx.Eip);   // absolute VA range of the current procedure
        _stepEbp = ctx.Ebp; _stepGuard = 0;
        var l = LocateAt(ctx.Eip); _stepModule = l?.Module; _stepLine = l?.Line ?? -1;

        bool needReArm = userBpAddr != 0;
        if (needReArm) _reArm = userBpAddr;

        if (_pendingTemp is uint tmp) { SetTempBp(tmp, false); _pendingTemp = null; }   // run-to-cursor target

        switch (_act)
        {
            case Act.Into: _stepping = StepKind.Into; Trap(ref ctx, hThread); break;
            case Act.Over: _stepping = StepKind.Over; Trap(ref ctx, hThread); break;
            case Act.Out:
                uint ret = ReadDword(ctx.Ebp + 4);
                if (ret != 0 && IsCode(ret)) SetTempBp(ret, false);
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
        uint eip = ctx.Eip;
        bool inText = IsCode(eip);
        bool inProc = inText && eip >= _stepLo && eip < _stepHi;
        var l = inText ? LocateAt(eip) : null;
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
            // stepped into runtime / a non-debug DLL — run to return rather than single-step it
            uint ret = ReadDword(ctx.Esp);
            if (ret != 0 && IsCode(ret)) { SetTempBp(ret, true); return Native.DBG_CONTINUE; }
            Trap(ref ctx, hThread); return Native.DBG_CONTINUE;
        }
        if (inText && newLine) return Stop(ref ctx, hThread, 0);
        Trap(ref ctx, hThread);
        return Native.DBG_CONTINUE;
    }

    // _stepLo/_stepHi are absolute VAs, so a return address in another module compares correctly.
    bool RetInProc(uint ret) => ret != 0 && IsCode(ret) && ret >= _stepLo && ret < _stepHi;

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

    /// <summary>Add/remove/toggle a breakpoint on a live process (safe while running or stopped).</summary>
    public void AddBreakpointLive(Breakpoint bp)
    { lock (_bpLock) if (_hProcess != IntPtr.Zero && bp.Enabled) Arm(bp); }

    public void RemoveBreakpointLive(Breakpoint bp)
    { lock (_bpLock) if (_hProcess != IntPtr.Zero) Disarm(bp); }

    public void SetBreakpointEnabled(Breakpoint bp, bool enabled)
    {
        bp.Enabled = enabled;
        lock (_bpLock) { if (_hProcess == IntPtr.Zero) return; if (enabled) Arm(bp); else Disarm(bp); }
    }

    /// <summary>Run until execution reaches a source line (one-shot), then stop.</summary>
    public void RunTo(string module, int line)
    {
        if (ResolveLineAbs(module, line) is uint va) _pendingTemp = va;
        Continue();
    }

    uint _stoppedTid;

    void ReportStop(Native.CONTEXT ctx, string reason)
    {
        var loc = LocateAt(ctx.Eip);
        var stack = WalkStack(ctx);

        var globals = new List<VarValue>();
        foreach (var (m, g) in StopGlobals(ctx.Eip))
            globals.Add(ReadVar(g.Name, m.LoadBase + g.Rva, g.Type, g.DisplaySize, g.Threaded));

        Stopped?.Invoke(new StopInfo(ctx.Eip, loc?.Module, loc?.Line, stack, globals,
                                     stack[0].Locals, BuildThreads(), _stoppedTid, reason));
    }

    /// <summary>EBP call-stack walk for a thread context; each frame carries its own locals.</summary>
    List<Frame> WalkStack(Native.CONTEXT ctx)
    {
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
        return stack;
    }

    List<ThreadRef> BuildThreads()
    {
        var list = new List<ThreadRef>();
        foreach (var kv in _threads)
        {
            Native.CONTEXT c;
            try { c = GetCtx(kv.Value); } catch { continue; }
            var m = ModuleAt(c.Eip);
            string where = m?.IsDebuggableCode(c.Eip) == true
                ? (m.Info!.ProcContaining(c.Eip - m.LoadBase)?.Name ?? $"0x{c.Eip:X8}")
                : $"[runtime] 0x{c.Eip:X8}";
            string mark = kv.Key == _stoppedTid ? "►" : "  ";
            list.Add(new ThreadRef(kv.Key, $"{mark} Thread {kv.Key}   {where}"));
        }
        return list.OrderByDescending(t => t.Tid == _stoppedTid).ThenBy(t => t.Tid).ToList();
    }

    /// <summary>Rebuild the call stack for another thread (valid while stopped — all threads are suspended).</summary>
    public IReadOnlyList<Frame> SwitchThread(uint tid)
    {
        if (_hProcess == IntPtr.Zero || !_threads.TryGetValue(tid, out var h)) return Array.Empty<Frame>();
        try { return WalkStack(GetCtx(h)); } catch { return Array.Empty<Frame>(); }
    }

    // ---- conditional / hit-count / tracepoint evaluation ----

    bool CondOk(Breakpoint bp, Native.CONTEXT ctx)
    {
        if (string.IsNullOrWhiteSpace(bp.Condition)) return true;
        try { return Expr.EvalBool(bp.Condition!, name => ResolveVar(name, ctx)); }
        catch { return true; }   // a malformed condition shouldn't swallow the breakpoint
    }

    static bool HitOk(Breakpoint bp)
    {
        var h = bp.HitCondition?.Trim();
        if (string.IsNullOrEmpty(h)) return true;
        int n;
        if (h.StartsWith("%")  && int.TryParse(h[1..], out n) && n > 0) return bp.HitCount % n == 0;
        if (h.StartsWith(">=") && int.TryParse(h[2..], out n))          return bp.HitCount >= n;
        if (h.StartsWith("=")  && int.TryParse(h[1..], out n))          return bp.HitCount == n;
        if (int.TryParse(h, out n))                                     return bp.HitCount >= n;
        return true;
    }

    string FormatTrace(Breakpoint bp, Native.CONTEXT ctx)
    {
        string msg = System.Text.RegularExpressions.Regex.Replace(bp.LogMessage!, @"\{([^}]+)\}",
            m => ResolveVar(m.Groups[1].Value.Trim(), ctx) ?? m.Value);
        return $"[trace {bp.Where}#{bp.HitCount}] {msg}";
    }

    /// <summary>Resolve a variable name to its display value, current frame first then globals.</summary>
    string? ResolveVar(string name, Native.CONTEXT ctx)
    {
        var m = ModuleAt(ctx.Eip);
        if (m?.IsDebuggableCode(ctx.Eip) == true && m.Info!.ProcContaining(ctx.Eip - m.LoadBase) is { } proc)
            foreach (var lv in proc.Locals)
                if (string.Equals(lv.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    uint va = lv.IsStatic ? m.LoadBase + lv.Rva : (uint)((long)ctx.Ebp + lv.FrameOffset);
                    int sz = lv.Type.Size > 0 ? lv.Type.Size : lv.DisplaySize;
                    return CleanVal(ReadVar(lv.Name, va, lv.Type, sz, lv.Threaded).Display);
                }
        foreach (var (gm, g) in AllGlobals())
            if (string.Equals(g.Name, name, StringComparison.OrdinalIgnoreCase))
                return CleanVal(ReadVar(g.Name, gm.LoadBase + g.Rva, g.Type, g.DisplaySize, g.Threaded).Display);
        return null;
    }

    static string CleanVal(string d)
    {
        d = d.Trim();
        if (d.Length >= 2 && d[0] == '\'' && d[^1] == '\'') d = d[1..^1].TrimEnd();
        return d;
    }

    // ---- watch expressions (resolved against a specific stack frame, current memory) ----

    /// <summary>Find a variable by name in the given frame's locals, then globals; null if unknown.</summary>
    (uint Va, ClaType Type, int Size, bool Threaded, string Name)? LocateVar(string name, int frameIndex)
    {
        if (frameIndex >= 0 && frameIndex < _liveFrames.Count)
        {
            var (ebp, m, rva) = _liveFrames[frameIndex];
            if (m?.Info != null && m.Pe!.IsCodeRva(rva) && m.Info.ProcContaining(rva) is { } proc)
                foreach (var lv in proc.Locals)
                    if (string.Equals(lv.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        uint va = lv.IsStatic ? m.LoadBase + lv.Rva : (uint)((long)ebp + lv.FrameOffset);
                        int sz = lv.Type.Size > 0 ? lv.Type.Size : lv.DisplaySize;
                        return (va, lv.Type, sz, lv.Threaded, lv.Name);
                    }
        }
        foreach (var (gm, g) in AllGlobals())
            if (string.Equals(g.Name, name, StringComparison.OrdinalIgnoreCase))
                return (gm.LoadBase + g.Rva, g.Type, g.DisplaySize, g.Threaded, g.Name);
        return null;
    }

    string? ResolveName(string name, int frameIndex)
        => LocateMember(name, frameIndex) is { } v ? CleanVal(ReadVar(v.Name, v.Va, v.Type, v.Size, v.Threaded).Display) : null;

    /// <summary>Like <see cref="LocateVar"/> but also resolves into GROUP members: a dotted path
    /// (<c>vGroup.gA</c>, <c>BRW1.Q</c>) or a flat record-field name (<c>STU:LastName</c>) found as a
    /// member of any group-typed global/local. Reference (&amp;QUEUE/&amp;GROUP) deref is not yet decoded.</summary>
    (uint Va, ClaType Type, int Size, bool Threaded, string Name)? LocateMember(string name, int frameIndex)
    {
        if (LocateVar(name, frameIndex) is { } direct) return direct;   // top-level symbol (incl. fields that are standalone)

        // dotted member path: resolve the head, then walk into each group member
        if (name.Contains('.'))
        {
            var parts = name.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length >= 2)
            {
                // ABC convention: BRW<n>.Q is the browse queue. Its reference must be dereferenced
                // (the local is a 4-byte handle) to reach the current element buffer.
                var bm = System.Text.RegularExpressions.Regex.Match(parts[0], @"^BRW(\d+)$",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (bm.Success && parts[1].Equals("Q", StringComparison.OrdinalIgnoreCase))
                    return ResolveBrowseQueue(bm.Groups[1].Value, parts, frameIndex, name);

                // general group member walk (e.g. vGroup.gA, an inline record buffer)
                if (LocateVar(parts[0], frameIndex) is { } head)
                {
                    uint va = head.Va; ClaType type = head.Type; bool threaded = head.Threaded; bool ok = true;
                    for (int i = 1; i < parts.Length; i++)
                    {
                        if (type.Kind != TypeKind.Group || FindField(type, parts[i]) is not { } f) { ok = false; break; }
                        va = (uint)(va + f.Offset); type = f.Type;
                    }
                    if (ok) return (va, type, type.Size > 0 ? type.Size : 4, threaded, name);
                }
            }
        }

        // flat field name: search the members of every group-typed global / current-frame local
        foreach (var (rootVa, rootType, threaded) in GroupRoots(frameIndex))
            if (FindFieldDeep(rootType, rootVa, name) is { } hit)
                return (hit.Va, hit.Type, hit.Type.Size > 0 ? hit.Type.Size : 4, threaded, name);

        return null;
    }

    /// <summary>Resolve BRW&lt;n&gt;.Q[.field…]: dereference the browse-queue handle to the current
    /// element buffer, then index it with the queue's field layout (built on demand).</summary>
    (uint Va, ClaType Type, int Size, bool Threaded, string Name)? ResolveBrowseQueue(
        string n, string[] parts, int frameIndex, string name)
    {
        if (frameIndex < 0 || frameIndex >= _liveFrames.Count) return null;
        var (ebp, m, rva) = _liveFrames[frameIndex];
        if (m?.Info == null) return null;
        var proc = m.Pe!.IsCodeRva(rva) ? m.Info.ProcContaining(rva) : null;
        var q = proc?.Locals.FirstOrDefault(l => l.Name.Equals($"QUEUE:BROWSE:{n}", StringComparison.OrdinalIgnoreCase));
        if (q == null || m.Info.GroupTypeForRef(q.TypeRef, 0) is not { } qtype) return null;

        uint handleVa = q.IsStatic ? m.LoadBase + q.Rva : (uint)((long)ebp + q.FrameOffset);
        uint buf = ReadU32(handleVa);                  // &QUEUE reference → element buffer
        if (buf == 0) return null;

        uint va = buf; ClaType type = qtype;
        for (int i = 2; i < parts.Length; i++)
        {
            if (type.Kind != TypeKind.Group || FindField(type, parts[i]) is not { } f) return null;
            va = (uint)(va + f.Offset); type = f.Type;
        }
        return (va, type, type.Size > 0 ? type.Size : 4, false, name);
    }

    uint ReadU32(uint va) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(ReadBytes(va, 4));

    // match a member name to a wanted field, tolerating the Clarion prefix being present on only
    // one side: "STU:LastName" ↔ "LastName", "gA" ↔ "gA". Exact (incl. prefix) is preferred.
    static string Unprefixed(string s) { int c = s.LastIndexOf(':'); return c >= 0 ? s[(c + 1)..] : s; }
    static bool FieldNameMatch(string member, string want) =>
        string.Equals(member, want, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Unprefixed(member), Unprefixed(want), StringComparison.OrdinalIgnoreCase);

    static ClaType.GroupField? FindField(ClaType g, string seg)
    {
        foreach (var m in g.Members) if (string.Equals(m.Name, seg, StringComparison.OrdinalIgnoreCase)) return m;
        foreach (var m in g.Members) if (FieldNameMatch(m.Name, seg)) return m;
        return null;
    }

    static (uint Va, ClaType Type)? FindFieldDeep(ClaType g, uint baseVa, string name)
    {
        if (g.Kind != TypeKind.Group) return null;
        foreach (var m in g.Members)                                   // exact (with prefix) first
            if (string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase))
                return ((uint)(baseVa + m.Offset), m.Type);
        foreach (var m in g.Members)                                   // then prefix-tolerant
            if (FieldNameMatch(m.Name, name))
                return ((uint)(baseVa + m.Offset), m.Type);
        foreach (var m in g.Members)                                   // then recurse into nested groups
            if (m.Type.Kind == TypeKind.Group && FindFieldDeep(m.Type, (uint)(baseVa + m.Offset), name) is { } hit)
                return hit;
        return null;
    }

    IEnumerable<(uint Va, ClaType Type, bool Threaded)> GroupRoots(int frameIndex)
    {
        // globals first: a flat field name like STU:LastName means the file-record buffer, not a
        // local queue copy of the same field.
        foreach (var (gm, gl) in AllGlobals())
            if (gl.Type.Kind == TypeKind.Group)
                yield return (gm.LoadBase + gl.Rva, gl.Type, gl.Threaded);

        if (frameIndex >= 0 && frameIndex < _liveFrames.Count)
        {
            var (ebp, m, rva) = _liveFrames[frameIndex];
            if (m?.Info != null && m.Pe!.IsCodeRva(rva) && m.Info.ProcContaining(rva) is { } proc)
                foreach (var lv in proc.Locals)
                    if (lv.Type.Kind == TypeKind.Group)
                        yield return (lv.IsStatic ? m.LoadBase + lv.Rva : (uint)((long)ebp + lv.FrameOffset), lv.Type, lv.Threaded);
        }
    }

    /// <summary>Evaluate a watch expression (a variable name, or a comparison like "count &gt; 5")
    /// against a stack frame using current process memory. Returns null while not stopped.</summary>
    public VarValue? EvalWatch(string expr, int frameIndex)
    {
        if (_hProcess == IntPtr.Zero) return null;
        expr = (expr ?? "").Trim();
        if (expr.Length == 0) return null;

        if (HasCompare(expr))   // boolean expression → show true/false
        {
            try
            {
                bool r = Expr.EvalBool(expr, n => ResolveName(n, frameIndex));
                return new VarValue(expr, 0, "BOOL", r ? "true" : "false", $"{expr}  →  {r}", 0, WriteKind.Raw);
            }
            catch { return new VarValue(expr, 0, "", "<error>", "could not evaluate expression", 0, WriteKind.Raw); }
        }

        if (LocateMember(expr, frameIndex) is { } v)
            return ReadVar(v.Name, v.Va, v.Type, v.Size, v.Threaded) with { Name = expr };
        return new VarValue(expr, 0, "", "<not found>", "no local or global named '" + expr + "'", 0, WriteKind.Raw);
    }

    static bool HasCompare(string s)
    {
        bool inStr = false;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\'') { inStr = !inStr; continue; }
            if (!inStr && (s[i] == '<' || s[i] == '>' || s[i] == '=' || (s[i] == '!' && i + 1 < s.Length && s[i + 1] == '='))) return true;
        }
        return false;
    }

    readonly List<(uint Ebp, LoadedModule? Mod, uint Rva)> _liveFrames = new();   // for live re-reading while running

    Frame MakeFrame(uint addr, uint frameEbp)
    {
        var m = ModuleAt(addr);
        uint rva = m != null ? addr - m.LoadBase : addr;
        bool code = m?.IsDebuggableCode(addr) ?? false;
        var l = code ? m!.Info!.Locate(rva) : null;
        _liveFrames.Add((frameEbp, m, rva));
        return new Frame(FrameLabel(m, addr), addr, l?.Module, l?.Line, ReadProcLocals(frameEbp, m, rva));
    }

    List<VarValue> ReadProcLocals(uint frameEbp, LoadedModule? m, uint rva)
    {
        var locals = new List<VarValue>();
        if (m?.Info == null || !m.Pe!.IsCodeRva(rva)) return locals;
        var proc = m.Info.ProcContaining(rva);
        if (proc != null)
            foreach (var lv in proc.Locals)
            {
                uint va = lv.IsStatic ? m.LoadBase + lv.Rva : (uint)((long)frameEbp + lv.FrameOffset);
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
        var (ebp, m, rva) = _liveFrames[frameIndex];
        return ReadProcLocals(ebp, m, rva);
    }

    public IReadOnlyList<VarValue> RereadGlobals()
    {
        if (_hProcess == IntPtr.Zero) return Array.Empty<VarValue>();
        uint eip = _stoppedTid != 0 && _threads.TryGetValue(_stoppedTid, out var h) ? GetCtx(h).Eip : 0;
        var list = new List<VarValue>();
        foreach (var (m, g) in StopGlobals(eip))
            list.Add(ReadVar(g.Name, m.LoadBase + g.Rva, g.Type, g.DisplaySize, g.Threaded));
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
        if (threaded) { disp = "[tls] " + disp; full = "(thread-local; template value — right-click ‘Resolve on current thread’ for the live instance)\n" + full; }
        string tn = type.Kind == TypeKind.Unknown ? InferType(kind, n) : type.Describe();
        return new VarValue(name, va, tn, disp, full, n, kind) { Threaded = threaded };
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

    string FrameLabel(LoadedModule? m, uint absAddr)
    {
        if (m?.Info == null || !m.IsDebuggableCode(absAddr)) return $"[runtime]  0x{absAddr:X8}";
        var p = m.Info.ProcContaining(absAddr - m.LoadBase);
        return p != null ? p.Name : $"0x{absAddr:X8}";
    }

    /// <summary>Read and format a value at an address as an untyped field (for the array viewer).</summary>
    public VarValue ReadValueAt(string name, uint addr, int size)
        => ReadVar(name, addr, new ClaType { Kind = TypeKind.Unknown }, size);

    /// <summary>Read a block of process memory (for the hex/memory view). Empty if not running.</summary>
    public byte[] ReadMemory(uint addr, int len)
        => _hProcess == IntPtr.Zero || len <= 0 ? Array.Empty<byte>() : ReadBytes(addr, Math.Clamp(len, 1, 1 << 20));

    public record DisasmLine(uint Addr, string Bytes, string Text, string? Source);

    /// <summary>Disassemble <paramref name="count"/> x86 instructions starting at <paramref name="addr"/>,
    /// annotating each with its source line where known.</summary>
    public IReadOnlyList<DisasmLine> Disassemble(uint addr, int count)
    {
        var lines = new List<DisasmLine>();
        if (_hProcess == IntPtr.Zero || count <= 0) return lines;
        var code = ReadBytes(addr, Math.Clamp(count * 8 + 16, 16, 4096));   // ~8 bytes/insn upper bound
        var reader = new Iced.Intel.ByteArrayCodeReader(code);
        var decoder = Iced.Intel.Decoder.Create(32, reader);
        decoder.IP = addr;
        var formatter = new Iced.Intel.NasmFormatter();
        var output = new Iced.Intel.StringOutput();
        string? lastSrc = null;
        for (int i = 0; i < count && reader.CanReadByte; i++)
        {
            var insn = decoder.Decode();
            if (insn.IsInvalid) break;
            uint ip = (uint)insn.IP;
            output.Reset(); formatter.Format(insn, output);
            int len = insn.Length;
            int off = (int)(ip - addr);
            string bytes = off >= 0 && off + len <= code.Length
                ? BitConverter.ToString(code, off, len).Replace("-", " ") : "";
            // source annotation: only when the line changes (mirrors how the source view groups bytes)
            string? src = null;
            var loc = LocateAt(ip);
            if (loc is { } l) { var tag = $"{l.Module}:{l.Line}"; if (tag != lastSrc) { src = tag; lastSrc = tag; } }
            lines.Add(new DisasmLine(ip, bytes, output.ToStringAndReset(), src));
        }
        return lines;
    }

    public uint CurrentEip => _stoppedTid != 0 && _threads.TryGetValue(_stoppedTid, out var h)
        ? GetCtx(h).Eip : 0;

    /// <summary>Move the instruction pointer to another line in the current procedure (set-next-statement).
    /// Only safe within the same procedure (the frame/locals stay valid). Refreshes the UI at the new line.</summary>
    public bool SetNextStatement(string module, int line)
    {
        if (_hProcess == IntPtr.Zero) return false;
        if (ResolveLineAbs(module, line) is not uint va) return false;
        if (!_threads.TryGetValue(_stoppedTid, out var h)) return false;
        var ctx = GetCtx(h);
        ctx.Eip = va;
        if (!Native.SetThreadContext(h, ref ctx)) return false;
        ReportStop(ctx, "set next statement");   // re-report so the UI moves the current line + re-reads
        return true;
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
