using System.Buffers.Binary;

namespace ClarionDbg.Engine;

// Multi-DLL support: the module table and everything that resolves a live address through the
// owning image. The EXE is module 0; every loaded DLL is added on LOAD_DLL_DEBUG_EVENT, its own
// TSWD parsed off disk, and any breakpoints it owns are armed (deferred breakpoints). All VA math
// elsewhere in DebugSession goes through ModuleAt / the helpers here rather than a single base.
public sealed partial class DebugSession
{
    // _modules is authoritative (mutated only under _modLock on the worker thread); _mods is an
    // immutable snapshot read lock-free from any thread. Swapping the snapshot reference is atomic,
    // so readers always see a consistent, fully-initialised module set.
    readonly List<LoadedModule> _modules = new();
    volatile LoadedModule[] _mods = Array.Empty<LoadedModule>();
    readonly object _modLock = new();
    LoadedModule _exe = null!;   // module 0, set in the constructor

    void RebuildModSnapshot() => _mods = _modules.ToArray();   // call under _modLock

    /// <summary>Pre-register a sibling DLL (e.g. a solution's runtime DLLs) before launch so its
    /// module:line breakpoints resolve immediately when it maps. Best-effort; safe to call before
    /// Start. The live base is filled in at LOAD_DLL.</summary>
    public void PreloadModule(string dllPath)
    {
        if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath)) return;
        string name = Path.GetFileName(dllPath).ToLowerInvariant();
        lock (_modLock)
        {
            foreach (var m in _modules) if (m.Name == name) return;   // already known
            var pe = PeImage.TryLoad(dllPath);
            var info = pe != null ? TswdInfo.Load(pe) : null;
            var mod = new LoadedModule
            {
                Path = dllPath, Name = name, Pe = pe, Info = info,
                Size = pe?.SizeOfImage ?? 0, Preloaded = true,
            };
            mod.ResolveThreadedInfo();
            _modules.Add(mod);
            RebuildModSnapshot();
        }
    }

    /// <summary>The currently mapped modules (EXE first), for the UI's module/source switching.</summary>
    public IReadOnlyList<LoadedModule> Modules => _mods;

    // ---------------------------------------------------------------- address → module resolution

    /// <summary>The mapped module whose [LoadBase, LoadBase+Size) contains <paramref name="va"/>, or null.</summary>
    LoadedModule? ModuleAt(uint va)
    {
        foreach (var m in _mods) if (m.ContainsVa(va)) return m;
        return null;
    }

    LoadedModule? _runtimeModule;   // cached: the Clarion RTL image (ClaRUN.dll), found by export presence

    /// <summary>The loaded Clarion runtime module (ClaRUN.dll), identified by the presence of the
    /// <c>Cla$EVENT</c> export rather than by file name (version/rename proof). Used by Library State,
    /// which reads per-thread RTL values by calling the runtime's <c>Cla$*</c> getter exports.
    /// <para>Returns null when the app is <b>locally linked</b> — the RTL is baked into the EXE and no
    /// clarun.dll maps — in which case Library State is unavailable and callers should report that.</para>
    /// Resolved once and cached; the runtime image does not unload during a session.</summary>
    LoadedModule? RuntimeModule()
    {
        var cached = _runtimeModule;
        if (cached != null && cached.LoadBase != 0 && Array.IndexOf(_mods, cached) >= 0)
            return cached;
        foreach (var m in _mods)
            if (m.LoadBase != 0 && m.Pe != null && m.Pe.FindExportRva("Cla$EVENT") != 0)
                return _runtimeModule = m;
        return _runtimeModule = null;
    }

    /// <summary>True if a Clarion runtime DLL (ClaRUN.dll) is mapped — i.e. Library State can run.
    /// False for a locally-linked EXE. Call while the debuggee is loaded/stopped.</summary>
    public bool HasClarionRuntime => RuntimeModule() != null;

    /// <summary>True if <paramref name="va"/> is Clarion code we can resolve and single-step
    /// (in a debug module's .text). Non-debug DLLs and the runtime return false so stepping runs
    /// them at full speed — this matches the old EXE-only <c>_pe.IsCodeRva</c> semantics.</summary>
    bool IsCode(uint va) => ModuleAt(va)?.IsDebuggableCode(va) ?? false;

    /// <summary>Resolve an absolute code VA to (module, line) via the owning image's TSWD; null if
    /// no mapped debug module owns it.</summary>
    (string Module, int Line)? LocateAt(uint va)
    {
        var m = ModuleAt(va);
        if (m?.Info == null || !m.Pe!.IsCodeRva(va - m.LoadBase)) return null;
        return m.Info.Locate(va - m.LoadBase);
    }

    /// <summary>Absolute VA range [entry, nextEntry) of the procedure containing <paramref name="va"/>.
    /// Returns (0,0) — an empty range — when no debug procedure owns it.</summary>
    (uint Lo, uint Hi) ProcRangeAbs(uint va)
    {
        var m = ModuleAt(va);
        if (m?.Info == null || !m.Pe!.IsCodeRva(va - m.LoadBase)) return (0, 0);
        var (lo, hi) = m.Info.ProcRange(va - m.LoadBase);
        uint absLo = m.LoadBase + lo;
        uint absHi = hi == uint.MaxValue ? uint.MaxValue : m.LoadBase + hi;
        return (absLo, absHi);
    }

    /// <summary>Every global across all mapped debug modules, EXE first (so a flat field name binds
    /// to the program's buffer before a DLL's same-named one). Used for name-based watch/condition
    /// resolution — searches the whole process.</summary>
    IEnumerable<(LoadedModule M, TswdSymbol G)> AllGlobals()
    {
        if (_exe.Info != null && _exe.LoadBase != 0)
            foreach (var g in _exe.Info.Globals) yield return (_exe, g);
        foreach (var m in _mods)
        {
            if (m == _exe || m.Info == null || m.LoadBase == 0) continue;
            foreach (var g in m.Info.Globals) yield return (m, g);
        }
    }

    /// <summary>Globals to display in the variables panel for a stop at <paramref name="eip"/>: the
    /// program's own globals, plus the globals of the module currently executing if that's a debug
    /// DLL. (We don't dump every loaded module's globals — that floods the panel with runtime
    /// internals from ClaRUN and the like.)</summary>
    IEnumerable<(LoadedModule M, TswdSymbol G)> StopGlobals(uint eip)
    {
        if (_exe.Info != null && _exe.LoadBase != 0)
            foreach (var g in _exe.Info.Globals) yield return (_exe, g);
        var m = ModuleAt(eip);
        if (m != null && m != _exe && m.Info != null)
            foreach (var g in m.Info.Globals) yield return (m, g);
    }

    /// <summary>Resolve a module:line to an absolute VA, preferring the module the program is
    /// currently stopped in, then any mapped debug module.</summary>
    uint? ResolveLineAbs(string? module, int line)
    {
        var cur = _stoppedTid != 0 && _threads.TryGetValue(_stoppedTid, out var h) ? ModuleAt(GetCtx(h).Eip) : null;
        if (cur?.Info != null && cur.LoadBase != 0 && LineInImage(cur.Info, module, line) is uint r0)
            return cur.LoadBase + r0;
        foreach (var m in _mods)
            if (m.Info != null && m.LoadBase != 0 && LineInImage(m.Info, module, line) is uint r)
                return m.LoadBase + r;
        return null;
    }

    // When a module name is given, resolve strictly within that compiland of THIS blob so a
    // same-numbered line in another image can't match; otherwise fall back to any module.
    static uint? LineInImage(TswdInfo info, string? module, int line)
        => module != null ? info.LineToRvaStrict(line, module) : info.LineToRva(line, null);

    /// <summary>Resolve a breakpoint to its owning mapped module + absolute VA, or null if pending
    /// (the owning image isn't loaded yet). An RVA-only breakpoint (proc entry) belongs to the EXE.</summary>
    (LoadedModule M, uint Va)? ResolveBp(Breakpoint bp)
    {
        if (bp.Rva != 0)
            return _exe.LoadBase != 0 ? (_exe, _exe.LoadBase + bp.Rva) : null;
        foreach (var m in _mods)
            if (m.Info != null && m.LoadBase != 0 && LineInImage(m.Info, bp.Module, bp.Line) is uint r)
                return (m, m.LoadBase + r);
        return null;
    }

    // ---------------------------------------------------------------- DLL load / unload

    void SetExeBase(uint baseVa)
    {
        lock (_modLock) { _exe.LoadBase = baseVa; RebuildModSnapshot(); }
    }

    /// <summary>A DLL mapped into the target: resolve its on-disk path from the file handle, parse
    /// its own PE + TSWD, record its live base/size, and arm any breakpoints it owns. Non-debug DLLs
    /// are still registered (base+size) for correct address attribution; the handle is always closed.</summary>
    void OnDllLoaded(IntPtr hFile, uint baseVa)
    {
        try
        {
            string? path = GetPathFromHandle(hFile);
            string name = !string.IsNullOrEmpty(path) ? Path.GetFileName(path)!.ToLowerInvariant() : $"(0x{baseVa:x8})";

            LoadedModule m;
            lock (_modLock)
            {
                // reuse a pre-registered (solution) entry with this name if one is waiting for its base
                m = _modules.FirstOrDefault(im => im.LoadBase == 0 && im.Name == name)!;
                if (m != null)
                {
                    m.LoadBase = baseVa;
                    if (m.Path == null && path != null) m.Path = path;
                }
                else
                {
                    var pe = path != null ? PeImage.TryLoad(path) : null;
                    var info = pe != null ? TswdInfo.Load(pe) : null;
                    m = new LoadedModule
                    {
                        Path = path, Name = name, Pe = pe, Info = info, LoadBase = baseVa,
                        Size = pe?.SizeOfImage ?? ReadRemoteSizeOfImage(baseVa),
                    };
                    m.ResolveThreadedInfo();
                    _modules.Add(m);
                }
                if (m.Size == 0) m.Size = ReadRemoteSizeOfImage(baseVa);
                RebuildModSnapshot();
            }

            if (m.HasDebug) Log?.Invoke($"DLL loaded: {m.Name} @ 0x{baseVa:X8} (debug info present).");
            ArmPendingForModule(m);
        }
        catch { /* a malformed/unreadable DLL must not break the debug loop */ }
        finally
        {
            if (hFile != IntPtr.Zero) Native.CloseHandle(hFile);
        }
    }

    /// <summary>A DLL unmapped: drop the breakpoints it owned (back to pending so they re-arm if it
    /// reloads) and forget its address range. Pre-registered solution entries are kept (base cleared);
    /// runtime-discovered modules are removed so the table doesn't grow across load/unload churn.</summary>
    void OnDllUnloaded(uint baseVa)
    {
        LoadedModule? m;
        lock (_modLock)
        {
            m = _modules.FirstOrDefault(im => im.LoadBase == baseVa && im != _exe);
            if (m == null) return;
        }

        DisarmModule(m);

        lock (_modLock)
        {
            if (m.Preloaded) m.LoadBase = 0;   // keep parsed Pe/Info; re-arms on reload
            else _modules.Remove(m);
            RebuildModSnapshot();
        }
    }

    static string? GetPathFromHandle(IntPtr hFile)
    {
        if (hFile == IntPtr.Zero) return null;
        var sb = new System.Text.StringBuilder(512);
        uint n = Native.GetFinalPathNameByHandle(hFile, sb, (uint)sb.Capacity, 0);
        if (n == 0 || n >= sb.Capacity) return null;
        string s = sb.ToString();
        return s.StartsWith(@"\\?\", StringComparison.Ordinal) ? s[4..] : s;   // strip the \\?\ prefix
    }

    /// <summary>Read SizeOfImage from the target's mapped PE header — fallback when the DLL file is
    /// unavailable — so address attribution still has a valid span.</summary>
    uint ReadRemoteSizeOfImage(uint baseVa)
    {
        try
        {
            uint lfanew = ReadDword(baseVa + 0x3C);
            if (lfanew == 0 || lfanew > 0x1000) return 0x10000;   // sane floor if the header looks odd
            uint size = ReadDword(baseVa + lfanew + 24 + 56);     // NT sig(4)+file hdr(20)=24, SizeOfImage @ opt+56
            return size != 0 ? size : 0x10000;
        }
        catch { return 0x10000; }
    }

    // ---------------------------------------------------------------- breakpoint arming (module-aware)

    void ArmBreakpoints()
    {
        lock (_bpLock)
            foreach (var bp in RequestedBreaks)
                if (bp.Enabled) Arm(bp);
    }

    /// <summary>Arm any pending breakpoints whose owning compiland this freshly-mapped module carries.</summary>
    void ArmPendingForModule(LoadedModule m)
    {
        lock (_bpLock)
            foreach (var bp in _logical.ToList())
                if (bp.Enabled && !_armedAt.ContainsKey(bp) && ResolveBp(bp) is { } hit && hit.M == m)
                    PlantAt(bp, hit.Va);
    }

    /// <summary>Disarm every breakpoint planted in <paramref name="m"/> (the module is unmapping, so
    /// no memory write is needed) and return them to pending.</summary>
    void DisarmModule(LoadedModule m)
    {
        lock (_bpLock)
        {
            foreach (var bp in _armedAt.Where(kv => m.ContainsVa(kv.Value)).Select(kv => kv.Key).ToList())
                _armedAt.Remove(bp);
            foreach (var va in _breakpoints.Keys.Where(m.ContainsVa).ToList())
            {
                _breakpoints.Remove(va);
                _bpByVa.Remove(va);
            }
        }
    }

    /// <summary>Register a logical breakpoint and plant it if its owning module is mapped; otherwise
    /// hold it pending. Caller holds _bpLock.</summary>
    void Arm(Breakpoint bp)
    {
        if (!_logical.Contains(bp)) _logical.Add(bp);
        if (_armedAt.ContainsKey(bp)) return;                 // already planted
        if (ResolveBp(bp) is not { } hit)
        {
            Log?.Invoke($"Breakpoint pending (module not loaded): {bp.Where}.");
            return;
        }
        PlantAt(bp, hit.Va);
    }

    /// <summary>Write the 0xCC for a breakpoint at a resolved VA. Caller holds _bpLock.</summary>
    void PlantAt(Breakpoint bp, uint va)
    {
        _bpByVa[va] = bp;
        _armedAt[bp] = va;
        if (!_breakpoints.ContainsKey(va)) { _breakpoints[va] = ReadByte(va); WriteByte(va, 0xCC); }
        Log?.Invoke($"Breakpoint armed: {bp.Where} @ 0x{va:X8}");
    }

    /// <summary>Restore the original byte and unregister a breakpoint. Caller holds _bpLock.</summary>
    void Disarm(Breakpoint bp)
    {
        _logical.Remove(bp);
        if (!_armedAt.TryGetValue(bp, out var va)) return;
        _armedAt.Remove(bp);
        if (_armedAt.ContainsValue(va)) { _bpByVa[va] = _armedAt.First(kv => kv.Value == va).Key; return; }   // another bp shares this VA
        if (_breakpoints.TryGetValue(va, out var orig)) { WriteByte(va, orig); _breakpoints.Remove(va); }
        _bpByVa.Remove(va);
    }
}
