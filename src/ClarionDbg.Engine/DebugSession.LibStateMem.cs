using System.Buffers.Binary;

namespace ClarionDbg.Engine;

// Library State, the SAFE way: read the runtime's per-thread state directly from memory instead of
// CALLING the Cla$* getters. Calling them re-enters the RTL's thread-instance machinery, which corrupts
// state when the thread is parked inside the ACCEPT/TakeEvent loop and crashes the app (0x6BEF5E4C) —
// confirmed against school.exe and reproduced by CA-Debugger too.
//
// How the getters find their data (reverse-engineered from ClaRUN 11.1, see probe `disasmexport`):
//   instance  = TlsGetValue( *(u32*)(ClaRUN_base + 0x13F12C) )      ; D1FC4: a plain Win32 TLS read
//   THREAD    = *(instance + 0x14) + 1                              ; Cla$THREAD
//   ERRORCODE = (eb=*(instance+0x40)) ? *(eb + 4) : 0               ; Cla$ERRORCODE (eb lazily alloc'd by RTL)
//   EVENT     = *(*(*(*(instance+0x20)+4)+0xB9)) - 0xA000           ; Cla$EVENT (0xA000 = message offset)
//
// We replicate the reads with ReadProcessMemory — NO hijack, NO thread suspend, NO func-eval — so it is
// safe to run while parked anywhere, including mid-TakeEvent, which is exactly where these values matter.
//
// PROTOTYPE: EVENT/THREAD/ERRORCODE only, with offsets hardcoded for ClaRUN 11.1. Version independence
// (deriving the TLS-index global + offsets by disassembling the getters at runtime) is the next step.
public sealed partial class DebugSession
{
    public record LibMemItem(string Name, string Value, bool Resolved);

    /// <summary>Resolve the runtime's per-thread instance pointer for the stopped thread, WITHOUT calling
    /// anything: derive the TLS index from the live code (Cla$THREAD's first `call` → its resolver's
    /// `push dword [global]`, read straight from relocated memory so no preferred-base math is needed),
    /// then read that TLS slot out of the thread's TEB. 0 if it can't be resolved.</summary>
    uint ResolveRtlInstance(LoadedModule rt, uint teb, out string dbg)
    {
        dbg = "";
        uint threadRva = rt.Pe!.FindExportRva("Cla$THREAD");
        if (threadRva == 0) { dbg = "no Cla$THREAD"; return 0; }
        uint threadVa = rt.LoadBase + threadRva;

        // Cla$THREAD begins with `call rel32` (E8) to the resolver.
        var tb = ReadBytes(threadVa, 5);
        if (tb.Length < 5 || tb[0] != 0xE8) { dbg = $"Cla$THREAD not E8 ({tb[0]:X2})"; return 0; }
        uint resolverVa = (uint)(threadVa + 5 + BinaryPrimitives.ReadInt32LittleEndian(tb.AsSpan(1)));

        // The resolver pushes the TLS-index global: find `FF 35 imm32` (push dword [imm32]); imm32 is the
        // already-relocated live address of the global.
        var rb = ReadBytes(resolverVa, 24);
        int p = -1;
        for (int i = 0; i + 6 <= rb.Length; i++)
            if (rb[i] == 0xFF && rb[i + 1] == 0x35) { p = i; break; }
        if (p < 0) { dbg = "no push [global] in resolver"; return 0; }
        uint tlsGlobalVa = BinaryPrimitives.ReadUInt32LittleEndian(rb.AsSpan(p + 2));
        uint tlsIndex = ReadDword(tlsGlobalVa);
        uint inst = ReadTlsSlot(teb, tlsIndex);
        dbg = $"resolver=0x{resolverVa:X} tlsGlobal=0x{tlsGlobalVa:X} idx={tlsIndex} inst=0x{inst:X}";
        return inst;
    }

    /// <summary>Read EVENT/THREAD/ERRORCODE for the stopped thread by walking the runtime's TLS-backed
    /// instance block in memory. No RTL calls — safe at any stop. Returns rows or an explanatory error.</summary>
    public (IReadOnlyList<LibMemItem> Items, string? Error) ReadLibraryStateMem()
    {
        if (_hProcess == IntPtr.Zero) return (Array.Empty<LibMemItem>(), "No running process.");
        var rt = RuntimeModule();
        if (rt == null) return (Array.Empty<LibMemItem>(), "No Clarion runtime DLL (locally linked build?).");
        if (_stoppedTid == 0 || !_threads.TryGetValue(_stoppedTid, out var hThread))
            return (Array.Empty<LibMemItem>(), "No stopped thread.");

        uint teb = GetTebBase(hThread);
        if (teb == 0) return (Array.Empty<LibMemItem>(), "Could not resolve the thread's TEB.");
        uint inst = ResolveRtlInstance(rt, teb, out _);

        var items = new List<LibMemItem>();
        if (inst == 0)
        {
            foreach (var n in new[] { "EVENT", "THREAD", "ERRORCODE" })
                items.Add(new(n, "<no thread instance>", false));
            return (items, null);
        }

        // EVENT = *(*(*(*(inst+0x20)+4)+0xB9)) - 0xA000, null-safe at each hop
        uint a = ReadDword(inst + 0x20);
        uint b = a == 0 ? 0 : ReadDword(a + 4);
        uint c = b == 0 ? 0 : ReadDword(b + 0xB9);
        uint rawEv = c == 0 ? 0 : ReadDword(c);
        int ev = rawEv == 0 ? 0 : (int)(rawEv - 0xA000);
        string evStr = ev.ToString();
        if (ev != 0 && ClarionEvents.Name((uint)ev) is { } nm) evStr += $"  ({nm})";
        items.Add(new("EVENT", evStr, true));

        // THREAD = [inst+0x14] + 1
        items.Add(new("THREAD", ((int)(ReadDword(inst + 0x14) + 1)).ToString(), true));

        // ERRORCODE = [[inst+0x40]+4]; the error sub-block is null until an error occurs (= 0). Do NOT
        // allocate it (the getter would, via the RTL — we must stay read-only).
        uint errBlk = ReadDword(inst + 0x40);
        items.Add(new("ERRORCODE", errBlk == 0 ? "0" : ((int)ReadDword(errBlk + 4)).ToString(), true));

        return (items, null);
    }

    /// <summary>Read the full Library State by EMULATING every getter (read-only, no RTL re-entrancy) —
    /// safe at any stop, including inside TakeEvent. Numerics/strings come from the emulator; TODAY/CLOCK
    /// are computed from the host clock (same machine as the debuggee). EVENT is annotated with its name.</summary>
    public (IReadOnlyList<LibStateItem> Items, string? Error) ReadLibraryStateEmu()
    {
        if (_hProcess == IntPtr.Zero) return (Array.Empty<LibStateItem>(), "No running process.");
        var rt = RuntimeModule();
        if (rt == null) return (Array.Empty<LibStateItem>(), "No Clarion runtime DLL (locally linked build?).");
        if (_stoppedTid == 0 || !_threads.TryGetValue(_stoppedTid, out var hThread))
            return (Array.Empty<LibStateItem>(), "No stopped thread.");
        uint teb = GetTebBase(hThread);
        if (teb == 0) return (Array.Empty<LibStateItem>(), "Could not resolve the thread's TEB.");

        var emu = BuildEmulator(rt, teb);
        var rows = new List<LibStateItem>();
        foreach (var g in Getters)
        {
            uint baseRva = rt.Pe!.FindExportRva(g.Export);
            string value; bool ok = true;
            try
            {
                if (g.Kind == LibKind.Date) value = ClarionDate(DateTime.Today);
                else if (g.Kind == LibKind.Time) value = ClarionClock(DateTime.Now);
                else if (baseRva == 0) { value = "<unavailable>"; ok = false; }
                else if (g.Kind == LibKind.Str)
                {
                    uint p = emu.Call(rt.LoadBase + baseRva);
                    value = emu.ReadCStringResult(p, 512);
                }
                else
                {
                    uint v = emu.Call(rt.LoadBase + baseRva);
                    value = g.Kind == LibKind.Unsigned ? v.ToString() : ((int)v).ToString();
                    if (g.Name == "EVENT" && v != 0 && ClarionEvents.Name(v) is { } nm) value = $"{value}  ({nm})";
                }
            }
            catch (RtlEmulator.NotSupported) { value = "<unavailable>"; ok = false; }
            rows.Add(new(g.Group, g.Name, value, g.Kind, ok));
        }
        return (rows, null);
    }

    static string ClarionDate(DateTime d) =>
        ((int)(d.Date - new DateTime(1800, 12, 28)).TotalDays).ToString();
    static string ClarionClock(DateTime t) =>
        ((int)(t.TimeOfDay.TotalMilliseconds / 10) + 1).ToString();

    /// <summary>Emulate a single getter export and return its value (or null if the emulator hit something
    /// unsupported). Pure read-only emulation — never runs code or writes memory in the debuggee.</summary>
    public uint? EmulateGetter(string export)
    {
        if (_hProcess == IntPtr.Zero) return null;
        var rt = RuntimeModule();
        if (rt == null || _stoppedTid == 0 || !_threads.TryGetValue(_stoppedTid, out var hThread)) return null;
        uint rva = rt.Pe!.FindExportRva(export);
        if (rva == 0) return null;
        uint teb = GetTebBase(hThread);
        if (teb == 0) return null;
        try { return BuildEmulator(rt, teb).Call(rt.LoadBase + rva); }
        catch (RtlEmulator.NotSupported) { return null; }
    }

    /// <summary>Emulate a string-returning getter (e.g. Cla$StackErrstr) and return the constructed string,
    /// or null if the emulator hit something unsupported. The string is built into the emulator's shadow
    /// memory (the debuggee is never written), then read back.</summary>
    public string? EmulateGetterString(string export)
    {
        if (_hProcess == IntPtr.Zero) return null;
        var rt = RuntimeModule();
        if (rt == null || _stoppedTid == 0 || !_threads.TryGetValue(_stoppedTid, out var hThread)) return null;
        uint rva = rt.Pe!.FindExportRva(export);
        if (rva == 0) return null;
        uint teb = GetTebBase(hThread);
        if (teb == 0) return null;
        try { var emu = BuildEmulator(rt, teb); uint p = emu.Call(rt.LoadBase + rva); return emu.ReadCStringResult(p, 512); }
        catch (RtlEmulator.NotSupported) { return null; }
    }

    /// <summary>Diagnostic: emulate a getter and return (value-or-null, trace string).</summary>
    public (uint? Value, string Trace) EmulateGetterDbg(string export)
    {
        var rt = RuntimeModule();
        if (rt == null || _stoppedTid == 0 || !_threads.TryGetValue(_stoppedTid, out var hThread))
            return (null, "no runtime/thread");
        uint rva = rt.Pe!.FindExportRva(export);
        if (rva == 0) return (null, "no export");
        uint teb = GetTebBase(hThread);
        var emu = BuildEmulator(rt, teb);
        try { var v = emu.Call(rt.LoadBase + rva); return (v, $"teb=0x{teb:X} " + string.Join(" | ", emu.Trace)); }
        catch (RtlEmulator.NotSupported e) { return (null, $"teb=0x{teb:X} " + string.Join(" | ", emu.Trace) + "  !! " + e.Message); }
    }

    /// <summary>Diagnostic: the hand-rolled instance resolution details, for comparing with the emulator.</summary>
    public string ResolveInstanceDbg()
    {
        var rt = RuntimeModule();
        if (rt == null || _stoppedTid == 0 || !_threads.TryGetValue(_stoppedTid, out var hThread)) return "no rt/thread";
        uint teb = GetTebBase(hThread);
        uint threadRva = rt.Pe!.FindExportRva("Cla$THREAD");
        uint inst = ResolveRtlInstance(rt, teb, out var dbg);
        return $"base=0x{rt.LoadBase:X} Cla$THREAD rva=0x{threadRva:X} teb=0x{teb:X} {dbg}";
    }

    RtlEmulator BuildEmulator(LoadedModule rt, uint teb)
    {
        var imports = new Dictionary<uint, string>();
        foreach (var (_, func, slotRva) in rt.Pe!.EnumerateImports())
            imports[rt.LoadBase + slotRva] = func;
        return new RtlEmulator(
            readMem: (a, n) => ReadBytes(a, n),
            tlsGetValue: idx => ReadTlsSlot(teb, idx),
            curThreadId: _stoppedTid,
            teb: teb,
            importAtSlot: slot => imports.TryGetValue(slot, out var nm) ? nm : null,
            isCode: va => ModuleAt(va) != null);
    }

    /// <summary>The thread's TEB base via NtQueryInformationThread(ThreadBasicInformation). 0 on failure.</summary>
    uint GetTebBase(IntPtr hThread)
    {
        var buf = new byte[28];   // THREAD_BASIC_INFORMATION (32-bit): ExitStatus(0), TebBaseAddress(+4), ...
        return Native.NtQueryInformationThread(hThread, 0, buf, buf.Length, out _) == 0
            ? BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(4)) : 0;
    }

    /// <summary>Read a TLS slot value from a 32-bit TEB: TlsSlots[64] @ 0xE10, TlsExpansionSlots ptr @ 0xF94.</summary>
    uint ReadTlsSlot(uint teb, uint index)
    {
        if (index < 64) return ReadDword(teb + 0xE10 + index * 4);
        uint exp = ReadDword(teb + 0xF94);
        return exp == 0 ? 0 : ReadDword(exp + (index - 64) * 4);
    }
}
