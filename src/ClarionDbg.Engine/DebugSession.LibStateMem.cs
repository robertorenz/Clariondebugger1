using System.Buffers.Binary;

namespace ClarionDbg.Engine;

// Library State, read SAFELY by EMULATION. Calling the Cla$* getters on the stopped thread re-enters the
// RTL's thread-instance machinery, which corrupts state when the thread is parked inside the ACCEPT/
// TakeEvent loop and crashes the app (0x6BEF5E4C) — confirmed against school.exe, and CA-Debugger fails
// the same way. Instead we evaluate each getter with a read-only x86 emulator (RtlEmulator): it runs the
// getter's real code but every debuggee access is a ReadProcessMemory, writes go to a copy-on-write
// shadow, and the imports that matter are intrinsics (TlsGetValue -> TEB.TlsSlots, etc.). No hijack, no
// thread suspend, no re-entrancy — safe to read while parked anywhere, including mid-TakeEvent.
public sealed partial class DebugSession
{
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
