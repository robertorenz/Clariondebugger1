namespace ClarionDbg.Engine;

/// <summary>
/// One image mapped into the debuggee: the EXE (module 0) plus every loaded DLL. The module table
/// is the foundation for multi-DLL debugging — all live VA math is done relative to the owning
/// image's <see cref="LoadBase"/>, and address/line/symbol resolution goes through that image's
/// own <see cref="Info"/> (its TSWD blob) and <see cref="Pe"/>.
///
/// Tiers (decided by what we could parse):
///   debug  — <see cref="Info"/> != null: full source-level debugging (EXE + Clarion debug DLLs).
///   plain  — <see cref="Info"/> == null but <see cref="Pe"/> != null: base/size/.text known, so we
///            attribute addresses and skip stepping into it (ClaRUN, Windows DLLs, release DLLs).
///   opaque — <see cref="Pe"/> == null: only base+name+size (from the remote PE header) for span math.
/// </summary>
public sealed class LoadedModule
{
    public string? Path;          // full disk path (the EXE arg, or GetFinalPathNameByHandle of the DLL)
    public string Name = "";      // file name, lowercased (e.g. myapp.dll)
    public uint LoadBase;         // runtime base from the debug event (0 until mapped); honours relocation
    public uint Size;             // PE SizeOfImage — defines [LoadBase, LoadBase+Size)
    public PeImage? Pe;           // null when the file could not be read
    public TswdInfo? Info;        // null for non-debug images (no TSWD blob)
    public bool Preloaded;        // registered ahead of launch (kept on unload) vs runtime-discovered (dropped)

    // ---- THREADed (.cwtls) data: per-thread instance resolution via ClaRUN!THR$GetInstance ----
    public uint CwtlsLo, CwtlsHi;          // .cwtls section RVA range (0 when the image has no threaded data)
    public uint ThrGetInstanceIatRva;      // IAT slot RVA of ClaRUN.dll!THR$GetInstance (0 when not imported)

    public bool HasDebug => Info != null;
    public bool HasThreadedData => CwtlsHi != 0 && ThrGetInstanceIatRva != 0;

    public bool ContainsVa(uint va) => LoadBase != 0 && va >= LoadBase && va < LoadBase + Size;

    /// <summary>True if <paramref name="va"/> is a threaded (.cwtls) template address in this image.</summary>
    public bool IsThreadedVa(uint va)
        => CwtlsHi != 0 && LoadBase != 0 && va >= LoadBase + CwtlsLo && va < LoadBase + CwtlsHi;

    /// <summary>Cache the .cwtls range and the THR$GetInstance IAT slot from the parsed PE.</summary>
    public void ResolveThreadedInfo()
    {
        if (Pe == null) return;
        var cwtls = Pe.FindSection(".cwtls");
        if (cwtls != null) { CwtlsLo = cwtls.Rva; CwtlsHi = cwtls.Rva + Math.Max(cwtls.VSize, cwtls.RawSize); }
        ThrGetInstanceIatRva = Pe.FindImportIatSlotRva("ClaRUN.dll", "THR$GetInstance");
    }

    /// <summary>True if <paramref name="va"/> falls in this image's executable section AND the image
    /// carries debug info — i.e. Clarion code we can resolve and single-step. Non-debug DLLs are
    /// deliberately excluded so stepping runs them at full speed.</summary>
    public bool IsDebuggableCode(uint va)
        => Info != null && Pe != null && LoadBase != 0 && Pe.IsCodeRva(va - LoadBase);

    public override string ToString() => $"{Name} @0x{LoadBase:X8} (+0x{Size:X})" + (HasDebug ? " [debug]" : "");
}
