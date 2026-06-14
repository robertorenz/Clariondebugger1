using System.Buffers.Binary;

namespace ClarionDbg.Engine;

public sealed class TswdSymbol
{
    public string Name = "";
    public ClaType Type = new() { Kind = TypeKind.Unknown };
    public bool IsGlobal;
    public uint Rva;            // when IsGlobal
    public int FrameOffset;     // when local/param
    public bool IsParam;
    public int DisplaySize = 4; // bytes to show when the type isn't fully decoded
    public bool Threaded;       // lives in .cwtls (Clarion thread-local)
    public bool IsStatic;       // local statically allocated at an RVA (threaded proc) vs EBP-relative
}

public sealed class TswdProc
{
    public string Name = "";
    public uint EntryRva;
    public ClaType? RetType;
    public List<TswdSymbol> Locals = new();
}

public sealed class TswdModule
{
    public string Name = "";
    public int FirstLine, LastLine;
    public List<(int Line, uint Rva)> Lines = new();
    public override string ToString() => $"{Name} ({Lines.Count})";
}

/// <summary>
/// Full parser for the Clarion/TopSpeed 'TSWD' debug blob.
/// Records are addressed by a ref into the symbol stream; the tag byte is at ref+4.
///   var  (0x04): typeRef u32 @+5, nameOff u32 @+9, offset i32 @+13
///   proc (0x05): retType @+5, nameOff @+9, entryRva @+13, localCount @+25, localRefs @+29..
///   type tags @typeRef+4: 0x11 int / 0x12 uint / 0x13 float / 0x14 char (+size u32);
///       0x23 decimal / 0x24 pdecimal (+size u32, +places u8);
///       0x08 group (+size u32, +count u32, +memberRefs); 0x18 array/string descriptor.
/// </summary>
public sealed class TswdInfo
{
    public string SourceFile = "";
    public int ModuleCount;
    public List<(int Line, uint Rva)> Lines { get; } = new();
    public List<TswdModule> Modules { get; } = new();
    public List<TswdSymbol> Globals { get; } = new();
    public List<TswdProc> Procs { get; } = new();
    public List<(string Name, uint Rva)> Procedures { get; } = new();

    // flat lookup sorted by rva: (rva, moduleIndex, line)
    (uint Rva, int Mod, int Line)[] _byRva = Array.Empty<(uint, int, int)>();

    byte[] _b = Array.Empty<byte>();
    int _nameBase, _symBase;
    PeImage? _pe;
    readonly Dictionary<int, ClaType> _typeCache = new();

    static uint U32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
    static int I32(byte[] b, int o) => BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(o));
    static ushort U16(byte[] b, int o) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o));

    string Name(int off)
    {
        int s = _nameBase + off;
        if (s < 0 || s >= _b.Length) return $"?{off:X}";
        int e = Array.IndexOf(_b, (byte)0, s);
        return e > s ? System.Text.Encoding.Latin1.GetString(_b, s, e - s) : "";
    }

    public static TswdInfo? Load(PeImage pe)
    {
        var blob = pe.ReadCwDebugBlob();
        if (blob == null || !blob.AsSpan(0, 4).SequenceEqual("TSWD"u8)) return null;

        var info = new TswdInfo { _b = blob };
        int[] dir = new int[12];
        for (int i = 0; i < 12; i++) dir[i] = (int)U32(blob, 8 + 4 * i);
        int srcOff = dir[1], ltOff = dir[3], ltCnt = dir[4];
        info._nameBase = dir[6];
        info._symBase = dir[8];
        int amOff = dir[11], amCnt = dir[10];
        info._symEnd = amOff;     // symbol-record stream lives between symBase and the address map
        info.ModuleCount = (int)U32(blob, 4);

        // --- line table (flat) ---
        var flat = new List<(int Line, uint Rva)>(ltCnt);
        for (int i = 0, o = ltOff; i < ltCnt && o + 6 <= blob.Length; i++, o += 6)
            flat.Add((U16(blob, o), U32(blob, o + 2)));
        info.Lines.AddRange(flat);

        // --- modules: dir[0]=name-offset array, dir[1]=name strings,
        //     dir[2]=per-module {firstLineIdx, lastLineIdx} into the flat line table ---
        int nameArr = dir[0], nameTbl = dir[1], perMod = dir[2];
        var byRva = new List<(uint, int, int)>();
        for (int m = 0; m < info.ModuleCount; m++)
        {
            int nOff = (int)U32(blob, nameArr + 4 * m);
            string mname = info.CStr(nameTbl + nOff);
            int a = (int)U32(blob, perMod + 8 * m);
            int b = (int)U32(blob, perMod + 8 * m + 4);
            var mod = new TswdModule { Name = mname, FirstLine = a, LastLine = b };
            if (!(a == 0 && b == 0))   // {0,0} sentinel = module has no debug lines
                for (int e = a; e <= b && e < flat.Count; e++)
                {
                    mod.Lines.Add(flat[e]);
                    byRva.Add((flat[e].Rva, m, flat[e].Line));
                }
            info.Modules.Add(mod);
        }
        byRva.Sort((x, y) => x.Item1.CompareTo(y.Item1));
        info._byRva = byRva.ToArray();
        // pick the app's primary module (last non-empty .clw, usually the program) for default display
        info.SourceFile = info.Modules.LastOrDefault(m => m.Lines.Count > 0)?.Name ?? "";

        // The address map indexes ALL debug records (incl. locals/inner records) and points
        // into them at varying offsets, so it can't be used to enumerate top-level symbols.
        // Instead scan the symbol-record stream for procedure (0x05) and global-var (0x04)
        // records, validated against the PE layout. This finds every procedure across all
        // modules (the address map only surfaces a fraction).
        info.ScanSymbols(pe);
        return info;
    }

    void ScanSymbols(PeImage pe)
    {
        _pe = pe;
        int nameSz = _symBase - _nameBase;
        var seenProc = new HashSet<uint>();
        var seenGlobal = new HashSet<uint>();
        for (int o = _symBase; o + 25 < _symEnd; o++)
        {
            byte tag = _b[o];
            if (tag == 0x05)   // procedure
            {
                int nameOff = (int)RU32(o + 5);
                uint entry = RU32(o + 9);
                int lcount = (int)RU32(o + 21);
                if (nameOff > 0 && nameOff < nameSz && pe.IsCodeRva(entry) && lcount is >= 0 and < 2000
                    && seenProc.Add(entry))
                {
                    string nm = Name(nameOff);
                    if (CleanName(nm))
                    {
                        try
                        {
                            var p = ParseProc(o - _symBase - 4);
                            if (p.Name == nm) { Procs.Add(p); Procedures.Add((p.Name, p.EntryRva)); }
                        }
                        catch { }
                    }
                }
            }
            else if (tag == 0x04)   // global variable (offset is a data RVA, not a frame offset)
            {
                int typeRef = (int)RU32(o + 1);
                int nameOff = (int)RU32(o + 5);
                uint rva = RU32(o + 9);
                if (nameOff > 0 && nameOff < nameSz && ValidRef(typeRef) && pe.IsDataRva(rva)
                    && seenGlobal.Add(rva))
                {
                    string nm = Name(nameOff);
                    // skip compiler-internal virtual method tables
                    if (CleanName(nm) && !nm.StartsWith("VMT$") && !nm.StartsWith("VMTP$"))
                    {
                        try
                        {
                            var sym = ParseVar(o - _symBase - 4);
                            sym.IsGlobal = true; sym.Rva = rva; sym.FrameOffset = 0;
                            Globals.Add(sym);
                        }
                        catch { }
                    }
                }
            }
        }
        Procs.Sort((a, b) => a.EntryRva.CompareTo(b.EntryRva));
        Globals.Sort((a, b) => a.Rva.CompareTo(b.Rva));

        // infer a display size from the gap to the next global so undecoded types still
        // show their data; flag thread-local (.cwtls) symbols.
        for (int i = 0; i < Globals.Count; i++)
        {
            var g = Globals[i];
            g.Threaded = pe.IsTlsRva(g.Rva);
            int sz = g.Type.Size > 0 ? g.Type.Size : 4;
            if (g.Type.Kind == TypeKind.Unknown && i + 1 < Globals.Count && Globals[i + 1].Rva > g.Rva)
                sz = (int)Math.Min(Globals[i + 1].Rva - g.Rva, 512);
            g.DisplaySize = Math.Max(sz, 1);
        }
    }

    static bool CleanName(string s) =>
        s.Length is > 0 and < 96 && s[0] != '?' && s.All(ch => ch >= 32 && ch < 127);

    // ---- bounds-safe blob readers ----
    int _symEnd;
    uint RU32(int o) => (o >= 0 && o + 4 <= _b.Length) ? BinaryPrimitives.ReadUInt32LittleEndian(_b.AsSpan(o)) : 0;
    int RI32(int o) => (o >= 0 && o + 4 <= _b.Length) ? BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan(o)) : 0;
    byte RB(int o) => (o >= 0 && o < _b.Length) ? _b[o] : (byte)0;
    bool ValidRef(int reff) => reff >= 0 && _symBase + reff + 5 <= _b.Length;
    string CStr(int off)
    {
        if (off < 0 || off >= _b.Length) return "";
        int e = Array.IndexOf(_b, (byte)0, off);
        return e > off ? System.Text.Encoding.Latin1.GetString(_b, off, e - off) : "";
    }

    TswdSymbol ParseVar(int reff)
    {
        int b = _symBase + reff;     // record start; tag at b+4
        int typeRef = (int)RU32(b + 5);
        int nameOff = (int)RU32(b + 9);
        int off = RI32(b + 13);
        return new TswdSymbol { Name = Name(nameOff), FrameOffset = off, Type = ParseType(typeRef) };
    }

    TswdProc ParseProc(int reff)
    {
        int b = _symBase + reff;
        int retTypeRef = (int)RU32(b + 5);
        int nameOff = (int)RU32(b + 9);
        uint entry = RU32(b + 13);
        int localCount = (int)RU32(b + 25);
        var proc = new TswdProc { Name = Name(nameOff), EntryRva = entry };
        if (ValidRef(retTypeRef) && retTypeRef > 0) proc.RetType = ParseType(retTypeRef);
        var seen = new HashSet<string>();
        for (int i = 0; i < localCount && i < 1024; i++)
        {
            int lref = (int)RU32(b + 29 + 4 * i);
            // The local-record reference can point either at the record (tag at ref+4, as in
            // simple procs) or directly at the tag (tag at ref+0, seen in threaded ABC procs).
            // Try both and accept whichever yields a clean variable record.
            TswdSymbol? sym = null;
            foreach (int cand in new[] { lref, lref - 4 })
            {
                if (!ValidRef(cand)) continue;
                byte tg = RB(_symBase + cand + 4);
                if (tg != 0x04 && tg != 0x0c) continue;
                var s = ParseVar(cand);
                if (CleanName(s.Name)) { sym = s; break; }
            }
            if (sym == null || !seen.Add(sym.Name)) continue;

            // Threaded ABC procedures allocate locals statically (data RVA); simple procs use
            // an EBP-relative frame offset.
            uint asRva = (uint)sym.FrameOffset;
            if (_pe != null && _pe.IsDataRva(asRva))
            {
                sym.IsStatic = true; sym.Rva = asRva; sym.Threaded = _pe.IsTlsRva(asRva); sym.FrameOffset = 0;
                proc.Locals.Add(sym);
            }
            else if (Math.Abs(sym.FrameOffset) < 0x10000)
                proc.Locals.Add(sym);
        }
        return proc;
    }

    ClaType ParseType(int typeRef)
    {
        if (_typeCache.TryGetValue(typeRef, out var c)) return c;
        var t = new ClaType { Kind = TypeKind.Unknown };
        if (!ValidRef(typeRef)) return t;
        _typeCache[typeRef] = t;             // guard against cycles
        int o = _symBase + typeRef + 4;      // tag
        byte tag = RB(o);
        switch (tag)
        {
            case 0x11: t.Kind = TypeKind.Int; t.Size = (int)RU32(o + 1); break;
            case 0x12: t.Kind = TypeKind.UInt; t.Size = (int)RU32(o + 1); break;
            case 0x13: t.Kind = TypeKind.Float; t.Size = (int)RU32(o + 1); break;
            case 0x14: t.Kind = TypeKind.Char; t.Size = (int)RU32(o + 1); break;
            case 0x23: t.Kind = TypeKind.Decimal; t.Size = (int)RU32(o + 1); t.Places = RB(o + 5); break;
            case 0x24: t.Kind = TypeKind.PDecimal; t.Size = (int)RU32(o + 1); t.Places = RB(o + 5); break;
            case 0x08:
                t.Kind = TypeKind.Group; t.Size = (int)RU32(o + 1);
                int cnt = (int)RU32(o + 5);
                for (int i = 0; i < cnt && i < 1024; i++)
                {
                    int mref = (int)RU32(o + 9 + 4 * i);
                    if (!ValidRef(mref)) continue;
                    byte mtag = RB(_symBase + mref + 4);    // members use tag 0x0c, plain vars 0x04
                    if (mtag != 0x04 && mtag != 0x0c) continue;
                    var m = ParseVar(mref);
                    t.Members.Add(new ClaType.GroupField(m.Name, m.FrameOffset, m.Type));
                }
                break;
            case 0x18:
                {
                    byte elemTag = RB(o + 9);
                    int elemSize = (int)RU32(o + 10);
                    int length = (int)RU32(o + 23);
                    var elem = new ClaType
                    {
                        Kind = elemTag switch
                        {
                            0x11 => TypeKind.Int,
                            0x12 => TypeKind.UInt,
                            0x13 => TypeKind.Float,
                            0x14 => TypeKind.Char,
                            _ => TypeKind.Unknown
                        },
                        Size = elemSize
                    };
                    if (length is < 0 or > 0xFFFF) length = 0;
                    if (elemTag == 0x14) { t.Kind = TypeKind.String; t.Length = length; t.Size = length; }
                    else { t.Kind = TypeKind.Array; t.Element = elem; t.Length = length; t.Size = elemSize * length; }
                    break;
                }
        }
        return t;
    }

    /// <summary>Map a code RVA to its (module, line) via the largest line-entry rva ≤ rva.</summary>
    public (string Module, int Line)? Locate(uint rva)
    {
        if (_byRva.Length == 0) return null;
        int lo = 0, hi = _byRva.Length - 1, idx = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (_byRva[mid].Rva <= rva) { idx = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (idx < 0) return null;
        var e = _byRva[idx];
        // don't attribute an address that is far past the last line of its module
        return (Modules[e.Mod].Name, e.Line);
    }

    public int? RvaToLine(uint rva) => Locate(rva)?.Line;

    /// <summary>Resolve a breakpoint to an address: prefer the given module, else any module.</summary>
    public uint? LineToRva(int line, string? module = null)
    {
        if (module != null)
        {
            var m = Modules.FirstOrDefault(x => x.Name.Equals(module, StringComparison.OrdinalIgnoreCase));
            if (m != null) return LineInModule(m, line);
        }
        foreach (var m in Modules) { var r = LineInModule(m, line); if (r != null) return r; }
        return null;
    }

    /// <summary>Nearest source line that actually has code in the given module (for snapping breakpoints).</summary>
    public int? NearestCodeLine(string module, int line)
    {
        var m = Modules.FirstOrDefault(x => x.Name.Equals(module, StringComparison.OrdinalIgnoreCase));
        if (m == null || m.Lines.Count == 0) return null;
        int? up = null, down = null;
        foreach (var (l, _) in m.Lines)
        {
            if (l == line) return line;
            if (l > line && (up == null || l < up)) up = l;
            if (l < line && (down == null || l > down)) down = l;
        }
        // prefer the next line forward (where execution of the clicked statement would resume)
        return up ?? down;
    }

    static uint? LineInModule(TswdModule m, int line)
    {
        foreach (var (l, r) in m.Lines) if (l == line) return r;
        uint? best = null; int bestLine = int.MaxValue;
        foreach (var (l, r) in m.Lines) if (l >= line && l < bestLine) { bestLine = l; best = r; }
        return best;
    }

    /// <summary>The procedure whose code range contains the given RVA.</summary>
    public TswdProc? ProcContaining(uint rva)
    {
        TswdProc? best = null; uint bestEntry = 0;
        foreach (var p in Procs)
            if (p.EntryRva <= rva && p.EntryRva >= bestEntry) { bestEntry = p.EntryRva; best = p; }
        return best;
    }
}
