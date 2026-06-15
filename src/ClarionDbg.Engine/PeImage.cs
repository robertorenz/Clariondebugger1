using System.Buffers.Binary;

namespace ClarionDbg.Engine;

/// <summary>Minimal PE reader: sections + the Clarion '.cwdebug' locator.</summary>
public sealed class PeImage
{
    public record Section(string Name, uint Rva, uint VSize, uint RawPtr, uint RawSize);

    public byte[] Raw { get; }
    public uint PreferredBase { get; }
    public uint EntryRva { get; }
    public uint SizeOfImage { get; }     // total mapped span — defines [LoadBase, LoadBase+SizeOfImage)
    public IReadOnlyList<Section> Sections { get; }

    readonly uint _importDirRva;

    public PeImage(string path)
    {
        Raw = File.ReadAllBytes(path);
        uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(0x3c));
        int coff = (int)lfanew + 4;
        ushort nsec = BinaryPrimitives.ReadUInt16LittleEndian(Raw.AsSpan(coff + 2));
        ushort optSize = BinaryPrimitives.ReadUInt16LittleEndian(Raw.AsSpan(coff + 16));
        int opt = coff + 20;
        EntryRva = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(opt + 16));
        PreferredBase = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(opt + 28)); // ImageBase (PE32)
        SizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(opt + 56));   // SizeOfImage (PE32)
        // data directory [1] = import table {VirtualAddress, Size}; array starts at opt+96 (PE32)
        if (opt + 96 + 12 <= Raw.Length)
            _importDirRva = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(opt + 96 + 8));
        int sectbl = opt + optSize;
        var secs = new List<Section>();
        for (int i = 0; i < nsec; i++)
        {
            int o = sectbl + i * 40;
            string name = System.Text.Encoding.ASCII.GetString(Raw, o, 8).TrimEnd('\0');
            secs.Add(new Section(name,
                BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(o + 12)),
                BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(o + 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(o + 20)),
                BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(o + 16))));
        }
        Sections = secs;
    }

    /// <summary>Best-effort load — returns null instead of throwing for absent/malformed images
    /// (a DLL discovered at runtime may be unreadable, packed, or a stub).</summary>
    public static PeImage? TryLoad(string path)
    {
        try { return new PeImage(path); }
        catch { return null; }
    }

    public Section? FindSection(string name) =>
        Sections.FirstOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    public bool IsCodeRva(uint rva)
    {
        var t = FindSection(".text");
        return t != null && rva >= t.Rva && rva < t.Rva + t.VSize;
    }

    /// <summary>True if rva falls in a writable data section (globals / file buffers / TLS).</summary>
    public bool IsDataRva(uint rva)
    {
        foreach (var s in Sections)
            if ((s.Name == ".data" || s.Name == ".cwtls" || s.Name == ".bss") &&
                rva >= s.Rva && rva < s.Rva + Math.Max(s.VSize, s.RawSize))
                return true;
        return false;
    }

    /// <summary>True if rva is in Clarion's thread-local section (.cwtls) — threaded data.</summary>
    public bool IsTlsRva(uint rva)
    {
        var s = FindSection(".cwtls");
        return s != null && rva >= s.Rva && rva < s.Rva + Math.Max(s.VSize, s.RawSize);
    }

    /// <summary>Map an RVA to a file offset, or -1 if it falls outside every section.</summary>
    public long RvaToOffset(uint rva)
    {
        foreach (var s in Sections)
            if (rva >= s.Rva && rva < s.Rva + Math.Max(s.VSize, s.RawSize))
                return s.RawPtr + (rva - s.Rva);
        return -1;
    }

    string ReadAsciiZ(int off)
    {
        if (off < 0 || off >= Raw.Length) return "";
        int e = off; while (e < Raw.Length && Raw[e] != 0) e++;
        return System.Text.Encoding.ASCII.GetString(Raw, off, e - off);
    }

    /// <summary>Enumerate named imports as (dll, function, iatSlotRva). By-ordinal imports are skipped.</summary>
    public IEnumerable<(string Dll, string Func, uint SlotRva)> EnumerateImports()
    {
        if (_importDirRva == 0) yield break;
        long dirOff = RvaToOffset(_importDirRva);
        if (dirOff < 0) yield break;
        for (int d = 0; ; d++)
        {
            int desc = (int)dirOff + d * 20;
            if (desc + 20 > Raw.Length) break;
            uint oft = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(desc));
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(desc + 12));
            uint ft = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(desc + 16));
            if (oft == 0 && nameRva == 0 && ft == 0) break;
            long nameOff = RvaToOffset(nameRva);
            string dll = nameOff >= 0 ? ReadAsciiZ((int)nameOff) : "?";
            long thunkOff = RvaToOffset(oft != 0 ? oft : ft);
            if (thunkOff < 0) continue;
            for (int i = 0; ; i++)
            {
                if (thunkOff + i * 4 + 4 > Raw.Length) break;
                uint entry = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan((int)thunkOff + i * 4));
                if (entry == 0) break;
                if ((entry & 0x80000000) != 0) continue;
                long hintOff = RvaToOffset(entry);
                if (hintOff < 0) continue;
                yield return (dll, ReadAsciiZ((int)hintOff + 2), ft + (uint)i * 4);
            }
        }
    }

    /// <summary>The IAT slot RVA for an imported function (e.g. ClaRUN.dll!THR$GetInstance): at
    /// runtime the u32 at loadBase+slot holds the function's live address. 0 if not imported.</summary>
    public uint FindImportIatSlotRva(string dllName, string funcName)
    {
        if (_importDirRva == 0) return 0;
        long dirOff = RvaToOffset(_importDirRva);
        if (dirOff < 0) return 0;
        for (int d = 0; ; d++)
        {
            int desc = (int)dirOff + d * 20;                                  // IMAGE_IMPORT_DESCRIPTOR
            if (desc + 20 > Raw.Length) break;
            uint oft = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(desc));        // OriginalFirstThunk
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(desc + 12));
            uint ft = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(desc + 16));    // FirstThunk = the IAT
            if (oft == 0 && nameRva == 0 && ft == 0) break;

            long nameOff = RvaToOffset(nameRva);
            if (nameOff < 0 || !string.Equals(ReadAsciiZ((int)nameOff), dllName, StringComparison.OrdinalIgnoreCase))
                continue;

            uint thunks = oft != 0 ? oft : ft;                               // name table (fall back to bound IAT)
            long thunkOff = RvaToOffset(thunks);
            if (thunkOff < 0) continue;
            for (int i = 0; ; i++)
            {
                if (thunkOff + i * 4 + 4 > Raw.Length) break;
                uint entry = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan((int)thunkOff + i * 4));
                if (entry == 0) break;
                if ((entry & 0x80000000) != 0) continue;                     // by-ordinal — no name
                long hintOff = RvaToOffset(entry);
                if (hintOff < 0) continue;
                if (string.Equals(ReadAsciiZ((int)hintOff + 2), funcName, StringComparison.Ordinal))
                    return ft + (uint)i * 4;
            }
        }
        return 0;
    }

    /// <summary>Returns the raw bytes of the appended TSWD debug blob, or null if release build.</summary>
    public byte[]? ReadCwDebugBlob()
    {
        var sec = FindSection(".cwdebug");
        if (sec == null) return null;
        var loc = Raw.AsSpan((int)sec.RawPtr, 32);
        if (!loc.Slice(12, 4).SequenceEqual("TSWD"u8)) return null;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(loc.Slice(16));
        uint off = BinaryPrimitives.ReadUInt32LittleEndian(loc.Slice(24));
        return Raw.AsSpan((int)off, (int)size).ToArray();
    }
}
