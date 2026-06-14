using System.Buffers.Binary;

namespace ClarionDbg.Engine;

/// <summary>Minimal PE reader: sections + the Clarion '.cwdebug' locator.</summary>
public sealed class PeImage
{
    public record Section(string Name, uint Rva, uint VSize, uint RawPtr, uint RawSize);

    public byte[] Raw { get; }
    public uint PreferredBase { get; }
    public uint EntryRva { get; }
    public IReadOnlyList<Section> Sections { get; }

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
