using System.Buffers.Binary;
using System.Text;

namespace ClarionDbg.Engine;

public enum TypeKind { Int, UInt, Float, Char, Decimal, PDecimal, Group, String, Array, Unknown }

/// <summary>A decoded Clarion data type from the TSWD type records.</summary>
public sealed class ClaType
{
    public TypeKind Kind;
    public int Size;                       // total byte size
    public int Places;                     // decimal places (Decimal/PDecimal)
    public ClaType? Element;               // element type (Array/String)
    public int Length;                     // element count (Array/String)
    public List<GroupField> Members = new();// group members

    public record GroupField(string Name, int Offset, ClaType Type);

    public string Describe() => Kind switch
    {
        TypeKind.Int => $"int{Size * 8}",
        TypeKind.UInt => $"uint{Size * 8}",
        TypeKind.Float => Size == 4 ? "real4" : "real8",
        TypeKind.Char => "char",
        TypeKind.Decimal => $"decimal(.{Places})",
        TypeKind.PDecimal => $"pdecimal(.{Places})",
        TypeKind.String => $"string({Length})",
        TypeKind.Array => $"{Element?.Describe()}[{Length}]",
        TypeKind.Group => $"group({Members.Count})",
        _ => "?"
    };

    /// <summary>Format a value from its raw bytes (len >= Size).</summary>
    public string Format(byte[] b, int off = 0)
    {
        switch (Kind)
        {
            case TypeKind.Int:
                long sv = Size switch
                {
                    1 => (sbyte)b[off],
                    2 => BinaryPrimitives.ReadInt16LittleEndian(b.AsSpan(off)),
                    4 => BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(off)),
                    8 => BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(off)),
                    _ => 0
                };
                return sv.ToString();
            case TypeKind.UInt:
                ulong uv = Size switch
                {
                    1 => b[off],
                    2 => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(off)),
                    4 => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off)),
                    8 => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(off)),
                    _ => 0
                };
                return uv.ToString();
            case TypeKind.Float:
                return Size == 4
                    ? BitConverter.ToSingle(b, off).ToString("0.######")
                    : BitConverter.ToDouble(b, off).ToString("0.##########");
            case TypeKind.Char:
                return $"'{(char)b[off]}'";
            case TypeKind.Decimal:
            case TypeKind.PDecimal:
                return FormatBcd(b, off, Size, Places);
            case TypeKind.String:
                return "'" + Ascii(b, off, Length).TrimEnd('\0', ' ') + "'";
            case TypeKind.Array:
                {
                    var sb = new StringBuilder("[");
                    int es = Element!.Size;
                    for (int i = 0; i < Length && off + (i + 1) * es <= b.Length; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        if (i >= 16) { sb.Append('…'); break; }
                        sb.Append(Element.Format(b, off + i * es));
                    }
                    return sb.Append(']').ToString();
                }
            case TypeKind.Group:
                {
                    var sb = new StringBuilder("{");
                    bool first = true;
                    foreach (var m in Members)
                    {
                        if (!first) sb.Append(", ");
                        first = false;
                        sb.Append(m.Name).Append('=').Append(m.Type.Format(b, off + m.Offset));
                    }
                    return sb.Append('}').ToString();
                }
            default:
                int avail = b.Length - off;
                if (avail <= 0) return "?";
                int show = Math.Min(avail, Size > 0 ? Size : 4);
                return "0x" + BitConverter.ToString(b, off, show).Replace("-", "");
        }
    }

    static string Ascii(byte[] b, int off, int len)
    {
        int n = Math.Min(len, b.Length - off);
        var sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) { byte c = b[off + i]; if (c == 0) break; sb.Append(c >= 32 && c < 127 ? (char)c : '.'); }
        return sb.ToString();
    }

    /// <summary>Packed BCD: two digits per byte, optional sign nibble in the low nibble.</summary>
    static string FormatBcd(byte[] b, int off, int size, int places)
    {
        var digits = new StringBuilder();
        bool neg = false;
        for (int i = 0; i < size && off + i < b.Length; i++)
        {
            int hi = (b[off + i] >> 4) & 0xF, lo = b[off + i] & 0xF;
            digits.Append((char)('0' + (hi <= 9 ? hi : 0)));
            if (i == size - 1 && lo >= 0xA) { neg = lo is 0x0B or 0x0D; }
            else digits.Append((char)('0' + (lo <= 9 ? lo : 0)));
        }
        string s = digits.ToString().TrimStart('0');
        if (s.Length <= places) s = new string('0', places - s.Length + 1) + s;
        string res = places > 0 ? s[..^places] + "." + s[^places..] : s;
        return (neg ? "-" : "") + res;
    }
}
