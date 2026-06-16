using System.Windows;
using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;

namespace ClarionDbg.App;

/// <summary>
/// Paints a full-width background band across the current execution line — the
/// AvalonEdit equivalent of the old per-row <c>RowBg</c> highlight. Set
/// <see cref="Line"/> (1-based, or null) and invalidate the background layer.
/// </summary>
public sealed class CurrentLineRenderer : IBackgroundRenderer
{
    Brush? _brush;

    /// <summary>The current execution line (1-based), or null for none.</summary>
    public int? Line { get; set; }

    public KnownLayer Layer => KnownLayer.Background;

    public void Draw(TextView textView, DrawingContext dc)
    {
        if (Line is not int ln || textView.Document == null) return;
        if (ln < 1 || ln > textView.Document.LineCount) return;

        var docLine = textView.Document.GetLineByNumber(ln);
        var seg = new TextSegment { StartOffset = docLine.Offset, EndOffset = docLine.EndOffset };
        _brush ??= MakeBrush();

        foreach (var rect in BackgroundGeometryBuilder.GetRectsForSegment(textView, seg))
            dc.DrawRectangle(_brush, null, new Rect(0, rect.Top, textView.ActualWidth, rect.Height));
    }

    static Brush MakeBrush()
    {
        var b = (System.Windows.Application.Current?.Resources["CurLine"] as Brush)
                ?? new SolidColorBrush(Color.FromArgb(0x50, 0x2A, 0x4A, 0x2A));
        if (b.CanFreeze) b.Freeze();
        return b;
    }
}
