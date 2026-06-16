using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using ICSharpCode.AvalonEdit.Editing;
using ICSharpCode.AvalonEdit.Rendering;

namespace ClarionDbg.App;

/// <summary>
/// A left margin (to the left of the line numbers) that draws a red dot on lines
/// carrying a breakpoint and toggles a breakpoint when clicked. Breakpoint state
/// and toggling are delegated to the host, so this stays purely visual.
/// </summary>
public sealed class BreakpointMargin : AbstractMargin
{
    const double MarginWidth = 18;
    const double Radius = 4.5;

    readonly Func<int, bool> _hasBreakpoint;   // line (1-based) -> has a breakpoint?
    readonly Action<int> _toggle;              // toggle breakpoint on line (1-based)
    static readonly Brush Dot = MakeDot();

    public BreakpointMargin(Func<int, bool> hasBreakpoint, Action<int> toggle)
    {
        _hasBreakpoint = hasBreakpoint;
        _toggle = toggle;
        Cursor = Cursors.Hand;
    }

    static Brush MakeDot()
    {
        var b = (System.Windows.Application.Current?.Resources["BpRed"] as Brush)
                ?? new SolidColorBrush(Color.FromRgb(0xE0, 0x51, 0x51));
        if (b.CanFreeze) b.Freeze();
        return b;
    }

    /// <summary>Redraw after breakpoints change elsewhere (toggle, Breakpoints window, restore).</summary>
    public void Refresh() => InvalidateVisual();

    protected override Size MeasureOverride(Size availableSize) => new Size(MarginWidth, 0);

    protected override void OnTextViewChanged(TextView oldTextView, TextView newTextView)
    {
        if (oldTextView != null) oldTextView.VisualLinesChanged -= OnVisualLinesChanged;
        base.OnTextViewChanged(oldTextView, newTextView);
        if (newTextView != null) newTextView.VisualLinesChanged += OnVisualLinesChanged;
        InvalidateVisual();
    }

    void OnVisualLinesChanged(object? sender, EventArgs e) => InvalidateVisual();

    protected override void OnRender(DrawingContext dc)
    {
        // A transparent fill over the whole margin makes it hit-testable for clicks.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, RenderSize.Width, RenderSize.Height));

        var tv = TextView;
        if (tv == null || !tv.VisualLinesValid) return;

        foreach (var vl in tv.VisualLines)
        {
            int lineNo = vl.FirstDocumentLine.LineNumber;
            if (!_hasBreakpoint(lineNo)) continue;
            double top = vl.GetTextLineVisualYPosition(vl.TextLines[0], VisualYPosition.LineTop) - tv.VerticalOffset;
            double bottom = vl.GetTextLineVisualYPosition(vl.TextLines[^1], VisualYPosition.LineBottom) - tv.VerticalOffset;
            double cy = top + (bottom - top) / 2;
            dc.DrawEllipse(Dot, null, new Point(MarginWidth / 2, cy), Radius, Radius);
        }
    }

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        base.OnMouseDown(e);
        var tv = TextView;
        if (e.ChangedButton != MouseButton.Left || tv == null || !tv.VisualLinesValid) return;

        double y = e.GetPosition(this).Y;
        foreach (var vl in tv.VisualLines)
        {
            double top = vl.GetTextLineVisualYPosition(vl.TextLines[0], VisualYPosition.LineTop) - tv.VerticalOffset;
            double bottom = vl.GetTextLineVisualYPosition(vl.TextLines[^1], VisualYPosition.LineBottom) - tv.VerticalOffset;
            if (y >= top && y < bottom)
            {
                _toggle(vl.FirstDocumentLine.LineNumber);
                e.Handled = true;
                return;
            }
        }
    }
}
