using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;

namespace ClarionDbg.App;

/// <summary>
/// Colorizes Clarion source in the AvalonEdit editor by reusing the existing
/// <see cref="SyntaxHighlight.Tokenize"/> vocabulary — so the new view matches the
/// legacy per-line TextBlock colouring exactly. Per visual line: tokenize the line's
/// text and recolor each span's foreground. Stateless/per-line, like the original.
/// </summary>
public sealed class ClarionColorizer : DocumentColorizingTransformer
{
    protected override void ColorizeLine(DocumentLine line)
    {
        if (line.Length == 0) return;

        int lineStart = line.Offset;
        string text = CurrentContext.Document.GetText(line);

        int pos = 0;
        foreach (var (token, brush) in SyntaxHighlight.Tokenize(text))
        {
            int len = token.Length;
            if (len > 0)
            {
                int start = lineStart + pos;
                ChangeLinePart(start, start + len,
                    el => el.TextRunProperties.SetForegroundBrush(brush));
            }
            pos += len;
        }
    }
}
