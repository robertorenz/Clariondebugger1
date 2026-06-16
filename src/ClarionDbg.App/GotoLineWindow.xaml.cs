using System.Windows;
using System.Windows.Input;

namespace ClarionDbg.App;

/// <summary>Minimal "Go to Line" prompt: enter a 1-based line number within range.</summary>
public partial class GotoLineWindow : Window
{
    public int? LineNumber { get; private set; }

    readonly int _max;

    public GotoLineWindow(int currentLine, int maxLine)
    {
        InitializeComponent();
        _max = maxLine;
        TxtPrompt.Text = $"Line number (1–{maxLine}):";
        TxtLine.Text = currentLine.ToString();
        Loaded += (_, _) => { TxtLine.Focus(); TxtLine.SelectAll(); };
    }

    void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (int.TryParse(TxtLine.Text.Trim(), out int n) && n >= 1 && n <= _max)
        {
            LineNumber = n;
            DialogResult = true;
        }
        else
        {
            TxtPrompt.Text = $"Enter a number between 1 and {_max}.";
            TxtLine.SelectAll();
            TxtLine.Focus();
        }
    }

    void TxtLine_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { Ok_Click(sender, e); e.Handled = true; }
    }

    void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
