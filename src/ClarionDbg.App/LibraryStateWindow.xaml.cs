using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using ClarionDbg.Engine;

namespace ClarionDbg.App;

/// <summary>Shows the stopped thread's RTL "Library State" (ERROR/EVENT/THREAD/…), read by calling
/// the ClaRUN getter exports on that thread. The values are a point-in-time snapshot: refreshed on
/// each stop while the window is open, cleared on resume (it runs target code, so nothing runs while
/// the program is free or the window is closed).</summary>
public partial class LibraryStateWindow : Window
{
    readonly Func<DebugSession?> _session;   // pulled live so the window survives a session restart

    public LibraryStateWindow(Func<DebugSession?> session)
    {
        InitializeComponent();
        _session = session;
        Loaded += (_, _) => RefreshNow();
    }

    /// <summary>The debugger has stopped — auto-refresh the snapshot, but DEFER it. The engine fires its
    /// stop event on the worker thread via Dispatcher.Invoke, so the worker is still inside that handler
    /// and has not yet parked in its wait loop; reading getters synchronously now would deadlock. Background
    /// priority runs after the stop handler returns and the worker is ready. (The read is on the UI thread,
    /// which naturally serialises it before any Continue — and the batch never calls back to the UI, so the
    /// earlier worker↔UI deadlock can't recur.)</summary>
    public void OnDebuggerStopped()
        => Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(RefreshNow));

    /// <summary>The debugger resumed — drop the stale snapshot; the getters must not run while the
    /// program is free.</summary>
    public void OnDebuggerResumed()
    {
        Grid.ItemsSource = null;
        TxtStatus.Text = "Running — Library State is a point-in-time read. Pause at a source breakpoint, then Refresh.";
    }

    public void RefreshNow()
    {
        var s = _session();
        if (s == null) { Grid.ItemsSource = null; TxtStatus.Text = "Not debugging."; return; }

        var (items, err) = s.ReadLibraryState();
        if (err != null) { Grid.ItemsSource = null; TxtStatus.Text = err; return; }

        var rows = items.Select(it => new LibRow
        {
            Group = it.Group,
            Name = it.Name,
            Value = it.Ok ? Pretty(it) : "<unavailable>",
            Ok = it.Ok,
        }).ToList();

        var view = new ListCollectionView(rows);
        view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(LibRow.Group)));
        Grid.ItemsSource = view;
        TxtStatus.Text = $"Snapshot at the current stop — {rows.Count} values. Discarded on resume.";
    }

    void Refresh_Click(object sender, RoutedEventArgs e) => RefreshNow();

    // Render a raw Clarion DATE (days since 1800-12-28) / TIME (centiseconds since midnight, +1) as a
    // human form alongside the raw serial. Mirrors MainWindow.TryFormatClarionDateTime.
    static string Pretty(DebugSession.LibStateItem it)
    {
        if (!long.TryParse(it.Value, out var n)) return it.Value;
        try
        {
            if (it.Kind == DebugSession.LibKind.Date && n > 0 && n <= 109207)
                return $"{n}  ({new DateTime(1800, 12, 28).AddDays(n):yyyy-MM-dd ddd})";
            if (it.Kind == DebugSession.LibKind.Time)
            {
                long cs = n - 1;
                if (cs >= 0 && cs < 8640000)
                    return $"{n}  ({cs / 360000:D2}:{cs / 6000 % 60:D2}:{cs / 100 % 60:D2}.{cs % 100:D2})";
            }
        }
        catch { /* fall through to raw */ }
        return it.Value;
    }

    sealed class LibRow
    {
        public string Group { get; set; } = "";
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public bool Ok { get; set; }
    }
}
