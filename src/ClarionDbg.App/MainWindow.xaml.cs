using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using ClarionDbg.Engine;
using Microsoft.Win32;

namespace ClarionDbg.App;

public partial class MainWindow : Window
{
    enum State { Idle, Running, Stopped }

    PeImage? _pe;
    TswdInfo? _info;
    DebugSession? _session;
    State _state = State.Idle;
    string? _exePath;
    string? _curModule;
    bool _suppressModuleEvent;
    readonly HashSet<(string Module, int Line)> _breaks = new();

    readonly ObservableCollection<SourceLine> _lines = new();
    readonly ObservableCollection<VarRow> _vars = new();
    readonly ObservableCollection<VarRow> _localsRows = new();

    public MainWindow()
    {
        InitializeComponent();
        SourceList.ItemsSource = _lines;
        GridVars.ItemsSource = _vars;
        GridLocals.ItemsSource = _localsRows;
        Loaded += (_, _) =>
        {
            // optional: open an EXE passed on the command line, else the bundled sample
            var args = Environment.GetCommandLineArgs();
            var target = args.Length > 1 && File.Exists(args[1]) ? args[1]
                       : @"C:\ai\debuger\sample\dbgtest\dbgtest_dbg.exe";
            if (File.Exists(target)) LoadExe(target);
        };
    }

    // ---------- loading ----------
    void BtnOpen_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "Clarion debug EXE (*.exe)|*.exe" };
        if (dlg.ShowDialog() == true) LoadExe(dlg.FileName);
    }

    void LoadExe(string path)
    {
        try
        {
            _exePath = path;
            _breaks.Clear();
            _pe = new PeImage(path);
            _info = TswdInfo.Load(_pe);
            if (_info == null) { Log("No .cwdebug info — this EXE was not built in Debug mode (vid=full)."); return; }

            var withLines = _info.Modules.Where(m => m.Lines.Count > 0).Select(m => m.Name).ToList();
            _suppressModuleEvent = true;
            CmbModule.ItemsSource = withLines;
            _suppressModuleEvent = false;

            _allProcs = _info.Procedures.OrderBy(p => p.Name)
                             .Select(p => new ProcItem(p.Name, p.Rva)).ToList();
            FilterProcs("");
            Log($"Loaded {Path.GetFileName(path)} — {_info.ModuleCount} modules " +
                $"({withLines.Count} with debug lines), {_info.Lines.Count} line entries, " +
                $"{_info.Procedures.Count} procedures.");

            // show the program's primary module
            string primary = !string.IsNullOrEmpty(_info.SourceFile) ? _info.SourceFile : withLines.FirstOrDefault() ?? "";
            CmbModule.SelectedItem = primary;     // triggers ShowModule
            if (_info.ModuleCount == 1 && primary.Equals("dbgtest.clw", StringComparison.OrdinalIgnoreCase))
                ToggleBreak(21);                  // demo breakpoint for the bundled sample
            Status($"Loaded {Path.GetFileName(path)}. Pick a module, set breakpoints, press Go.");
        }
        catch (Exception ex) { Log("Load error: " + ex.Message); }
    }

    void CmbModule_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_suppressModuleEvent) return;
        if (CmbModule.SelectedItem is string name) ShowModule(name);
    }

    void ShowModule(string moduleName)
    {
        _curModule = moduleName;
        string? src = ResolveSource(moduleName);
        TxtSourceName.Text = src ?? "(source file not found)";
        _lines.Clear();
        if (src == null) { Log($"Source not found for {moduleName} (searched exe dir + Clarion libsrc)."); return; }
        int n = 1;
        foreach (var line in File.ReadAllLines(src))
        {
            var sl = new SourceLine { LineNo = n, Text = line.Replace("\t", "    ") };
            sl.HasBreakpoint = _breaks.Contains((moduleName, n));
            _lines.Add(sl);
            n++;
        }
    }

    static readonly string[] SourceSearchDirs =
    {
        @"C:\Clarion12\libsrc\win", @"C:\Clarion1213999\libsrc\win",
        @"C:\Clarion12\accessory\libsrc\win"
    };

    string? ResolveSource(string moduleName)
    {
        var dirs = new List<string>();
        if (_exePath != null)
        {
            var d = Path.GetDirectoryName(_exePath)!;
            dirs.Add(d);
            dirs.Add(Path.GetDirectoryName(d) ?? d);   // project dir often one above the bin
        }
        dirs.AddRange(SourceSearchDirs);
        foreach (var dir in dirs)
        {
            var p = Path.Combine(dir, moduleName);
            if (File.Exists(p)) return p;
        }
        return null;
    }

    // ---------- breakpoints ----------
    void Gutter_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is SourceLine sl) ToggleBreak(sl.LineNo);
    }

    void ToggleBreak(int clicked)
    {
        if (_curModule == null || _info == null) return;
        // snap to the nearest line that actually has executable code in this module
        int line = _info.NearestCodeLine(_curModule, clicked) ?? clicked;
        var key = (_curModule, line);
        var sl = _lines.FirstOrDefault(l => l.LineNo == line);
        if (_breaks.Remove(key))
        {
            if (sl != null) sl.HasBreakpoint = false;
            Log($"Breakpoint cleared at {_curModule}:{line}.");
        }
        else
        {
            _breaks.Add(key);
            if (sl != null) sl.HasBreakpoint = true;
            Log(line == clicked
                ? $"Breakpoint set at {_curModule}:{line}."
                : $"Breakpoint set at {_curModule}:{line} (no code on line {clicked}; moved to nearest).");
        }
    }

    // ---------- run control ----------
    void BtnGo_Click(object sender, RoutedEventArgs e)
    {
        if (_state == State.Stopped) { ClearCurrentLine(); _session!.Continue(); SetState(State.Running); Status("Running…"); return; }
        if (_state == State.Running) return;
        if (_pe == null || _info == null || _exePath == null) { Log("Open a debug EXE first."); return; }

        if (_breaks.Count == 0) { Log("Set at least one breakpoint (click the gutter)."); return; }

        _vars.Clear(); _localsRows.Clear(); LstStack.ItemsSource = null;
        _session = new DebugSession(_exePath, _pe, _info);
        _session.Log += s => Dispatcher.Invoke(() => Log(s));
        _session.Stopped += OnStopped;
        _session.Exited += code => Dispatcher.Invoke(() =>
        {
            Log($"--- debuggee exited (code {code}) ---");
            ClearCurrentLine(); SetState(State.Idle); Status("Exited.");
        });
        _session.Start(_breaks.Select(b => new DebugSession.Breakpoint(b.Module, b.Line)));
        SetState(State.Running);
        Status("Running…");
    }

    void OnStopped(DebugSession.StopInfo info) => Dispatcher.Invoke(() =>
    {
        SetState(State.Stopped);
        Log($"Stopped: {info.Reason} at {info.Module}:{info.Line} (EIP 0x{info.Eip:X8})");

        // switch the source view to the module we stopped in
        if (info.Module != null && info.Module != _curModule)
        {
            _suppressModuleEvent = true;
            CmbModule.SelectedItem = info.Module;
            _suppressModuleEvent = false;
            ShowModule(info.Module);
        }

        ClearCurrentLine();
        if (info.Line is int line)
        {
            var sl = _lines.FirstOrDefault(x => x.LineNo == line);
            if (sl != null) { sl.IsCurrent = true; SourceList.UpdateLayout();
                ((FrameworkElement?)SourceList.ItemContainerGenerator.ContainerFromItem(sl))?.BringIntoView(); }
        }

        LstStack.ItemsSource = info.Stack.Select((f, i) => new FrameRow(i, f)).ToList();
        LstStack.SelectedIndex = 0;   // triggers ShowFrameLocals for the innermost frame

        _vars.Clear();
        foreach (var v in info.Globals)
            _vars.Add(new VarRow { Name = v.Name, Type = v.TypeName, Value = v.Display, Address = $"0x{v.Addr:X8}", Tip = v.Full });

        Status($"Stopped at line {info.Line}. Press Go to continue.");
    });

    void LstStack_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LstStack.SelectedItem is not FrameRow fr) return;
        var f = fr.Frame;
        TxtLocalsHeader.Text = $"LOCALS — {f.Proc}" + (f.Line is int ln ? $"  ({f.Module}:{ln})" : "");
        _localsRows.Clear();
        foreach (var v in f.Locals)
            _localsRows.Add(new VarRow { Name = v.Name, Type = v.TypeName, Value = v.Display, Address = $"0x{v.Addr:X8}", Tip = v.Full });
        // jump the source view to the selected frame's line
        if (f.Module != null && f.Line is int fl)
        {
            if (f.Module != _curModule)
            {
                _suppressModuleEvent = true; CmbModule.SelectedItem = f.Module; _suppressModuleEvent = false;
                ShowModule(f.Module);
            }
            ClearCurrentLine();
            var sl = _lines.FirstOrDefault(x => x.LineNo == fl);
            if (sl != null) { sl.IsCurrent = true; SourceList.UpdateLayout();
                ((FrameworkElement?)SourceList.ItemContainerGenerator.ContainerFromItem(sl))?.BringIntoView(); }
        }
    }

    void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        _session?.Terminate();
        ClearCurrentLine(); SetState(State.Idle); Status("Stopped.");
    }

    List<ProcItem> _allProcs = new();

    void FilterProcs(string text)
    {
        IEnumerable<ProcItem> items = _allProcs;
        if (!string.IsNullOrWhiteSpace(text))
            items = _allProcs.Where(p => p.Name.Contains(text, StringComparison.OrdinalIgnoreCase));
        LstProcs.ItemsSource = items.Take(500).ToList();
    }

    void TxtProcFilter_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        => FilterProcs(TxtProcFilter.Text);

    void LstProcs_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_info == null || LstProcs.SelectedItem is not ProcItem p) return;
        var loc = _info.Locate(p.Rva);   // entry RVA -> (module, line)
        if (loc is not { } l) { Log($"{p.Name}: no source line for entry 0x{p.Rva:X}."); return; }
        if (l.Module != _curModule)
        {
            _suppressModuleEvent = true;
            CmbModule.SelectedItem = l.Module;
            _suppressModuleEvent = false;
            ShowModule(l.Module);
        }
        var sl = _lines.FirstOrDefault(x => x.LineNo == l.Line);
        if (sl != null)
        {
            SourceList.UpdateLayout();
            ((FrameworkElement?)SourceList.ItemContainerGenerator.ContainerFromItem(sl))?.BringIntoView();
        }
        Status($"{p.Name} → {l.Module}:{l.Line}. Click the gutter there to set a breakpoint.");
    }

    // ---------- helpers ----------
    void ClearCurrentLine() { foreach (var l in _lines) if (l.IsCurrent) l.IsCurrent = false; }

    void SetState(State s)
    {
        _state = s;
        BtnGo.IsEnabled = s != State.Running;
        BtnStop.IsEnabled = s != State.Idle;
        BtnGo.Content = s == State.Stopped ? "▶  Continue  (F5)" : "▶  Go  (F5)";
    }

    void Log(string s) { TxtLog.AppendText(s + "\n"); TxtLog.ScrollToEnd(); }
    void Status(string s) => TxtStatus.Text = s;

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.F5) { BtnGo_Click(this, new RoutedEventArgs()); e.Handled = true; }
        base.OnKeyDown(e);
    }
}

public sealed class SourceLine : INotifyPropertyChanged
{
    public int LineNo { get; set; }
    public string Text { get; set; } = "";

    bool _bp, _cur;
    public bool HasBreakpoint { get => _bp; set { _bp = value; Raise(nameof(BpVisibility)); } }
    public bool IsCurrent { get => _cur; set { _cur = value; Raise(nameof(RowBg)); } }

    public Visibility BpVisibility => _bp ? Visibility.Visible : Visibility.Collapsed;
    public Brush RowBg => _cur ? (Brush)System.Windows.Application.Current.Resources["CurLine"]
                               : Brushes.Transparent;

    public event PropertyChangedEventHandler? PropertyChanged;
    void Raise(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}

public sealed class FrameRow
{
    public DebugSession.Frame Frame { get; }
    readonly int _i;
    public FrameRow(int i, DebugSession.Frame f) { _i = i; Frame = f; }
    public override string ToString() =>
        $"#{_i} {Frame.Proc}  0x{Frame.Addr:X8}" + (Frame.Line is int l ? $"  {Frame.Module}:{l}" : "");
}

public sealed class ProcItem
{
    public string Name { get; }
    public uint Rva { get; }
    public ProcItem(string name, uint rva) { Name = name; Rva = rva; }
    public override string ToString() => $"{Name}  @0x{Rva:X}";
}

public sealed class VarRow
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string Address { get; set; } = "";
    public string Tip { get; set; } = "";
}
