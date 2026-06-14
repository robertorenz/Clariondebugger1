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
    string? _stickyFrame;          // keep this procedure selected in the call stack across steps
    bool _suppressStackSource;     // re-selecting a frame on stop shouldn't move the source off the execution line
    readonly HashSet<(string Module, int Line)> _breaks = new();

    readonly ObservableCollection<SourceLine> _lines = new();
    readonly ObservableCollection<VarRow> _vars = new();
    readonly ObservableCollection<VarRow> _localsRows = new();
    string _localsFilter = "", _globalsFilter = "";

    static bool FilterMatch(object o, string f) =>
        string.IsNullOrEmpty(f) || (o is VarRow r && r.Name.Contains(f, StringComparison.OrdinalIgnoreCase));

    void TxtLocalsFilter_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    { _localsFilter = TxtLocalsFilter.Text; System.Windows.Data.CollectionViewSource.GetDefaultView(_localsRows).Refresh(); }

    void TxtGlobalsFilter_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    { _globalsFilter = TxtGlobalsFilter.Text; System.Windows.Data.CollectionViewSource.GetDefaultView(_vars).Refresh(); }

    readonly System.Windows.Threading.DispatcherTimer _liveTimer = new() { Interval = TimeSpan.FromMilliseconds(400) };

    public MainWindow()
    {
        InitializeComponent();
        SourceList.ItemsSource = _lines;
        GridVars.ItemsSource = _vars;
        GridLocals.ItemsSource = _localsRows;
        // name filters (collection-view filtering keeps the live refresh working)
        System.Windows.Data.CollectionViewSource.GetDefaultView(_localsRows).Filter = o => FilterMatch(o, _localsFilter);
        System.Windows.Data.CollectionViewSource.GetDefaultView(_vars).Filter = o => FilterMatch(o, _globalsFilter);
        _liveTimer.Tick += (_, _) => RefreshLive();
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
            BuildSourceTypeIndex();   // read declared types from the .clw sources
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

        // rebuild the call stack, keeping the user's selected procedure selected if it's still present
        var rows = info.Stack.Select((f, i) => new FrameRow(i, f)).ToList();
        LstStack.ItemsSource = rows;
        int sel = _stickyFrame != null ? rows.FindIndex(r => r.Frame.Proc == _stickyFrame) : -1;
        _suppressStackSource = true;          // keep the source on the execution line, not the re-selected frame
        LstStack.SelectedIndex = sel >= 0 ? sel : 0;
        _suppressStackSource = false;

        _vars.Clear();
        foreach (var v in info.Globals) _vars.Add(ToRow(v, null));

        Status($"Stopped at line {info.Line}. Press Go to continue.");
    });

    void LstStack_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LstStack.SelectedItem is not FrameRow fr) return;
        var f = fr.Frame;
        _stickyFrame = f.Proc;          // remember the user's choice so steps keep it selected
        TxtLocalsHeader.Text = $"LOCALS — {f.Proc}" + (f.Line is int ln ? $"  ({f.Module}:{ln})" : "");
        _localsRows.Clear();
        foreach (var v in f.Locals) _localsRows.Add(ToRow(v, f.Module));
        // jump the source view to the selected frame's line — but only on an explicit click,
        // not when we re-select the sticky frame on a stop (then the source follows execution)
        if (!_suppressStackSource && f.Module != null && f.Line is int fl)
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

    void Step(Action step, string what)
    {
        if (_state != State.Stopped || _session == null) return;
        ClearCurrentLine(); step(); SetState(State.Running); Status(what + "…");
    }
    void BtnStepOver_Click(object sender, RoutedEventArgs e) => Step(_session!.StepOver, "Step over");
    void BtnStepInto_Click(object sender, RoutedEventArgs e) => Step(_session!.StepInto, "Step into");
    void BtnStepOut_Click(object sender, RoutedEventArgs e) => Step(_session!.StepOut, "Step out");

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
        BtnStepOver.IsEnabled = BtnStepInto.IsEnabled = BtnStepOut.IsEnabled = s == State.Stopped;
        BtnGo.Content = s == State.Stopped ? "▶  Continue  (F5)" : "▶  Go  (F5)";
        if (s == State.Running) _liveTimer.Start(); else _liveTimer.Stop();   // live value refresh
    }

    /// <summary>While running, re-read the selected frame's locals + globals from live memory so
    /// values update without re-breaking (works while the frame is still alive).</summary>
    void RefreshLive()
    {
        if (_state != State.Running || _session == null) return;
        try
        {
            int idx = LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex;
            UpdateRows(_localsRows, _session.RereadFrameLocals(idx));
            UpdateRows(_vars, _session.RereadGlobals());
        }
        catch { }
    }

    static void UpdateRows(ObservableCollection<VarRow> rows, IReadOnlyList<DebugSession.VarValue> vals)
    {
        int n = Math.Min(rows.Count, vals.Count);
        for (int i = 0; i < n; i++)
            if (rows[i].Name == vals[i].Name) { rows[i].Value = vals[i].Display; rows[i].Tip = vals[i].Full; }
    }

    VarRow ToRow(DebugSession.VarValue v, string? module)
    {
        // prefer the exact type as declared in the .clw source; else the engine's inferred type
        string type = LookupDeclType(module, v.Name) ?? v.TypeName;
        return new VarRow
        {
            Name = v.Name, Type = type, Value = v.Display, Address = $"0x{v.Addr:X8}",
            Tip = v.Full, AddrValue = v.Addr, Size = v.Size, Kind = v.Kind
        };
    }

    // ---------- declared types from .clw source ----------
    readonly Dictionary<string, string> _typeByModName = new();          // "MODULE\0NAME" -> declared type
    readonly Dictionary<string, string> _typeByName = new(StringComparer.OrdinalIgnoreCase);

    static readonly HashSet<string> StructuralKw = new(StringComparer.OrdinalIgnoreCase)
    { "PROCEDURE","FUNCTION","ROUTINE","MAP","MODULE","CODE","END","CLASS","INTERFACE",
      "APPLICATION","OMIT","COMPILE","INCLUDE","SECTION","PROGRAM","MEMBER" };

    void BuildSourceTypeIndex()
    {
        _typeByModName.Clear(); _typeByName.Clear();
        if (_info == null) return;
        foreach (var m in _info.Modules)
        {
            var src = ResolveSource(m.Name);
            if (src == null) continue;
            try { ParseDecls(m.Name, File.ReadAllLines(src)); } catch { }
        }
    }

    void ParseDecls(string module, string[] lines)
    {
        string modKey = module.ToUpperInvariant();
        foreach (var line in lines)
        {
            if (line.Length == 0 || char.IsWhiteSpace(line[0]) || line[0] == '!') continue;   // labels start at col 1
            int sp = 0; while (sp < line.Length && !char.IsWhiteSpace(line[sp])) sp++;
            if (sp >= line.Length) continue;
            string label = line[..sp];
            string rest = line[sp..].Trim();
            int bang = FindComment(rest); if (bang >= 0) rest = rest[..bang].Trim();
            if (rest.Length == 0) continue;
            int w = 0; while (w < rest.Length && !char.IsWhiteSpace(rest[w]) && rest[w] != '(' && rest[w] != ',') w++;
            if (StructuralKw.Contains(rest[..w])) continue;          // skip procs/structures/etc.
            string nameUp = label.ToUpperInvariant();
            _typeByModName[modKey + "\0" + nameUp] = rest;
            _typeByName[nameUp] = rest;
        }
    }

    static int FindComment(string s)   // first '!' that isn't inside a string literal
    {
        bool q = false;
        for (int i = 0; i < s.Length; i++) { if (s[i] == '\'') q = !q; else if (s[i] == '!' && !q) return i; }
        return -1;
    }

    string? LookupDeclType(string? module, string name)
    {
        string n = name.ToUpperInvariant();
        if (module != null && _typeByModName.TryGetValue(module.ToUpperInvariant() + "\0" + n, out var t)) return t;
        return _typeByName.TryGetValue(n, out var g) ? g : null;
    }

    // ---------- edit value (write to process memory) ----------
    void GridLocals_DoubleClick(object sender, MouseButtonEventArgs e) => EditRow(GridLocals.SelectedItem as VarRow);
    void GridVars_DoubleClick(object sender, MouseButtonEventArgs e) => EditRow(GridVars.SelectedItem as VarRow);

    void SetValue_Click(object sender, RoutedEventArgs e)
    {
        var grid = ((sender as System.Windows.Controls.MenuItem)?.Parent as System.Windows.Controls.ContextMenu)
                   ?.PlacementTarget as System.Windows.Controls.DataGrid;
        EditRow(grid?.SelectedItem as VarRow);
    }

    // right-click selects the row under the cursor so the context menu targets it
    void Grid_RightDown(object sender, MouseButtonEventArgs e)
    {
        var dep = e.OriginalSource as DependencyObject;
        while (dep != null && dep is not System.Windows.Controls.DataGridRow)
            dep = System.Windows.Media.VisualTreeHelper.GetParent(dep);
        if (dep is System.Windows.Controls.DataGridRow r) r.IsSelected = true;
    }

    void EditRow(VarRow? row)
    {
        if (_session == null) { Log("Start debugging first."); return; }
        if (row == null) return;
        if (row.AddrValue == 0) { Log($"{row.Name}: no writable address."); return; }

        var dlg = new EditValueWindow(row.Name, row.Type, row.AddrValue, row.Value) { Owner = this };
        if (dlg.ShowDialog() != true) return;

        bool ok = _session.WriteVar(row.AddrValue, row.Kind, row.Size, dlg.NewValue);
        Log(ok ? $"Set {row.Name} = {dlg.NewValue} @ 0x{row.AddrValue:X8}"
               : $"Failed to write {row.Name} (check the value format / memory is writable).");
        if (ok)
        {
            var reread = _localsRows.Contains(row)
                ? _session.RereadFrameLocals(LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex)
                : _session.RereadGlobals();
            var nv = reread.FirstOrDefault(x => x.Name == row.Name && x.Addr == row.AddrValue);
            if (nv != null) { row.Value = nv.Display; row.Tip = nv.Full; }
        }
    }

    void Log(string s) { TxtLog.AppendText(s + "\n"); TxtLog.ScrollToEnd(); }
    void Status(string s) => TxtStatus.Text = s;

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.F5: BtnGo_Click(this, new RoutedEventArgs()); e.Handled = true; break;
            case Key.F10: BtnStepOver_Click(this, new RoutedEventArgs()); e.Handled = true; break;
            case Key.F11 when (Keyboard.Modifiers & ModifierKeys.Shift) != 0:
                BtnStepOut_Click(this, new RoutedEventArgs()); e.Handled = true; break;
            case Key.F11: BtnStepInto_Click(this, new RoutedEventArgs()); e.Handled = true; break;
        }
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

public sealed class VarRow : INotifyPropertyChanged
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Address { get; set; } = "";
    public uint AddrValue { get; set; }
    public int Size { get; set; }
    public DebugSession.WriteKind Kind { get; set; }

    string _value = "", _tip = "";
    public string Value { get => _value; set { if (_value != value) { _value = value; Raise(nameof(Value)); } } }
    public string Tip { get => _tip; set { if (_tip != value) { _tip = value; Raise(nameof(Tip)); } } }

    public event PropertyChangedEventHandler? PropertyChanged;
    void Raise(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}
