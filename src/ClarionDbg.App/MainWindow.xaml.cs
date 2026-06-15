using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
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

    // ---- multi-DLL: the EXE plus any sibling Clarion debug DLLs, and the source-module catalog ----
    sealed record LoadedImage(string Path, string Name, PeImage Pe, TswdInfo Info);
    readonly List<LoadedImage> _images = new();                                   // EXE first, then debug DLLs
    readonly Dictionary<string, (TswdInfo Info, string Image)> _modOwners = new(StringComparer.OrdinalIgnoreCase); // .clw -> owning blob
    readonly List<string> _moduleNames = new();                                   // every source module, EXE modules first
    readonly List<string> _siblingDlls = new();                                   // debug DLL paths to PreloadModule onto the session

    /// <summary>The TSWD blob that owns a source module (the EXE's, a DLL's, or the EXE as fallback).</summary>
    TswdInfo? InfoFor(string? module)
        => module != null && _modOwners.TryGetValue(module, out var ms) ? ms.Info : _info;
    bool _suppressModuleEvent;
    string? _stickyFrame;          // keep this procedure selected in the call stack across steps
    bool _suppressStackSource;     // re-selecting a frame on stop shouldn't move the source off the execution line
    bool _suppressThreadEvent;     // populating the thread combo on stop shouldn't trigger a switch
    readonly ObservableCollection<DebugSession.Breakpoint> _bps = new();   // master breakpoint list
    DebugSession.Breakpoint? LineBp(string module, int line) =>
        _bps.FirstOrDefault(b => b.Label == null && b.Module == module && b.Line == line);

    readonly ObservableCollection<SourceLine> _lines = new();
    readonly ObservableCollection<VarRow> _vars = new();
    readonly ObservableCollection<VarRow> _localsRows = new();
    readonly ObservableCollection<VarRow> _watch = new();
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
        GridWatch.ItemsSource = _watch;
        // name filters (collection-view filtering keeps the live refresh working)
        System.Windows.Data.CollectionViewSource.GetDefaultView(_localsRows).Filter = o => FilterMatch(o, _localsFilter);
        System.Windows.Data.CollectionViewSource.GetDefaultView(_vars).Filter = o => FilterMatch(o, _globalsFilter);
        _liveTimer.Tick += (_, _) => RefreshLive();
        _pickTimer.Tick += (_, _) => PickThreadTick();
        LoadRecent();
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
            _bps.Clear();
            _pe = new PeImage(path);
            _info = TswdInfo.Load(_pe);
            if (_info == null) { Log("No .cwdebug info — this EXE was not built in Debug mode (vid=full)."); return; }

            DiscoverImages(path);     // EXE + sibling Clarion debug DLLs -> _images / _modOwners / _moduleNames

            _suppressModuleEvent = true;
            CmbModule.ItemsSource = _moduleNames.ToList();
            _suppressModuleEvent = false;

            _allProcs = _images.SelectMany(img => img.Info.Procedures
                                   .Select(p => new ProcItem(p.Name, p.Rva, img.Info, img.Name)))
                               .OrderBy(p => p.Name).ToList();
            BuildProcCategories();    // populate the kind pulldown (sets _procGroup = null)
            FilterProcs("");
            BuildSourceTypeIndex();   // read declared types from the .clw sources
            int dlls = _images.Count - 1;
            Log($"Loaded {Path.GetFileName(path)} — {_images.Count} image(s)" +
                (dlls > 0 ? $" (EXE + {dlls} debug DLL(s): {string.Join(", ", _siblingDlls.Select(Path.GetFileName))})" : "") +
                $", {_moduleNames.Count} source modules, {_allProcs.Count} procedures.");

            AddRecent(path);
            LoadBreakpoints();   // restore saved breakpoints for this EXE

            // show the program's primary module
            string primary = !string.IsNullOrEmpty(_info.SourceFile) ? _info.SourceFile : _moduleNames.FirstOrDefault() ?? "";
            CmbModule.SelectedItem = primary;     // triggers ShowModule
            if (_bps.Count == 0 && _info.ModuleCount == 1 && primary.Equals("dbgtest.clw", StringComparison.OrdinalIgnoreCase))
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

    /// <summary>Build the image set and source-module catalog: the EXE (module 0) plus every sibling
    /// Clarion <em>debug</em> DLL in the EXE's directory. A debug DLL is one whose PE carries a TSWD
    /// blob; the Clarion runtime (ClaRUN) and non-debug DLLs are skipped here (the engine still
    /// discovers and attributes them at runtime). EXE modules win any name collision.</summary>
    void DiscoverImages(string exePath)
    {
        _images.Clear(); _modOwners.Clear(); _moduleNames.Clear(); _siblingDlls.Clear();
        _images.Add(new LoadedImage(exePath, Path.GetFileName(exePath), _pe!, _info!));

        var dir = Path.GetDirectoryName(Path.GetFullPath(exePath));
        if (dir != null && Directory.Exists(dir))
            foreach (var dll in Directory.EnumerateFiles(dir, "*.dll"))
            {
                var name = Path.GetFileName(dll);
                if (name.StartsWith("clarun", StringComparison.OrdinalIgnoreCase)) continue;  // the runtime, not user code
                try
                {
                    var pe = PeImage.TryLoad(dll);
                    var info = pe != null ? TswdInfo.Load(pe) : null;
                    if (info == null) continue;     // not a Clarion debug DLL
                    _images.Add(new LoadedImage(dll, name, pe!, info));
                    _siblingDlls.Add(dll);
                }
                catch { /* unreadable DLL — skip */ }
            }

        foreach (var img in _images)
            foreach (var m in img.Info.Modules)
                if (m.Lines.Count > 0 && _modOwners.TryAdd(m.Name, (img.Info, img.Name)))
                    _moduleNames.Add(m.Name);
    }

    void ShowModule(string moduleName)
    {
        _curModule = moduleName;
        string? src = ResolveSource(moduleName);
        string? img = _modOwners.TryGetValue(moduleName, out var ms) ? ms.Image : null;
        bool fromDll = img != null && !string.Equals(img, Path.GetFileName(_exePath), StringComparison.OrdinalIgnoreCase);
        TxtSourceName.Text = (src ?? "(source file not found)") + (fromDll ? $"   [{img}]" : "");
        _lines.Clear();
        if (src == null) { Log($"Source not found for {moduleName} (searched exe dir + Clarion libsrc)."); return; }
        int n = 1;
        foreach (var line in File.ReadAllLines(src))
        {
            var sl = new SourceLine { LineNo = n, Text = line.Replace("\t", "    ") };
            sl.HasBreakpoint = LineBp(moduleName, n) != null;
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
        int line = (InfoFor(_curModule) ?? _info).NearestCodeLine(_curModule, clicked) ?? clicked;
        var sl = _lines.FirstOrDefault(l => l.LineNo == line);
        var existing = LineBp(_curModule, line);
        if (existing != null)
        {
            _bps.Remove(existing);
            _session?.RemoveBreakpointLive(existing);
            if (sl != null) sl.HasBreakpoint = false;
            Log($"Breakpoint cleared at {_curModule}:{line}.");
        }
        else
        {
            var bp = new DebugSession.Breakpoint(_curModule, line);
            _bps.Add(bp);
            _session?.AddBreakpointLive(bp);
            if (sl != null) sl.HasBreakpoint = true;
            Log(line == clicked
                ? $"Breakpoint set at {_curModule}:{line}."
                : $"Breakpoint set at {_curModule}:{line} (no code on line {clicked}; moved to nearest).");
        }
        SaveBreakpoints();
    }

    // ---------- run-to-cursor & break-on-procedure-entry ----------
    static SourceLine? MenuLine(object sender) =>
        (sender as FrameworkElement)?.DataContext as SourceLine;

    void RunToCursor_Click(object sender, RoutedEventArgs e)
    {
        if (_curModule == null) return;
        if (_state != State.Stopped || _session == null) { Status("Run to cursor needs a stopped program."); return; }
        if (MenuLine(sender) is not SourceLine sl) return;
        int line = InfoFor(_curModule)?.NearestCodeLine(_curModule, sl.LineNo) ?? sl.LineNo;
        ClearCurrentLine();
        _session.RunTo(_curModule, line);
        SetState(State.Running);
        Status($"Running to {_curModule}:{line}…");
    }

    void ToggleBreakMenu_Click(object sender, RoutedEventArgs e)
    {
        if (MenuLine(sender) is SourceLine sl) ToggleBreak(sl.LineNo);
    }

    void BreakOnProcEntry_Click(object sender, RoutedEventArgs e)
    {
        if (LstProcs.SelectedItem is not ProcItem p || _info == null) return;
        string label = $"⊕ {p.Name}";
        if (_bps.Any(b => b.Label == label)) { Status($"Already breaking on {p.Name}."); return; }
        var info = p.Info ?? _info;
        bool isExe = info == _info;
        var loc = info.Locate(p.Rva);                  // entry RVA -> (module, line) in the proc's own image
        // The engine resolves a raw Rva against the EXE only, so a DLL proc-entry must be expressed as
        // module:line (resolved against the owning DLL's TSWD when it maps).
        DebugSession.Breakpoint bp;
        if (isExe)
            bp = new DebugSession.Breakpoint { Rva = p.Rva, Label = label };
        else if (loc is { } dl)
            bp = new DebugSession.Breakpoint(dl.Module, dl.Line) { Label = label };
        else { Status($"{p.Name}: no source line for its entry in {p.Image}."); return; }
        if (loc != null) { bp.Module = loc.Value.Module; bp.Line = loc.Value.Line; }
        _bps.Add(bp);
        _session?.AddBreakpointLive(bp);
        SaveBreakpoints();
        Log($"Break on entry of {p.Name} (0x{p.Rva:X8}).");
        Status($"Will break when {p.Name} is entered.");
    }

    void BtnDisasm_Click(object sender, RoutedEventArgs e)
    {
        if (_session == null) { Status("Start debugging first."); return; }
        new DisassemblyWindow(_session) { Owner = this }.Show();
    }

    // ---------- breakpoint manager ----------
    void BtnBreakpoints_Click(object sender, RoutedEventArgs e)
    {
        var win = new BreakpointsWindow(_bps, _session) { Owner = this };
        win.ShowDialog();
        // reflect any gutter changes for the current module after edits/removals
        if (_curModule != null)
            foreach (var sl in _lines) sl.HasBreakpoint = LineBp(_curModule, sl.LineNo) != null;
        SaveBreakpoints();
    }

    // ---------- persistence (per-EXE, under %APPDATA%\ClarionDbg\breakpoints) ----------
    sealed class BpDto
    {
        public string? Module { get; set; }
        public int Line { get; set; }
        public uint Rva { get; set; }
        public bool Enabled { get; set; } = true;
        public string? Condition { get; set; }
        public string? HitCondition { get; set; }
        public string? LogMessage { get; set; }
        public string? Label { get; set; }
    }

    string BpStorePath()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                               "ClarionDbg", "breakpoints");
        Directory.CreateDirectory(dir);
        string key = Path.GetFileNameWithoutExtension(_exePath ?? "x") + "_" +
                     (uint)(_exePath ?? "").ToLowerInvariant().GetHashCode();
        return Path.Combine(dir, key + ".json");
    }

    void SaveBreakpoints()
    {
        if (_exePath == null) return;
        try
        {
            var dto = _bps.Select(b => new BpDto
            {
                Module = b.Module, Line = b.Line, Rva = b.Rva, Enabled = b.Enabled,
                Condition = b.Condition, HitCondition = b.HitCondition, LogMessage = b.LogMessage, Label = b.Label
            }).ToList();
            File.WriteAllText(BpStorePath(), System.Text.Json.JsonSerializer.Serialize(dto));
        }
        catch { /* best effort */ }
    }

    void LoadBreakpoints()
    {
        try
        {
            var path = BpStorePath();
            if (!File.Exists(path)) return;
            var dto = System.Text.Json.JsonSerializer.Deserialize<List<BpDto>>(File.ReadAllText(path));
            if (dto == null) return;
            foreach (var d in dto)
                _bps.Add(new DebugSession.Breakpoint
                {
                    Module = d.Module, Line = d.Line, Rva = d.Rva, Enabled = d.Enabled,
                    Condition = d.Condition, HitCondition = d.HitCondition, LogMessage = d.LogMessage, Label = d.Label
                });
            if (_bps.Count > 0) Log($"Restored {_bps.Count} saved breakpoint(s).");
        }
        catch { /* ignore corrupt store */ }
    }

    // ---------- run control ----------
    void BtnGo_Click(object sender, RoutedEventArgs e)
    {
        if (_state == State.Stopped) { ClearCurrentLine(); _session!.Continue(); SetState(State.Running); Status("Running…"); return; }
        if (_state == State.Running) return;
        if (_pe == null || _info == null || _exePath == null) { Log("Open a debug EXE first."); return; }

        if (_bps.Count == 0) { Log("Set at least one breakpoint (click the gutter)."); return; }

        _vars.Clear(); _localsRows.Clear(); LstStack.ItemsSource = null;
        _session = new DebugSession(_exePath, _pe, _info) { BreakOnException = ChkBreakCrash.IsChecked == true };
        foreach (var dll in _siblingDlls) _session.PreloadModule(dll);   // so DLL breakpoints resolve before launch
        _session.Log += s => Dispatcher.Invoke(() => Log(s));
        _session.Stopped += OnStopped;
        _session.Exited += code => Dispatcher.Invoke(() =>
        {
            Log($"--- debuggee exited (code {code}) ---");
            ClearCurrentLine(); SetState(State.Idle); Status("Exited.");
        });
        foreach (var b in _bps) b.HitCount = 0;
        _session.Start(_bps.ToList());
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

        // thread list — mark the stopped thread, let the user switch to inspect another stack
        _suppressThreadEvent = true;
        CmbThreads.ItemsSource = info.Threads;
        CmbThreads.DisplayMemberPath = nameof(DebugSession.ThreadRef.Label);
        var cur = info.Threads.FirstOrDefault(t => t.Tid == info.Tid);
        CmbThreads.SelectedItem = cur ?? info.Threads.FirstOrDefault();
        _suppressThreadEvent = false;

        // rebuild the call stack, keeping the user's selected procedure selected if it's still present
        ShowStack(info.Stack);

        _vars.Clear();
        foreach (var v in info.Globals) _vars.Add(ToRow(v, null));

        RefreshWatch(LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex);

        Status($"Stopped at line {info.Line}. Press Go to continue.");
    });

    /// <summary>Populate the call-stack list from a set of frames, restoring the sticky selection.</summary>
    void ShowStack(IReadOnlyList<DebugSession.Frame> frames)
    {
        var rows = frames.Select((f, i) => new FrameRow(i, f)).ToList();
        LstStack.ItemsSource = rows;
        int sel = _stickyFrame != null ? rows.FindIndex(r => r.Frame.Proc == _stickyFrame) : -1;
        _suppressStackSource = true;          // keep the source on the execution line, not the re-selected frame
        LstStack.SelectedIndex = sel >= 0 ? sel : 0;
        _suppressStackSource = false;
    }

    void CmbThreads_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_suppressThreadEvent || _session == null) return;
        if (CmbThreads.SelectedItem is not DebugSession.ThreadRef tr) return;
        var frames = _session.SwitchThread(tr.Tid);
        if (frames.Count == 0) { Status($"Thread {tr.Tid}: no readable stack."); return; }
        ShowStack(frames);
        Status($"Showing thread {tr.Tid}.");
    }

    void LstStack_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LstStack.SelectedItem is not FrameRow fr) return;
        var f = fr.Frame;
        _stickyFrame = f.Proc;          // remember the user's choice so steps keep it selected
        TxtLocalsHeader.Text = $"LOCALS — {f.Proc}" + (f.Line is int ln ? $"  ({f.Module}:{ln})" : "");
        _localsRows.Clear();
        foreach (var v in f.Locals) _localsRows.Add(ToRow(v, f.Module));
        RefreshWatch(LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex);   // watches follow the selected frame
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

    void BtnPause_Click(object sender, RoutedEventArgs e)
    {
        if (_state != State.Running || _session == null) { Status("Nothing running to pause."); return; }
        _session.Pause();
        Status("Pausing…");   // the Stopped event arrives once the target breaks into Clarion code
    }

    void ChkBreakCrash_Changed(object sender, RoutedEventArgs e)
    { if (_session != null) _session.BreakOnException = ChkBreakCrash.IsChecked == true; }

    void Step(Action step, string what)
    {
        if (_state != State.Stopped || _session == null) return;
        ClearCurrentLine(); step(); SetState(State.Running); Status(what + "…");
    }
    void BtnStepOver_Click(object sender, RoutedEventArgs e) => Step(_session!.StepOver, "Step over");
    void BtnStepInto_Click(object sender, RoutedEventArgs e) => Step(_session!.StepInto, "Step into");
    void BtnStepOut_Click(object sender, RoutedEventArgs e) => Step(_session!.StepOut, "Step out");

    List<ProcItem> _allProcs = new();
    string? _procGroup;            // null = all kinds
    bool _suppressCatEvent;

    const string KeyLocal = "\x01Local";       // aggregate: ThisWindow/ThisReport/... methods
    const string KeyClasses = "\x01Classes";   // aggregate: all other (ABC/library) class methods
    static bool IsLocalClass(string g) => g.StartsWith("THIS", StringComparison.OrdinalIgnoreCase);

    void FilterProcs(string text)
    {
        IEnumerable<ProcItem> items = _allProcs;
        if (_procGroup != null)
            items = _procGroup switch
            {
                KeyLocal => items.Where(p => IsLocalClass(p.Group)),
                KeyClasses => items.Where(p => p.Group != ProcItem.App && p.Group != ProcItem.Runtime && !IsLocalClass(p.Group)),
                _ => items.Where(p => p.Group == _procGroup)
            };
        if (!string.IsNullOrWhiteSpace(text))
            items = items.Where(p => p.Name.Contains(text, StringComparison.OrdinalIgnoreCase));
        LstProcs.ItemsSource = items.Take(1000).ToList();
    }

    void TxtProcFilter_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        => FilterProcs(TxtProcFilter.Text);

    // pulldown of procedure kinds, built from what's actually in the app (App / each class / runtime)
    sealed class CatItem
    {
        public string? Key { get; }
        readonly string _label; readonly int _count;
        public CatItem(string label, string? key, int count) { _label = label; Key = key; _count = count; }
        public override string ToString() => $"{_label}  ({_count})";
    }

    void BuildProcCategories()
    {
        var counts = _allProcs.GroupBy(p => p.Group).ToDictionary(g => g.Key, g => g.Count());
        int total = _allProcs.Count;
        int app = counts.GetValueOrDefault(ProcItem.App);
        int rt = counts.GetValueOrDefault(ProcItem.Runtime);
        int local = _allProcs.Count(p => IsLocalClass(p.Group));
        int other = total - app - rt - local;

        // aggregate filters first, then a drill-down entry per class (sorted by count)
        var items = new List<CatItem> { new("All procedures", null, total) };
        if (app > 0) items.Add(new("Global procedures (yours)", ProcItem.App, app));
        if (local > 0) items.Add(new("Local methods (ThisWindow/Report)", KeyLocal, local));
        if (other > 0) items.Add(new("Other class methods (ABC)", KeyClasses, other));
        if (rt > 0) items.Add(new("Routines / thunks", ProcItem.Runtime, rt));
        foreach (var kv in counts.Where(kv => kv.Key != ProcItem.App && kv.Key != ProcItem.Runtime)
                                  .OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key))
            items.Add(new("   " + kv.Key, kv.Key, kv.Value));

        _suppressCatEvent = true;
        CmbProcCat.ItemsSource = items;
        CmbProcCat.SelectedIndex = 0;
        _suppressCatEvent = false;
        _procGroup = null;
    }

    void CmbProcCat_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_suppressCatEvent) return;
        _procGroup = (CmbProcCat.SelectedItem as CatItem)?.Key;
        FilterProcs(TxtProcFilter.Text);
    }

    void LstProcs_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_info == null || LstProcs.SelectedItem is not ProcItem p) return;
        var loc = (p.Info ?? _info).Locate(p.Rva);   // entry RVA -> (module, line) in the proc's own image
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

    // ---------- source data tips (hover a variable to see its live value) ----------
    // A Popup (not a ToolTip) is used deliberately: WPF only shows ToolTips via its own hover
    // timer, so toggling ToolTip.IsOpen from code is unreliable. A Popup shows on demand.
    System.Windows.Controls.Primitives.Popup? _dataPopup;
    double _srcCharWidth;
    string? _dataTipWord;

    // width of one character in the source font; the source view is monospace (Consolas 13),
    // so column-under-cursor = mouseX / charWidth is exact.
    double SourceCharWidth()
    {
        if (_srcCharWidth > 0) return _srcCharWidth;
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var ft = new System.Windows.Media.FormattedText(new string('0', 20),
            System.Globalization.CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            new Typeface("Consolas"), 13, Brushes.Black, dpi);
        _srcCharWidth = ft.WidthIncludingTrailingWhitespace / 20.0;
        return _srcCharWidth;
    }

    static bool IsIdentChar(char c) => char.IsLetterOrDigit(c) || c is '_' or ':' or '.';

    // extract the Clarion identifier (incl. LOC:Name / Que.Field) under the given column
    static string? WordAt(string text, int col)
    {
        if (col < 0 || col >= text.Length || !IsIdentChar(text[col])) return null;
        int s = col, e = col;
        while (s > 0 && IsIdentChar(text[s - 1])) s--;
        while (e < text.Length - 1 && IsIdentChar(text[e + 1])) e++;
        var w = text.Substring(s, e - s + 1).Trim('.', ':');
        return w.Length > 0 && !char.IsDigit(w[0]) ? w : null;
    }

    void SourceText_MouseMove(object sender, MouseEventArgs e)
    {
        if (sender is not System.Windows.Controls.TextBlock tb || tb.DataContext is not SourceLine sl)
        { HideDataTip(); return; }

        var pos = e.GetPosition(tb);
        int col = (int)(pos.X / SourceCharWidth());
        var word = WordAt(sl.Text, col);
        if (word == null) { HideDataTip(); return; }
        if (word == _dataTipWord && _dataPopup?.IsOpen == true) return;   // already showing this word

        // 1) live variable value — needs a running/stopped session and the right frame
        if (_session != null && _state != State.Idle)
        {
            int frame = LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex;
            DebugSession.VarValue? v;
            try { v = _session.EvalWatch(word, frame); } catch { v = null; }
            if (v != null && v.Display is not ("<not found>" or "<error>"))
            {
                _dataTipWord = word;
                string type = LookupDeclType(_curModule, v.Name) ?? v.TypeName;
                string body = v.Display, extra = v.Full;
                if (TryFormatClarionDateTime(type, v.Display, out var pretty))
                    body = $"{pretty}   (raw {v.Display})";
                else if (body.StartsWith("{") && body.EndsWith("}"))   // a GROUP / record — list fields by line
                { body = FormatGroupMultiline(body); extra = ""; }
                ShowDataTip(tb, pos, word, type, body, extra);
                return;
            }
        }

        // 2) EQUATE constant — compile-time, so it shows even before the program runs
        if (TryEquate(word, out var evalue, out var efull))
        {
            _dataTipWord = word;
            ShowDataTip(tb, pos, word, "EQUATE", evalue, efull);
            return;
        }

        HideDataTip();
    }

    /// <summary>Resolve a word to an EQUATE constant declared in the source (incl. INCLUDE files).</summary>
    bool TryEquate(string word, out string value, out string full)
    {
        value = ""; full = "";
        var decl = LookupDeclType(_curModule, word);
        if (decl == null) return false;
        var m = System.Text.RegularExpressions.Regex.Match(decl, @"^EQUATE\s*\(\s*(.*?)\s*\)\s*$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (!m.Success) return false;
        string raw = m.Groups[1].Value.Trim();
        value = raw.Length == 0 ? "(empty)" : raw;
        if (TryClarionNumber(raw, out long num) && num.ToString() != raw)
            full = $"=  {num}  (decimal)";
        return true;
    }

    /// <summary>Parse a Clarion numeric literal: decimal, hex (<c>0FFh</c>), binary (<c>101b</c>), octal (<c>17o</c>).</summary>
    static bool TryClarionNumber(string s, out long n)
    {
        n = 0; s = s.Trim();
        if (s.Length == 0) return false;
        try
        {
            char suf = char.ToLowerInvariant(s[^1]);
            string body = s[..^1];
            if (suf == 'h' && body.Length > 0) { n = Convert.ToInt64(body, 16); return true; }
            if (suf == 'b' && body.Length > 0 && body.All(c => c is '0' or '1')) { n = Convert.ToInt64(body, 2); return true; }
            if (suf == 'o' && body.Length > 0 && body.All(c => c is >= '0' and <= '7')) { n = Convert.ToInt64(body, 8); return true; }
            return long.TryParse(s, out n);
        }
        catch { return false; }
    }

    void SourceText_MouseLeave(object sender, MouseEventArgs e) => HideDataTip();

    /// <summary>Turn a group dump "{a=1, b='x', sub={c=2}}" into one "a = 1" line per top-level field.</summary>
    static string FormatGroupMultiline(string s)
    {
        if (s.Length < 2) return s;
        string inner = s[1..^1];
        var sb = new StringBuilder();
        int depth = 0, start = 0; bool q = false;
        void Emit(int end)
        {
            var part = inner[start..end].Trim();
            if (part.Length == 0) return;
            int eq = part.IndexOf('=');
            if (sb.Length > 0) sb.Append('\n');
            sb.Append(eq > 0 ? $"{part[..eq].Trim()}  =  {part[(eq + 1)..].Trim()}" : part);
        }
        for (int i = 0; i < inner.Length; i++)
        {
            char c = inner[i];
            if (c == '\'') q = !q;
            else if (!q && c == '{') depth++;
            else if (!q && c == '}') depth--;
            else if (!q && depth == 0 && c == ',') { Emit(i); start = i + 1; }
        }
        Emit(inner.Length);
        return sb.ToString();
    }

    void ShowDataTip(System.Windows.Controls.TextBlock anchor, Point at, string name, string type, string value, string full)
    {
        var fg  = (Brush)(TryFindResource("Fg") ?? Brushes.White);
        var dim = (Brush)(TryFindResource("FgDim") ?? Brushes.Gray);
        var border = (Brush)(TryFindResource("Border") ?? Brushes.Gray);

        var panel = new System.Windows.Controls.StackPanel();
        panel.Children.Add(new System.Windows.Controls.TextBlock
        { Text = $"{name}  :  {type}", Foreground = dim, FontFamily = new FontFamily("Consolas"), FontSize = 11 });
        panel.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = value, Foreground = fg, FontFamily = new FontFamily("Consolas"), FontSize = 14,
            FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, MaxWidth = 520
        });
        if (!string.IsNullOrEmpty(full) && full != value && !full.StartsWith(value))
            panel.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = full, Foreground = dim, FontFamily = new FontFamily("Consolas"), FontSize = 11,
                TextWrapping = TextWrapping.Wrap, MaxWidth = 520, Margin = new Thickness(0, 3, 0, 0)
            });

        _dataPopup ??= new System.Windows.Controls.Primitives.Popup
        {
            AllowsTransparency = true,
            Placement = System.Windows.Controls.Primitives.PlacementMode.Relative,
            StaysOpen = true
        };
        _dataPopup.Child = new System.Windows.Controls.Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x1E)),
            BorderBrush = border, BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 5, 8, 5), Child = panel
        };
        _dataPopup.PlacementTarget = anchor;
        _dataPopup.HorizontalOffset = at.X;
        _dataPopup.VerticalOffset = at.Y + 18;     // drop just below the hovered word
        _dataPopup.IsOpen = false;                 // toggle forces a reposition at the new spot
        _dataPopup.IsOpen = true;
    }

    void HideDataTip()
    {
        if (_dataPopup != null) _dataPopup.IsOpen = false;
        _dataTipWord = null;
    }

    // ---------- identify which debuggee thread owns the window under the cursor ----------
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int X, Y; }
    [DllImport("user32.dll")] static extern bool GetCursorPos(out POINT p);
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(POINT p);
    [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr hWnd, uint flags);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hWnd, StringBuilder s, int max);
    const uint GA_ROOT = 2;

    readonly System.Windows.Threading.DispatcherTimer _pickTimer =
        new() { Interval = TimeSpan.FromMilliseconds(150) };

    void BtnPickThread_Click(object sender, RoutedEventArgs e)
    {
        if (BtnPickThread.IsChecked == true)
        {
            if (_session == null || _session.Pid == 0)
            { BtnPickThread.IsChecked = false; Status("Start (or attach to) the program first."); return; }
            _pickTimer.Start();
            Status("Move the mouse over the program's window to identify its thread…");
        }
        else _pickTimer.Stop();
    }

    void PickThreadTick()
    {
        if (_session == null || _session.Pid == 0) return;
        if (!GetCursorPos(out var p)) return;
        var hwnd = WindowFromPoint(p);
        if (hwnd == IntPtr.Zero) return;
        var root = GetAncestor(hwnd, GA_ROOT);
        if (root == IntPtr.Zero) root = hwnd;
        uint tid = GetWindowThreadProcessId(root, out uint pid);
        if (pid != _session.Pid) { Status("Hover a window of the debuggee to identify its thread…"); return; }

        var sb = new StringBuilder(256);
        GetWindowText(root, sb, sb.Capacity);
        string title = sb.Length > 0 ? $"\"{sb}\"" : "(untitled window)";
        bool known = _session.HasThread(tid);
        Status($"Window {title}  →  Thread {tid}" + (known ? "" : "  (thread not tracked)"));

        // when stopped we can switch the debugger to that thread's stack/locals
        if (_state == State.Stopped && known)
            SelectThreadByTid(tid);
    }

    void SelectThreadByTid(uint tid)
    {
        if (CmbThreads.SelectedItem is DebugSession.ThreadRef cur && cur.Tid == tid) return;  // already there
        foreach (var item in CmbThreads.Items)
            if (item is DebugSession.ThreadRef tr && tr.Tid == tid)
            { CmbThreads.SelectedItem = tr; break; }   // triggers CmbThreads_SelectionChanged -> SwitchThread
    }

    // ---------- helpers ----------
    void ClearCurrentLine() { foreach (var l in _lines) if (l.IsCurrent) l.IsCurrent = false; }

    void SetState(State s)
    {
        _state = s;
        HideDataTip();
        BtnGo.IsEnabled = s != State.Running;
        BtnPause.IsEnabled = s == State.Running;
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
            RefreshWatch(idx);
        }
        catch { }
    }

    /// <summary>Re-evaluate every watch expression against the given stack frame's live memory.</summary>
    void RefreshWatch(int frameIndex)
    {
        if (_session == null) return;
        foreach (var row in _watch)
        {
            var v = _session.EvalWatch(row.Expr, frameIndex);
            if (v == null) continue;
            row.Type = v.TypeName; row.Value = v.Display; row.Tip = v.Full;
            row.AddrValue = v.Addr; row.Address = v.Addr != 0 ? $"0x{v.Addr:X8}" : "";
            row.Size = v.Size; row.Kind = v.Kind;
        }
    }

    void TxtWatchAdd_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        var expr = TxtWatchAdd.Text.Trim();
        if (expr.Length == 0) return;
        var row = new VarRow { Expr = expr, Name = expr, Value = "—" };
        _watch.Add(row);
        TxtWatchAdd.Clear();
        RefreshWatch(LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex);
        e.Handled = true;
    }

    void RemoveWatch_Click(object sender, RoutedEventArgs e)
    { if (GridWatch.SelectedItem is VarRow row) _watch.Remove(row); }

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
        string disp = v.Display, tip = v.Full;
        if (TryFormatClarionDateTime(type, v.Display, out var pretty))
        { tip = $"{type}  raw = {v.Display}\n{v.Full}"; disp = pretty; }
        return new VarRow
        {
            Name = v.Name, Type = type, Value = disp, Address = $"0x{v.Addr:X8}",
            Tip = tip, AddrValue = v.Addr, Size = v.Size, Kind = v.Kind, Threaded = v.Threaded
        };
    }

    /// <summary>Render a Clarion DATE (days since 1800-12-28) or TIME (centiseconds since
    /// midnight + 1) held in a LONG as a human-readable date/time.</summary>
    static bool TryFormatClarionDateTime(string type, string raw, out string pretty)
    {
        pretty = "";
        var t = type.TrimStart('&').ToUpperInvariant();
        bool isDate = t.StartsWith("DATE"), isTime = t.StartsWith("TIME");
        if ((!isDate && !isTime) || !long.TryParse(raw.Trim(), out var n)) return false;
        try
        {
            if (isDate)
            {
                if (n <= 0 || n > 109207) return false;   // ~ year 1801..2099 sanity window
                pretty = new DateTime(1800, 12, 28).AddDays(n).ToString("yyyy-MM-dd (ddd)");
                return true;
            }
            long cs = n - 1;                               // Clarion midnight = 1
            if (cs < 0 || cs >= 8640000) return false;
            pretty = $"{cs / 360000:D2}:{cs / 6000 % 60:D2}:{cs / 100 % 60:D2}.{cs % 100:D2}";
            return true;
        }
        catch { return false; }
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
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // each physical file parsed once
        foreach (var img in _images)
            foreach (var m in img.Info.Modules)
            {
                var src = ResolveSource(m.Name);
                if (src != null) ParseSourceFile(m.Name, src, seen, 0);
            }
    }

    // parse a source file's declarations, then follow its INCLUDE('file') directives so that
    // EQUATEs (and types) declared in included files are captured too.
    void ParseSourceFile(string module, string path, HashSet<string> seen, int depth)
    {
        if (depth > 6 || !seen.Add(path)) return;
        string[] lines;
        try { lines = File.ReadAllLines(path); } catch { return; }
        ParseDecls(module, lines);
        foreach (var line in lines)
        {
            var inc = ExtractInclude(line);
            if (inc == null) continue;
            var p = ResolveSource(inc) ?? ResolveNear(path, inc);
            if (p != null) ParseSourceFile(module, p, seen, depth + 1);
        }
    }

    static string? ExtractInclude(string line)
    {
        if (FindComment(line) == 0) return null;
        var m = System.Text.RegularExpressions.Regex.Match(line, @"INCLUDE\s*\(\s*'([^']+)'",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }

    static string? ResolveNear(string fromFile, string include)
    {
        try { var p = Path.Combine(Path.GetDirectoryName(fromFile)!, include); return File.Exists(p) ? p : null; }
        catch { return null; }
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
    void GridWatch_DoubleClick(object sender, MouseButtonEventArgs e) => EditRow(GridWatch.SelectedItem as VarRow);

    static VarRow? MenuRow(object sender) =>
        (((sender as System.Windows.Controls.MenuItem)?.Parent as System.Windows.Controls.ContextMenu)
            ?.PlacementTarget as System.Windows.Controls.DataGrid)?.SelectedItem as VarRow;

    void SetValue_Click(object sender, RoutedEventArgs e) => EditRow(MenuRow(sender));

    void CopyValue_Click(object sender, RoutedEventArgs e)
    { if (MenuRow(sender) is { } r) TrySetClipboard(r.Value); }

    void CopyName_Click(object sender, RoutedEventArgs e)
    { if (MenuRow(sender) is { } r) TrySetClipboard(r.Name); }

    static void TrySetClipboard(string s)
    { try { System.Windows.Clipboard.SetText(s ?? ""); } catch { } }

    void ViewMemory_Click(object sender, RoutedEventArgs e)
    {
        if (_session == null) { Status("Start debugging first."); return; }
        if (MenuRow(sender) is not { } r || r.AddrValue == 0) { Status("This row has no readable address."); return; }
        new MemoryWindow(_session, r.AddrValue, r.Name) { Owner = this }.Show();
    }

    void ResolveThreaded_Click(object sender, RoutedEventArgs e)
    {
        if (_session == null || _state != State.Stopped) { Status("Resolving threaded data needs a stopped program."); return; }
        if (MenuRow(sender) is not { } r || r.AddrValue == 0) { Status("This row has no address."); return; }
        if (!r.Threaded) { Status($"{r.Name} isn't THREADed (.cwtls) data — its value is already the real one."); return; }
        var v = _session.ResolveThreadedGlobal(r.AddrValue);   // hijacks the stopped thread to call THR$GetInstance
        if (v == null)
        { Status($"Couldn't resolve {r.Name} on the current thread (no THR$GetInstance import, or eval failed)."); return; }
        r.Value = v.Display; r.Tip = v.Full;
        Log($"{r.Name} on the stopped thread: {v.Display}");
        Status($"{r.Name} resolved on the stopped thread.");
    }

    void ViewArray_Click(object sender, RoutedEventArgs e)
    {
        if (_session == null) { Status("Start debugging first."); return; }
        if (MenuRow(sender) is not { } r || r.AddrValue == 0) { Status("This row has no readable address."); return; }
        int count = ParseDim(r.Type);
        if (count <= 1) { Status($"{r.Name} isn't a DIM array (declared '{r.Type}')."); return; }
        int elemSize = Math.Max(1, r.Size / count);
        new ArrayWindow(_session, r.Name, r.Type, r.AddrValue, elemSize, count) { Owner = this }.Show();
    }

    /// <summary>Total element count from a declared type's DIM(...) clause (product of all dims), else 1.</summary>
    static int ParseDim(string type)
    {
        var m = System.Text.RegularExpressions.Regex.Match(type, @"DIM\s*\(([^)]*)\)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (!m.Success) return 1;
        int total = 1; bool any = false;
        foreach (var part in m.Groups[1].Value.Split(','))
            if (int.TryParse(part.Trim(), out var d) && d > 0) { total *= d; any = true; }
        return any ? total : 1;
    }

    void SetNextStatement_Click(object sender, RoutedEventArgs e)
    {
        if (_state != State.Stopped || _session == null || _curModule == null)
        { Status("Set next statement needs a stopped program."); return; }
        if (MenuLine(sender) is not SourceLine sl) return;
        int line = InfoFor(_curModule)?.NearestCodeLine(_curModule, sl.LineNo) ?? sl.LineNo;
        if (_session.SetNextStatement(_curModule, line)) Status($"Next statement set to {_curModule}:{line}.");
        else Status("Couldn't set next statement here (must be code in the current procedure).");
    }

    // ---------- recent EXEs ----------
    readonly List<string> _recent = new();

    static string RecentPath()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ClarionDbg");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "recent.txt");
    }

    void LoadRecent()
    {
        try { if (File.Exists(RecentPath())) _recent.AddRange(File.ReadAllLines(RecentPath()).Where(File.Exists)); }
        catch { }
    }

    void AddRecent(string path)
    {
        _recent.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase));
        _recent.Insert(0, path);
        if (_recent.Count > 12) _recent.RemoveRange(12, _recent.Count - 12);
        try { File.WriteAllLines(RecentPath(), _recent); } catch { }
    }

    void BtnRecent_Click(object sender, RoutedEventArgs e)
    {
        if (_recent.Count == 0) { Status("No recent files yet."); return; }
        var menu = new System.Windows.Controls.ContextMenu();
        foreach (var p in _recent)
        {
            var item = new System.Windows.Controls.MenuItem { Header = p };
            string path = p;
            item.Click += (_, _) => LoadExe(path);
            menu.Items.Add(item);
        }
        menu.PlacementTarget = (UIElement)sender;
        menu.IsOpen = true;
    }

    // ---------- attach to a running process ----------
    void BtnAttach_Click(object sender, RoutedEventArgs e)
    {
        var win = new AttachWindow { Owner = this };
        if (win.ShowDialog() != true || win.SelectedPid == 0 || win.SelectedPath == null) return;
        LoadExe(win.SelectedPath);
        if (_pe == null || _info == null) return;
        if (_info.SourceFile == null && _info.ModuleCount == 0)
        { Log("The selected process's EXE has no debug info."); return; }

        _vars.Clear(); _localsRows.Clear(); LstStack.ItemsSource = null;
        _session = new DebugSession(_exePath!, _pe, _info) { BreakOnException = ChkBreakCrash.IsChecked == true };
        foreach (var dll in _siblingDlls) _session.PreloadModule(dll);   // so DLL breakpoints resolve on attach
        _session.Log += s => Dispatcher.Invoke(() => Log(s));
        _session.Stopped += OnStopped;
        _session.Exited += code => Dispatcher.Invoke(() =>
        { Log($"--- debuggee exited (code {code}) ---"); ClearCurrentLine(); SetState(State.Idle); Status("Exited."); });
        foreach (var b in _bps) b.HitCount = 0;
        _session.Attach((uint)win.SelectedPid, _bps.ToList());
        SetState(State.Running);
        Status($"Attached to PID {win.SelectedPid}. Set breakpoints / break to inspect.");
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
            if (_watch.Contains(row)) RefreshWatch(LstStack.SelectedIndex < 0 ? 0 : LstStack.SelectedIndex);
        }
    }

    void Log(string s) { TxtLog.AppendText(s + "\n"); TxtLog.ScrollToEnd(); }
    void Status(string s) => TxtStatus.Text = s;

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.F5: BtnGo_Click(this, new RoutedEventArgs()); e.Handled = true; break;
            case Key.F6: BtnPause_Click(this, new RoutedEventArgs()); e.Handled = true; break;
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
    public const string App = "\x01App";        // free procedures you wrote
    public const string Runtime = "\x01Runtime";// thunks / generated routines

    public string Name { get; }
    public uint Rva { get; }
    public string Group { get; }                // App, Runtime, or the owning class name (THISWINDOW, BROWSECLASS, …)
    public TswdInfo? Info { get; }              // the blob this proc came from (EXE or a DLL); null = EXE
    public string? Image { get; }               // owning image filename, for display
    public ProcItem(string name, uint rva, TswdInfo? info = null, string? image = null)
    { Name = name; Rva = rva; Info = info; Image = image; Group = GroupOf(name); }
    public override string ToString() => $"{Name}  @0x{Rva:X}";

    /// <summary>
    /// The procedure's group: <see cref="App"/> for a free procedure (NAME@F with no class, e.g.
    /// BROWSESTUDENTS@F), the owning class name for a method (THISWINDOW from ASK@F10THISWINDOW,
    /// BROWSECLASS from UPDATETHUMB@F11BROWSECLASS), or <see cref="Runtime"/> for thunks/routines.
    /// </summary>
    public static string GroupOf(string name)
    {
        if (name.StartsWith("__") || name.Contains("$$$") || name.StartsWith("R$") || name.Contains("@_"))
            return Runtime;
        int i = name.IndexOf("@F", StringComparison.Ordinal);
        if (i < 0) return Runtime;
        string rest = name[(i + 2)..];
        if (rest.Length == 0 || !char.IsDigit(rest[0])) return App;     // free procedure (no SELF class)
        int d = 0; while (d < rest.Length && char.IsDigit(rest[d])) d++;
        if (int.TryParse(rest[..d], out int len) && len > 0 && d + len <= rest.Length)
            return rest.Substring(d, len);                              // the owning class name
        return Runtime;
    }
}

public sealed class VarRow : INotifyPropertyChanged
{
    public string Name { get; set; } = "";
    public uint AddrValue { get; set; }
    public int Size { get; set; }
    public DebugSession.WriteKind Kind { get; set; }
    public bool Threaded { get; set; }       // THREADed (.cwtls) data — Value shows the template until resolved per-thread
    public string Expr { get; set; } = "";   // for watch rows: the original expression to re-evaluate

    string _value = "", _tip = "", _type = "", _addr = "";
    public string Type { get => _type; set { if (_type != value) { _type = value; Raise(nameof(Type)); } } }
    public string Address { get => _addr; set { if (_addr != value) { _addr = value; Raise(nameof(Address)); } } }
    public string Value { get => _value; set { if (_value != value) { _value = value; Raise(nameof(Value)); } } }
    public string Tip { get => _tip; set { if (_tip != value) { _tip = value; Raise(nameof(Tip)); } } }

    public event PropertyChangedEventHandler? PropertyChanged;
    void Raise(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}
