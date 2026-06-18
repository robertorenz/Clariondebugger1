using ClarionDbg.Engine;

// exports <pe> [filter]  — dump the PE export table (for the Library State getter port).
// Works on any PE (e.g. ClaRUN.dll), not just TSWD debug builds.
if (args.Length >= 2 && args[0].Equals("exports", StringComparison.OrdinalIgnoreCase))
{
    var epe = new PeImage(args[1]);
    string? filter = args.Length > 2 ? args[2] : null;
    var exps = epe.Exports;
    Console.WriteLine($"{args[1]}");
    Console.WriteLine($"exports   : {exps.Count}");
    foreach (var kv in exps.OrderBy(k => k.Value)
                 .Where(k => filter == null || k.Key.Contains(filter, StringComparison.OrdinalIgnoreCase)))
        Console.WriteLine($"   0x{kv.Value:X6}  {kv.Key}");
    return;
}

// imports <pe> [filter]  — dump the PE import table. Used to confirm an EXE is DLL-linked against
// the Clarion runtime (imports ClaRUN.dll) vs locally linked (RTL baked in — no clarun import).
if (args.Length >= 2 && args[0].Equals("imports", StringComparison.OrdinalIgnoreCase))
{
    var ipe = new PeImage(args[1]);
    string? filter = args.Length > 2 ? args[2] : null;
    var imps = ipe.EnumerateImports()
        .Where(i => filter == null || i.Dll.Contains(filter, StringComparison.OrdinalIgnoreCase)
                                   || i.Func.Contains(filter, StringComparison.OrdinalIgnoreCase))
        .ToList();
    Console.WriteLine($"{args[1]}");
    Console.WriteLine($"imports   : {imps.Count} ({imps.Select(i => i.Dll).Distinct().Count()} DLLs)");
    bool clarun = ipe.EnumerateImports().Any(i => i.Dll.Contains("ClaRUN", StringComparison.OrdinalIgnoreCase));
    Console.WriteLine($"DLL-linked: {(clarun ? "YES (imports ClaRUN.dll — Library State available)" : "no (locally linked — Library State unavailable)")}");
    foreach (var i in imps.OrderBy(i => i.Dll).ThenBy(i => i.Func))
        Console.WriteLine($"   {i.Dll}!{i.Func} @ slot 0x{i.SlotRva:X}");
    return;
}

string exe = args.Length > 0 ? args[0] : @"C:\ai\debuger\sample\dbgtest\dbgtest_dbg.exe";
int bpLine = args.Length > 1 ? int.Parse(args[1]) : 21;

var pe = new PeImage(exe);
var info = TswdInfo.Load(pe) ?? throw new Exception("not a debug build");

Console.WriteLine($"source    : {info.SourceFile}");
Console.WriteLine($"lines     : {info.Lines.Count}  (range {(info.Lines.Count>0?info.Lines.Min(l=>l.Line):0)}..{(info.Lines.Count>0?info.Lines.Max(l=>l.Line):0)})");
Console.WriteLine($"globals   : {info.Globals.Count}");
Console.WriteLine($"procs     : {info.Procedures.Count}");
Console.WriteLine($"entryRvas : {string.Join(", ", info.Procedures.OrderBy(p => p.Rva).Take(12).Select(p => $"{p.Name}@0x{p.Rva:X}"))}");
Console.WriteLine($"modules   : {info.Modules.Count} ({info.Modules.Count(m => m.Lines.Count > 0)} with debug lines)");
if (bpLine == 0 && args.Length > 2 && args[2].StartsWith("findlocal:"))
{
    string want = args[2]["findlocal:".Length..];
    foreach (var p in info.Procs.Where(p => p.Locals.Any(l => l.Name.Contains(want, StringComparison.OrdinalIgnoreCase))))
        Console.WriteLine($"proc {p.Name} @0x{p.EntryRva:X}  has {p.Locals.Count} locals incl: " +
            string.Join(", ", p.Locals.Where(l => l.Name.Contains(want, StringComparison.OrdinalIgnoreCase)).Select(l => l.Name)));
    return;
}
if (bpLine == 0 && args.Length > 2)   // dump locals of procedures matching a name
{
    foreach (var p in info.Procs.Where(p => p.Name.Contains(args[2], StringComparison.OrdinalIgnoreCase)))
    {
        Console.WriteLine($"\nproc {p.Name} @0x{p.EntryRva:X}  ({p.Locals.Count} locals):");
        foreach (var lv in p.Locals)
            Console.WriteLine($"   {lv.Name,-20} {lv.Type.Describe(),-14} frame={lv.FrameOffset}");
    }
    return;
}
if (bpLine == 0)   // parse-only diagnostic mode
{
    Console.WriteLine("\nmodules with debug lines:");
    foreach (var m in info.Modules.Where(m => m.Lines.Count > 0))
        Console.WriteLine($"   {m.Name,-16} {m.Lines.Count,5} lines  (entries {m.FirstLine}..{m.LastLine})");
    Console.WriteLine("\nRVA -> (module, line) check on procedure entry points:");
    foreach (var p in info.Procedures.OrderBy(p => p.Rva).Take(12))
    {
        var loc = info.Locate(p.Rva);
        Console.WriteLine($"   0x{p.Rva:X6} {p.Name,-40} -> {loc?.Module}:{loc?.Line}");
    }
    Console.WriteLine("\nthreaded-data eval foundation:");
    var cwtls = pe.FindSection(".cwtls");
    Console.WriteLine($"   .cwtls section        : {(cwtls != null ? $"rva=0x{cwtls.Rva:X} size=0x{Math.Max(cwtls.VSize, cwtls.RawSize):X}" : "(none)")}");
    Console.WriteLine($"   ClaRUN!THR$GetInstance: IAT slot rva = 0x{pe.FindImportIatSlotRva("ClaRUN.dll", "THR$GetInstance"):X}");
    var imports = pe.EnumerateImports().ToList();
    Console.WriteLine($"   imports parsed        : {imports.Count} ({imports.Select(i => i.Dll).Distinct().Count()} DLLs)");
    foreach (var i in imports.Take(8)) Console.WriteLine($"        {i.Dll}!{i.Func} @ slot 0x{i.SlotRva:X}");

    Console.WriteLine("\nfirst 15 globals (filtered):");
    foreach (var g in info.Globals.Take(15)) Console.WriteLine($"   {g.Name,-24} {g.Type.Describe(),-14} rva=0x{g.Rva:X}");
    Console.WriteLine("\nglobal GROUP/record buffers (decoded members, first 12):");
    foreach (var g in info.Globals.Where(g => g.Type.Kind == TypeKind.Group).Take(12))
    {
        Console.WriteLine($"   {g.Name,-26} GROUP({g.Type.Members.Count})  rva=0x{g.Rva:X}");
        foreach (var m in g.Type.Members.Take(20))
            Console.WriteLine($"        +{m.Offset,-4} {m.Name,-22} size={m.Type.Size}");
    }
    return;
}
Console.WriteLine($"break    : line {bpLine} -> rva 0x{info.LineToRva(bpLine):X}");
Console.WriteLine(new string('-', 60));

var done = new ManualResetEventSlim();
int stepCounter = 0;
var sess = new DebugSession(exe, pe, info);
sess.Log += s => Console.WriteLine("[engine] " + s);
sess.Exited += c => { Console.WriteLine($"[exit] code {c}"); done.Set(); };
sess.Stopped += info2 =>
{
    Console.WriteLine($"\n*** STOPPED: {info2.Reason} at EIP 0x{info2.Eip:X8} ({info2.Module}:{info2.Line}) ***");
    Console.WriteLine("call stack + per-frame locals:");
    int fi = 0;
    foreach (var f in info2.Stack)
    {
        Console.WriteLine($"  #{fi++} {f.Proc,-28} {(f.Line is int l ? f.Module + ":" + l : "")}  [{f.Locals.Count} locals]");
        foreach (var v in f.Locals.Take(6))
            Console.WriteLine($"        {v.Name,-22} {v.TypeName,-8} = {v.Display}");
    }
    Console.WriteLine("globals (typed, live values):");
    foreach (var v in info2.Globals)
        Console.WriteLine($"   {v.Name,-12} {v.TypeName,-14} = {v.Display}");
    var setLocal = Environment.GetEnvironmentVariable("CLARIONDBG_SETLOCAL");   // "NAME=VALUE"
    if (setLocal != null && setLocal.Contains('='))
    {
        var parts = setLocal.Split('=', 2);
        var lv = info2.Stack[0].Locals.FirstOrDefault(x => x.Name.Equals(parts[0], StringComparison.OrdinalIgnoreCase));
        if (lv != null)
        {
            bool ok = sess.WriteVar(lv.Addr, lv.Kind, lv.Size, parts[1]);
            Console.WriteLine($"\n>>> WriteVar {lv.Name} := {parts[1]} -> {ok}");
            var nv = sess.RereadFrameLocals(0).FirstOrDefault(x => x.Name == lv.Name);
            Console.WriteLine($">>> re-read {lv.Name} = {nv?.Display}");
        }
    }

    var watch = Environment.GetEnvironmentVariable("CLARIONDBG_WATCH");   // comma-separated expressions
    if (watch != null)
    {
        Console.WriteLine("watch:");
        foreach (var ex in watch.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var w = sess.EvalWatch(ex, 0);
            Console.WriteLine($"   {ex,-22} {w?.TypeName,-8} = {w?.Display}");
        }
    }

    if (Environment.GetEnvironmentVariable("CLARIONDBG_DISASM") == "1")
    {
        Console.WriteLine("disasm @ EIP:");
        foreach (var d in sess.Disassemble(info2.Eip, 10))
            Console.WriteLine($"   0x{d.Addr:X8}  {d.Bytes,-22} {d.Text}" + (d.Source != null ? $"    ; {d.Source}" : ""));
    }
    if (Environment.GetEnvironmentVariable("CLARIONDBG_MEM") == "1" && info2.Globals.Count > 0)
    {
        var g = info2.Globals[0];
        var mem = sess.ReadMemory(g.Addr, 32);
        Console.WriteLine($"mem @ {g.Name} 0x{g.Addr:X8}: {BitConverter.ToString(mem)}");
    }
    var setNext = Environment.GetEnvironmentVariable("CLARIONDBG_SETNEXT");
    if (setNext != null && int.TryParse(setNext, out var snLine))
    {
        Environment.SetEnvironmentVariable("CLARIONDBG_SETNEXT", null);   // clear first: ReportStop re-enters this handler
        bool ok = sess.SetNextStatement(info2.Module ?? "", snLine);
        Console.WriteLine($">>> SetNextStatement -> line {snLine}: {ok}");
    }

    int stepsLeft = int.TryParse(Environment.GetEnvironmentVariable("CLARIONDBG_STEPS"), out var sc) ? sc : 0;
    string kind = Environment.GetEnvironmentVariable("CLARIONDBG_STEPKIND") ?? "into";
    if (stepsLeft > 0 && stepCounter < stepsLeft)
    {
        stepCounter++;
        Console.WriteLine($"   [{kind} step {stepCounter}]");
        if (kind == "over") sess.StepOver(); else if (kind == "out") sess.StepOut(); else sess.StepInto();
    }
    else if (Environment.GetEnvironmentVariable("CLARIONDBG_ONCE") == "1")
    { Console.WriteLine("\n(terminating after first hit)"); sess.Terminate(); }
    else { Console.WriteLine("\n(continuing…)"); sess.Continue(); }
};

string? bpModule = args.Length > 2 ? args[2] : null;
var bp = new DebugSession.Breakpoint(bpModule, bpLine)
{
    Condition    = Environment.GetEnvironmentVariable("CLARIONDBG_COND"),
    HitCondition = Environment.GetEnvironmentVariable("CLARIONDBG_HIT"),
    LogMessage   = Environment.GetEnvironmentVariable("CLARIONDBG_TRACE"),
};
sess.Start(new[] { bp });
done.Wait(8000);
Console.WriteLine("probe finished.");
