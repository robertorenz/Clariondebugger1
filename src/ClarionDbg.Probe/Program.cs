using ClarionDbg.Engine;

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
    Console.WriteLine("\nfirst 15 globals (filtered):");
    foreach (var g in info.Globals.Take(15)) Console.WriteLine($"   {g.Name,-24} {g.Type.Describe(),-14} rva=0x{g.Rva:X}");
    return;
}
Console.WriteLine($"break    : line {bpLine} -> rva 0x{info.LineToRva(bpLine):X}");
Console.WriteLine(new string('-', 60));

var done = new ManualResetEventSlim();
var sess = new DebugSession(exe, pe, info);
sess.Log += s => Console.WriteLine("[engine] " + s);
sess.Exited += c => { Console.WriteLine($"[exit] code {c}"); done.Set(); };
sess.Stopped += info2 =>
{
    Console.WriteLine($"\n*** STOPPED: {info2.Reason} at EIP 0x{info2.Eip:X8} ({info2.Module}:{info2.Line}) ***");
    Console.WriteLine("call stack:");
    foreach (var f in info2.Stack) Console.WriteLine($"   {f.Proc,-20} 0x{f.Addr:X8} {(f.Line is int l ? f.Module + ":" + l : "")}");
    Console.WriteLine("locals (current procedure):");
    foreach (var v in info2.Locals)
        Console.WriteLine($"   {v.Name,-18} {v.TypeName,-14} = {v.Display}");
    Console.WriteLine("globals (typed, live values):");
    foreach (var v in info2.Globals)
        Console.WriteLine($"   {v.Name,-12} {v.TypeName,-14} = {v.Display}");
    if (Environment.GetEnvironmentVariable("CLARIONDBG_ONCE") == "1")
    { Console.WriteLine("\n(terminating after first hit)"); sess.Terminate(); }
    else { Console.WriteLine("\n(continuing…)"); sess.Continue(); }
};

string? bpModule = args.Length > 2 ? args[2] : null;
sess.Start(new[] { new DebugSession.Breakpoint(bpModule, bpLine) });
done.Wait(8000);
Console.WriteLine("probe finished.");
