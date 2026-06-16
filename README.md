# Clarion Debugger (modern)

A clean, modern replacement for the crash-prone debugger built into Clarion. It debugs
**Clarion / TopSpeed** executables compiled in Debug mode by parsing their embedded
`TSWD` debug information and driving the process with the standard **Win32 Debugging API** —
no dependency on the proprietary `D32` engine.

## Download

Grab the latest build from **[Releases](https://github.com/robertorenz/Clariondebugger1/releases)**:

| Asset | What it is |
|-------|-----------|
| `ClarionDebuggerSetup-x.y.z.exe` | Installer — per-user, no admin needed; adds Start-menu / desktop shortcuts and an uninstaller |
| `ClarionDebugger-x.y.z-portable-win-x86.zip` | Portable — a single self-contained `ClarionDbg.exe`; just unzip and run |

Both are **self-contained** (the .NET 8 runtime + WPF are bundled — nothing to install). The app
is 32-bit to match Clarion's 32-bit EXEs and runs on 64-bit Windows.

Maintainers — cut a new release in one command (builds artifacts **and** creates the GitHub
release): `powershell installer\publish-release.ps1 -Version x.y.z` (needs the .NET 8 SDK,
[Inno Setup 6](https://jrsoftware.org/isinfo.php), and an authenticated `gh`). To only build the
artifacts locally: `powershell installer\build-release.ps1 -Version x.y.z`.

## Features

A working source-level debugger for real Clarion apps (tested against a full multi-module
ABC application — `School`, 54 modules):

- **Launch & control** — runs the debuggee under the Win32 Debugging API
  (`CreateProcess(DEBUG_ONLY_THIS_PROCESS)`), ASLR-safe; **Go / Stop**,
  **Pause** (F6 — break into a freely-running program), and
  **Step Over / Into / Out** (F10 / F11 / Shift+F11) at line granularity.
- **Source-line breakpoints** — click the gutter; they snap to the nearest executable line.
- **Multi-module** — parses the whole TSWD module table; pick any of the app's `.clw`
  modules, with source resolution that also finds the Clarion `libsrc` sources.
- **Multi-DLL debugging** — debugs across the EXE *and* its loaded Clarion debug DLLs as one
  program: load/unload events are tracked at runtime and every image's modules, procedures, and
  symbols are merged into a single catalog (modules and procedures are grouped/labelled by owning
  image, with the project's own source floated to the top).
- **IDE-accurate source resolution** — finds the exact `.clw`/`.inc`/`.equ` sources the way the
  Clarion IDE does: reads redirection (`.red`) files, `.sln`/`.cwproj` solutions and their file
  lists, `FileList.xml`, IDE preferences, and detects installed Clarion versions. A **Link
  Solution** dialog binds a debugged EXE to its Clarion solution + version (`ConfigDir` /
  `ClarionProperties.xml` override), remembered per solution, so the right project sources load
  instead of just the shipped `libsrc`.
- **Searchable Procedures list** — filter across all procedures (text + a "kind" pulldown:
  your global procedures, ThisWindow/Report local methods, or any specific class's methods)
  and click to jump to source.
- **Call stack with per-frame locals** — click any frame to inspect *its* locals; the
  selected frame stays put across steps.
- **Locals & Globals** — full enumeration (incl. threaded ABC procedures via scope-grouping),
  with **name filters**. Values are readable (strings, numbers, groups, arrays) with a hover
  tooltip showing the complete value.
- **Exact types from your `.clw` source** — the Type column shows the type as you declared it
  (`STRING(80)`, `LONG`, `STRING('asdf {16}')`).
- **Live refresh** — while the program runs, the selected frame's locals and the globals
  update in place from process memory (no re-break needed).
- **Edit values** — right-click / double-click a variable → set a new value (writes to the
  live process via `WriteProcessMemory`).
- **Breakpoint power features** — beyond plain line breakpoints:
  - **Conditional breakpoints** — break only when an expression is true (`count > 10`,
    `mylocalvar1 = 5`), evaluated against the current frame's locals and the globals.
  - **Hit counts** — break on the Nth hit (`=5`), from the Nth on (`>=5`), or every Nth (`%3`).
  - **Tracepoints** — a breakpoint that logs a message and keeps running instead of stopping,
    with `{variable}` values interpolated (e.g. `LocIdx={LocIdx} LocSum={LocSum}`).
  - **Run to cursor** — right-click a source line → run there (one-shot).
  - **Break on procedure entry** — right-click any procedure → stop when it's entered.
  - **Breakpoint manager** — a window to enable/disable, edit conditions / hit counts /
    tracepoint logs, see hit counts, and remove breakpoints; all editable live while running.
  - **Persistence** — breakpoints are saved per-EXE and restored next time you open it.
- **Disassembly view** — an x86 disassembly window (powered by Iced) at the current instruction
  pointer, with byte columns, source-line annotations, and the current instruction highlighted;
  navigate to any address, auto-follows the IP.
- **Syntax highlighting** — the source view colorizes Clarion keywords, strings, comments,
  numbers, and column-1 labels (professional palette, no purple).
- **Array (DIM) viewer** — right-click a `DIM(...)` variable → *View as array* lists each element
  with its address and value.
- **Memory / hex view** — right-click a variable → *View memory* opens a live hex+ASCII dump at
  its address; navigate to any address, auto-refreshes while running.
- **DATE / TIME formatting** — Clarion `DATE` (days since 1800-12-28) and `TIME` (centiseconds)
  values are shown as `yyyy-MM-dd` / `HH:MM:SS.cc` (raw value kept in the tooltip).
- **Copy value / name**, **set next statement** (right-click a source line to move the IP within
  the current procedure), **attach to a running process** (lists processes that carry Clarion
  debug info), and a **Recent EXEs** menu.
- **Watch window** — type a variable name or an expression (`count > 5`, `mylocalvar1 = 'asdf'`)
  and watch its value; watches resolve against the selected stack frame and refresh live while
  the program runs and on every stop. Comparison expressions show `true`/`false`; double-click a
  watched variable to edit it.
- **Hover data tips** — hover any variable in the source view to see its current value in a
  tooltip (name, type, and value, with DATE/TIME formatted). Resolves against the selected stack
  frame and works both when stopped and live while the program is running. Hovering an **EQUATE**
  shows its compile-time constant value (decoded to decimal for hex/binary/octal literals),
  resolved from the source and any `INCLUDE`d files — so it works even before the program runs.
  Hovering also resolves **FILE / GROUP / QUEUE fields**: a file-record field by its prefixed name
  (`STU:LastName`, `MAJ:Number`), a dotted member path (`vGroup.gA`), and **browse-queue fields**
  via the ABC convention `BRW1.Q.STU:LastName` (the queue reference is dereferenced to the current
  row). Hovering a record/queue itself lists every field and value. Field layouts are decoded from
  the TSWD member records (see `TSWD_FORMAT.md`).
- **Break on crash** — automatically stops at the faulting instruction on a GPF / access
  violation, divide-by-zero, stack overflow, illegal instruction, etc. (toggle "Break on crash"),
  so you can inspect the call stack and variables before the app dies. Breaks on the *second
  chance* only, so the app's own exception handlers still get first crack at handled exceptions.
- **Thread list & switching** — a thread picker shows every live thread and where each is
  executing; switch threads to walk another thread's call stack (and its per-frame locals)
  while stopped.
- **Identify thread by window** — toggle "🎯 Identify thread", then move the mouse over any of
  the running program's windows to see which thread owns it (`GetWindowThreadProcessId`). When the
  program is stopped, hovering a window also selects that thread in the debugger so its call stack
  and locals load — handy in multi-threaded Clarion apps (one thread per window) to jump straight
  to the thread you're looking at.
- **WPF UI** — professional dark theme, breakpoint gutter, current-line highlight, output log.

Built on the decoded **TSWD** debug format (`TSWD_FORMAT.md`) — no dependency on the
proprietary `D32` engine.

## How Clarion debug mode works (reverse-engineered)

See **[FINDINGS.md](FINDINGS.md)** for the full write-up. In short:

- Build with project property `vid=full`. A debug build adds a PE section **`.cwdebug`**
  (a 32-byte locator: `TSWD` sig + blob size + file offset) and appends a **`TSWD` blob**
  after the last section. Release builds have neither.
- The blob holds: source filename, a **line ↔ address** table (matches the linker `.MAP`
  exactly), a name string table (globals `$NAME`, procedures mangled `NAME@F<args>`),
  symbol/type records, and an address → symbol map.

## Layout

```
FINDINGS.md                  full reverse-engineering write-up
tools/                       python helpers (PE/section dump, hexdump, TSWD parser)
sample/dbgtest/              minimal Clarion program built Debug + Release for study
src/ClarionDbg.Engine/       PE reader, TSWD parser, Win32 debug session  (x86)
src/ClarionDbg.App/          WPF debugger UI                               (x86)
src/ClarionDbg.Probe/        headless console harness that proves the engine
```

## Build & run

```powershell
# build everything
dotnet build src/ClarionDbg.App/ClarionDbg.App.csproj -c Debug

# run the GUI (auto-loads the sample debuggee)
src/ClarionDbg.App/bin/Debug/net8.0-windows/ClarionDbg.exe

# or prove the engine headlessly
dotnet run --project src/ClarionDbg.Probe
```

### Rebuilding the sample debuggee
```powershell
MSBuild.exe sample/dbgtest/dbgtest.cwproj /p:Configuration=Debug `
  /p:ClarionBinPath=C:\Clarion12\bin `
  "/p:clarion_version=Clarion 12.0.13941" `
  "/p:ConfigDir=$env:APPDATA\SoftVelocity\Clarion\12.0"
```
(`.clw` sources must use CRLF line endings.)

## Roadmap

- [x] Decode the TSWD **type records** fully → typed vars, GROUP layout, arrays, strings, decimals.
- [x] **Local variables & params** (EBP-relative) for the procedure in scope.
- [x] Proper module attribution for call-stack frames outside the debuggee module.
- [x] **Multi-module ABC apps** — parse the module table; map RVA ↔ (module, line) across
      all modules; module picker in the UI; source resolution incl. Clarion `libsrc`.
- [x] **Full symbol enumeration via stream scan** — finds every procedure (1221 in the
      School demo vs 67 from the address map) so locals resolve in any procedure, plus all
      global data symbols (VMT noise filtered, frame-offset filter separates locals/globals).
- [x] **Readable values for every global** — fully typed where the type is decoded
      (scalar/string/group/array/decimal), else size-aware hex + ASCII (size inferred from the
      next symbol), so e.g. `DEFAULTERRORS`, tooltip tables, scroll data show real text.
- [x] **Exact declared types from `.clw` source** — the Type column shows the type as written
      in source (`STRING(80)`, `STRING('asdf {16}')`, `LONG`), parsed from each module's
      declarations (label-at-col-1), scoped per module; falls back to a size/content-inferred
      Clarion type (`STRING(n)`/`LONG`/`BYTE`/`REAL`) when the source isn't found. This
      sidesteps the undecoded ABC binary type tree entirely for display purposes.
- [x] Decode ABC's record/group/queue layouts (the `0x03` wrapper → `0x0c` member records
      grouped by a shared scope ref) → field name + offset for FILE records, GROUPs, and browse
      QUEUEs; element size inferred from offset gaps. See `TSWD_FORMAT.md`.
- [x] **Disassembly view** (Iced x86 decoder), **Clarion syntax highlighting** in the source
      view, and an **array (DIM) viewer** that lists elements by address.
- [x] **File-buffer decode** (`STU:Record` field-by-field) — solved without a `.dct` parser:
      the record buffer is a fixed global (`STUDENTS$STU:RECORD`) and its fields come from the
      TSWD member records, so `STU:LastName`, `MAJ:Number`, etc. resolve to `base + offset` and
      show live values (hover, watch, conditions). Browse-queue fields resolve via `BRW1.Q.*`.
- [ ] Live thread-local (`.cwtls`) file buffers (`STU:Record`): `.cwtls` is Clarion-managed
      (not Windows TLS — TLS data dir is empty), so live per-thread values need ClaRUN's
      thread-block internals. Currently shown from the image template, flagged `[tls]`.
- [x] **Locals in threaded ABC procedures** — solved. Locals are 17-byte records
      `04 | typeRef | nameOff | frameOffset | scopeRef`; all locals of a procedure share a
      `scopeRef`, and the proc-record ref list is unreliable. Enumerate by scope-grouping and
      attach each group to the procedure whose record precedes it. Recovers the full local
      list (all 27 for `BrowseStudents`: `CurrentTab`, `mylocalvar1`, …) and reads live values
      at EBP+offset (verified). Types for ABC class/file locals still show as sized hex+ASCII.
- [x] **Breakpoints snap to the nearest executable line** and report when moved (clicking a
      declaration line no longer silently jumps into an unrelated procedure).
- [x] **Per-frame locals** — each call-stack frame carries its own locals (read at that
      frame's EBP); click a frame to see them. Essential for ABC, where you often break in a
      `ThisWindow.Init`/method and the window-proc locals live a few frames up.
- [x] **Searchable, click-to-navigate Procedures list** — filter by name, click to open the
      procedure's source ready to set a breakpoint.
- [x] **Stepping** — step over / into / out at line granularity (F10 / F11 / Shift+F11),
      via trap-flag single-stepping + the line table; locals re-read at every stop so values
      update as you step.
- [x] **Live value refresh** — while the debuggee runs, the selected frame's locals and the
      globals re-read from process memory every ~400 ms, so values update in place as the app
      changes them (no re-break needed), as long as that frame is still alive.
- [x] **Edit a variable's value** — right-click (or double-click) a local/global → modal dialog →
      writes the new value to process memory (`WriteProcessMemory`). Parses by kind: integer,
      float, string (space-padded like a Clarion STRING), or raw hex; re-reads to confirm.
- [ ] Clarion ROUTINE frame sharing (routines reuse the parent procedure's locals).
- [x] **Memory/hex view, DATE/TIME formatting, copy value, set-next-statement, attach to a
      running process, and recent EXEs** — a live hex+ASCII memory window, Clarion DATE/TIME
      rendering, clipboard copy, moving the instruction pointer within a procedure,
      `DebugActiveProcess` attach (filtered to EXEs with `.cwdebug`), and a recent-files menu.
- [x] **Watch window + expression evaluator** — watch variable names or comparison expressions,
      resolved against the selected frame's locals/params then globals, refreshed live and on
      each stop; booleans render `true`/`false`; watched variables are editable.
- [x] **Conditional breakpoints, hit counts, and tracepoints** — break on a condition
      (`count > 10`), on the Nth/every-Nth hit (`=5`/`%3`), or log-and-continue with
      `{variable}` interpolation; plus **run-to-cursor**, **break-on-procedure-entry**, a
      **breakpoint manager** window, and **per-EXE persistence**.
- [ ] STRING/CSTRING/PSTRING distinction; DATE/TIME calendar formatting.
- [x] **Break on crash** — stop at the faulting instruction on any fatal exception (GPF,
      divide-by-zero, stack overflow, illegal/privileged instruction, in-page error) so the
      stack and variables are inspectable before the process unwinds.
- [x] **Thread list + switching** — live thread picker (marks the stopped thread, shows each
      thread's current procedure); switch to walk any thread's call stack and per-frame locals
      (safe because all threads are suspended while stopped).
- [x] Disassembly + memory windows.
- [x] **Multi-DLL debugging** — debug across the EXE and its loaded Clarion debug DLLs as one
      program (runtime load/unload tracking; merged module/procedure/symbol catalog).
- [x] **IDE-accurate source resolution** — `.red` redirection, `.sln`/`.cwproj` + file lists,
      `FileList.xml`, installed-version detection, and a Link-Solution binding dialog
      (`Clarion.SourceResolution`, with a unit-test suite).
- [x] **Hover data tips** — variable values, EQUATE constants, and FILE/GROUP/QUEUE record
      fields (`STU:LastName`, `MAJ:Number`, `BRW1.Q.STU:LastName`) in the source view.
- [x] **Identify thread by window** and **Pause** (F6) to break into a running program.
```

## License

Released under the **MIT License** — see [LICENSE](LICENSE).

```
MIT License

Copyright (c) 2026 Roberto Renz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
