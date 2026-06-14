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
  (`CreateProcess(DEBUG_ONLY_THIS_PROCESS)`), ASLR-safe; **Go / Stop** and
  **Step Over / Into / Out** (F10 / F11 / Shift+F11) at line granularity.
- **Source-line breakpoints** — click the gutter; they snap to the nearest executable line.
- **Multi-module** — parses the whole TSWD module table; pick any of the app's `.clw`
  modules, with source resolution that also finds the Clarion `libsrc` sources.
- **Searchable Procedures list** — filter across all procedures and click to jump to source.
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
- [ ] Decode ABC's binary global type tree (the `0x03` wrapper) — only needed where source
      is unavailable; the source-based types cover the normal case.
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
- [ ] Edit-variable-at-runtime (`WriteProcessMemory`), watch expressions, conditional BPs.
- [ ] STRING/CSTRING/PSTRING distinction; DATE/TIME calendar formatting.
- [ ] Disassembly + memory windows, threads list.
- [ ] DLL debug info (`.cwdebug` in DLLs), multi-module programs.
```
