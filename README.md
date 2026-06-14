# Clarion Debugger (modern)

A clean, modern replacement for the crash-prone debugger built into Clarion. It debugs
**Clarion / TopSpeed** executables compiled in Debug mode by parsing their embedded
`TSWD` debug information and driving the process with the standard **Win32 Debugging API** —
no dependency on the proprietary `D32` engine.

## Status — Milestones 1 & 2 ✅ (proven)

The full pipeline works end-to-end against a real debuggee, with a **complete typed view**:

```
break inside Compute()  ->  typed locals + call stack + typed globals
LOCIDX int32 = 1→2   LOCSUM int32 = 0→1   PCOUNT int32 = 5      (EBP-relative locals)
call stack: COMPUTE → _main:21 → [runtime]
PERSON group = {AGE=42, PERSONNAME='Roberto'}   GBLPRICE decimal = 19.99
VARRAY int32[4] = [11,22,0,0]   VREAL real8 = 6.28318   VDEC = 12.34   VPDEC = 5.678
```

- Launches the debuggee (`CreateProcess(DEBUG_ONLY_THIS_PROCESS)`), uses the **runtime**
  image base (ASLR-safe).
- Software breakpoints (`0xCC`) mapped from **source line → address** via the TSWD line table.
- On hit: rewinds EIP, reads registers (`GetThreadContext`), walks the EBP call stack
  (runtime frames labeled `[runtime]`), re-arms via single-step; resume / terminate.
- **Full TSWD type system** (`TSWD_FORMAT.md`): int/uint/float/char, DECIMAL & PDECIMAL
  (packed BCD), STRING/CSTRING/PSTRING, arrays, and nested GROUPs — all formatted from
  live process memory.
- **Typed locals & parameters** read via EBP + frame offset for the procedure in scope.
- WPF UI (professional dark theme): source view with breakpoint gutter + current-line
  highlight, Procedures, Call Stack, **Locals** + **Globals** grids (name/type/value),
  output log.

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
- [ ] Decode ABC's complex global type tree (the `0x03` type-wrapper → class refs, `&`
      pointers, FILE/QUEUE/VIEW). Today these show as raw hex+ASCII rather than structured.
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
- [ ] Edit-variable-at-runtime (write a new value from the debugger via WriteProcessMemory).
- [ ] Clarion ROUTINE frame sharing (routines reuse the parent procedure's locals).
- [ ] Edit-variable-at-runtime (`WriteProcessMemory`), watch expressions, conditional BPs.
- [ ] STRING/CSTRING/PSTRING distinction; DATE/TIME calendar formatting.
- [ ] Disassembly + memory windows, threads list.
- [ ] DLL debug info (`.cwdebug` in DLLs), multi-module programs.
```
