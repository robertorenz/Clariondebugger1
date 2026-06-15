Clarion Debugger 1.1.0

A big feature release — six waves of new debugging power on top of the 1.0 core:

- **Break on crash** — automatically stop at the faulting instruction on a GPF, divide-by-zero,
  stack overflow, illegal/privileged instruction, or in-page error.
- **Thread list & switching** — see every live thread and where it's executing; switch to walk
  any thread's call stack and per-frame locals.
- **Breakpoint power features** — conditional breakpoints (`count > 10`), hit counts
  (`=5` / `>=5` / `%3`), tracepoints that log `{variable}` values and keep running, run-to-cursor,
  break-on-procedure-entry, a breakpoint manager window, and per-EXE persistence.
- **Watch window** — watch variable names or comparison expressions, resolved against the
  selected frame, refreshed live and on every stop.
- **Memory / hex view, DATE/TIME formatting, copy value, set-next-statement, attach to a running
  process, recent-EXEs menu.**
- **Disassembly view** (x86, with source annotations), **Clarion syntax highlighting** in the
  source view, and an **array (DIM) viewer**.

Download:
- ClarionDebuggerSetup-1.1.0.exe - installer (per-user, no admin)
- ClarionDebugger-1.1.0-portable-win-x86.zip - portable single .exe (unzip & run)

Self-contained (.NET 8 runtime bundled - nothing to install). 32-bit, runs on 64-bit Windows.
See the README for the full feature list.
