Clarion Debugger 1.5.0

Changes since 1.4.1:

- Dockable panel UI — replaced the fixed layout with a fully dockable AvalonDock layout
  (VS2013 dark theme): Procedures / Threads+Call Stack on the left, Source editor in the
  center (fixed, non-closeable), Watch / Locals / Globals on the right, Output log at the
  bottom. Panels can be resized, rearranged, and floated freely.

- Step Into App (Ctrl+F11) — a new step variant that works like F11 but only enters
  procedures that belong to the same .clw source module as the call site. ABC class methods,
  ClaRUN, external DLLs, and any other framework CLW are run transparently; the debugger
  resumes at the next line in your own application code.

- Fix Step Into (F11) not stepping line-by-line inside an entered procedure — the TSWD
  procedure list was not sorted by entry RVA after parsing, so ProcRange()'s floor search
  returned an incorrect range for the entered procedure, causing single-step to stop
  immediately instead of continuing inside it.

Download:
- ClarionDebuggerSetup-1.5.0.exe - installer (per-user, no admin)
- ClarionDebugger-1.5.0-portable-win-x86.zip - portable single .exe (unzip & run)

Self-contained (.NET 8 runtime bundled - nothing to install). 32-bit, runs on 64-bit Windows.
Licensed under MIT. See the README for the full feature list.
