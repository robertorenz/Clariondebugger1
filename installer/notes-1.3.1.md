Clarion Debugger 1.3.1

Changes since 1.3.0:

- Break on crash now triggers on the *second chance* only, so the application's own exception
  handlers still get first crack at handled exceptions (fewer false stops).
- README updated to document multi-DLL debugging, IDE-accurate source resolution + Link Solution,
  hover data tips (record/EQUATE/QUEUE fields), Pause (F6), and identify-thread.

Download:
- ClarionDebuggerSetup-1.3.1.exe - installer (per-user, no admin)
- ClarionDebugger-1.3.1-portable-win-x86.zip - portable single .exe (unzip & run)

Self-contained (.NET 8 runtime bundled - nothing to install). 32-bit, runs on 64-bit Windows.
Licensed under MIT. See the README for the full feature list.
