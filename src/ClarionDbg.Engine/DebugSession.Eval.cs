using System.Buffers.Binary;

namespace ClarionDbg.Engine;

// Opt-in THREADed (.cwtls) data evaluation. Reading threaded data for the CURRENT thread can't be
// done by reading the template address — each thread has its own instance, reached by calling
// ClaRUN!THR$GetInstance(EAX = template VA, EBX = .cwtls base), which returns the instance in EAX.
//
// We do that with a function-evaluation hijack: while stopped, redirect the stopped thread to call
// the helper, trap its RET at an unmapped magic address (an AV we recognise), read the instance
// pointer from EAX, then restore the thread's context exactly. All other threads are suspended for
// the duration so the nested event pump only ever sees our trap.
//
// This runs ONLY on an explicit user request (never the live refresh), so the brief target
// execution it requires is bounded — and a bug here can only affect that one action.
public sealed partial class DebugSession
{
    const uint EVAL_TRAP_VA = 0x7FFF1000;   // never mapped in 32-bit user space → AV on the helper's RET

    // eval request (set by the UI thread, consumed by the worker thread inside Stop's wait loop)
    uint _evalReqTid;
    uint _evalTemplateVa, _evalCwtlsBase, _evalHelperVa;
    volatile uint _evalResult;              // instance VA produced by the eval (0 = failed)
    readonly AutoResetEvent _evalDone = new(false);
    readonly object _evalGate = new();      // serialise: one hijack at a time

    /// <summary>Resolve the CURRENT thread's instance address for a THREADed (.cwtls) template VA via
    /// ClaRUN!THR$GetInstance. Returns null if the VA isn't threaded, the helper isn't imported, or
    /// the eval failed/timed out. Call from the UI thread while the debuggee is stopped.</summary>
    public uint? ResolveThreadInstance(uint templateVa)
    {
        if (_hProcess == IntPtr.Zero) return null;
        var owner = ModuleForThreadedVa(templateVa);
        if (owner == null || !owner.HasThreadedData) return null;
        uint helper = ReadDword(owner.LoadBase + owner.ThrGetInstanceIatRva);
        if (helper == 0) return null;

        lock (_evalGate)
        {
            _evalTemplateVa = templateVa;
            _evalCwtlsBase = owner.LoadBase + owner.CwtlsLo;
            _evalHelperVa = helper;
            _evalReqTid = _stoppedTid;
            _evalResult = 0;
            _act = Act.Eval;
            _resume.Set();                                    // wake the worker (blocked in Stop)
            if (!_evalDone.WaitOne(TimeSpan.FromSeconds(5)))  // safety net: THR$GetInstance returns instantly
            { Log?.Invoke("Threaded eval timed out — the debug session may be unstable."); return null; }
            return _evalResult != 0 ? _evalResult : null;
        }
    }

    /// <summary>Read a THREADed global's value on the current thread (typed), or null if the template
    /// VA isn't a known threaded global or the eval failed.</summary>
    public VarValue? ResolveThreadedGlobal(uint templateVa)
    {
        foreach (var (m, g) in AllGlobals())
            if (m.LoadBase + g.Rva == templateVa)
            {
                if (ResolveThreadInstance(templateVa) is not uint inst) return null;
                int sz = g.Type.Size > 0 ? g.Type.Size : g.DisplaySize;
                return ReadVar(g.Name, inst, g.Type, sz);   // read at the real instance (no [tls] tag)
            }
        return null;
    }

    LoadedModule? ModuleForThreadedVa(uint va)
    {
        foreach (var m in _mods) if (m.IsThreadedVa(va)) return m;
        return null;
    }

    /// <summary>Worker-thread side of the hijack. Continues the current (stop) debug event so the eval
    /// thread runs THR$GetInstance, then pumps until the trap fires, reads EAX, and restores context.
    /// Leaves the trap's debug event un-acked so the process stays frozen at the original stop — the
    /// top-level loop acks it (same tid) on the eventual resume.</summary>
    void DoFuncEval(IntPtr stoppedThread)
    {
        uint tid = _evalReqTid;
        _evalResult = 0;
        var suspended = new List<IntPtr>();
        try
        {
            if (!_threads.TryGetValue(tid, out var hThread)) hThread = stoppedThread;
            var saved = GetCtx(hThread);

            // suspend every OTHER thread so the nested pump only ever sees our eval thread's trap
            foreach (var kv in _threads)
                if (kv.Key != tid && Native.SuspendThread(kv.Value) != 0xFFFFFFFF) suspended.Add(kv.Value);

            // hijack: push the magic return address, load the helper's register args, jump to it
            var e = GetCtx(hThread);
            e.Esp = saved.Esp - 4;
            WriteDword(e.Esp, EVAL_TRAP_VA);
            e.Eax = _evalTemplateVa;
            e.Ebx = _evalCwtlsBase;
            e.Eip = _evalHelperVa;
            e.EFlags &= ~0x100u;                              // make sure the trap flag is clear
            Native.SetThreadContext(hThread, ref e);

            // release the current stop event so the eval thread runs the call
            Native.ContinueDebugEvent(_pid, tid, Native.DBG_CONTINUE);

            // nested pump until the helper RETs into the unmapped magic address (an AV there)
            var buf = new byte[256];
            uint instance = 0;
            for (int guard = 0; guard < 100000; guard++)
            {
                if (!Native.WaitForDebugEvent(buf, 5000)) break;   // timeout safety
                uint code = U32(buf, 0), etid = U32(buf, 8);
                if (code == Native.EXCEPTION_DEBUG_EVENT && etid == tid && U32(buf, 24) == EVAL_TRAP_VA)
                {
                    instance = GetCtx(hThread).Eax;
                    Native.SetThreadContext(hThread, ref saved);   // restore; deliberately leave this event un-acked
                    break;
                }
                Native.ContinueDebugEvent(_pid, etid, Native.DBG_CONTINUE);   // pass anything else through
            }
            _evalResult = instance;
        }
        catch { _evalResult = 0; }
        finally
        {
            foreach (var h in suspended) Native.ResumeThread(h);
            _evalDone.Set();
        }
    }

    void WriteDword(uint va, uint v)
    {
        var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        Native.WriteProcessMemory(_hProcess, (IntPtr)va, b, 4, out _);
    }
}
