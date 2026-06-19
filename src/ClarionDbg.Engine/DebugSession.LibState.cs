namespace ClarionDbg.Engine;

// Library State model: the per-thread RTL values (ERROR/EVENT/THREAD/...) and the table describing how
// to read each one. The values are read by EMULATING the matching ClaRUN.dll getter export read-only
// (see RtlEmulator + DebugSession.ReadLibraryStateEmu) rather than calling it — calling re-enters the
// RTL's thread machinery and crashes the app when parked inside the ACCEPT/TakeEvent loop.
public sealed partial class DebugSession
{
    public enum LibKind { Signed, Unsigned, Str, Date, Time }

    /// <summary>One Library State row: a display value with the source group/name and how it was read.</summary>
    public sealed record LibStateItem(string Group, string Name, string Value, LibKind Kind, bool Ok);

    sealed record Getter(string Group, string Name, string Export, LibKind Kind);

    // The getter set. Deliberately excludes the side-effecting exports: Cla$LONGPATH/Cla$SHORTPATH clear
    // the error code, Cla$CLIPBOARD locks the clipboard. FILEERRORCODE returns a string here
    // (Cla$FILEERRORCODE) per the runtime's own ABI. TODAY/CLOCK are computed from the host clock.
    static readonly Getter[] Getters =
    {
        new("Error", "ERRORCODE",     "Cla$ERRORCODE",     LibKind.Signed),
        new("Error", "ERROR",         "Cla$StackErrstr",   LibKind.Str),
        new("Error", "ERRORFILE",     "Cla$ERRORFILE",     LibKind.Str),
        new("Error", "FILEERRORCODE", "Cla$FILEERRORCODE", LibKind.Str),
        new("Error", "FILEERROR",     "Cla$FILEERRORMSG",  LibKind.Str),
        new("Event", "EVENT",         "Cla$EVENT",         LibKind.Signed),
        new("Event", "ACCEPTED",      "Cla$ACCEPTED",      LibKind.Signed),
        new("Event", "FIELD",         "Cla$FIELD",         LibKind.Signed),
        new("Event", "FOCUS",         "Cla$FOCUS",         LibKind.Signed),
        new("Event", "FIRSTFIELD",    "Cla$FIRSTFIELD",    LibKind.Signed),
        new("Event", "LASTFIELD",     "Cla$LASTFIELD",     LibKind.Signed),
        new("Event", "KEYCODE",       "Cla$KEYCODE",       LibKind.Signed),
        new("Event", "THREAD",        "Cla$THREAD",        LibKind.Signed),
        new("Other", "RUNCODE",       "Cla$RUNCODE",       LibKind.Signed),
        new("Other", "REJECTCODE",    "Cla$REJECTCODE",    LibKind.Signed),
        new("Other", "SELECTED",      "Cla$SELECTED",      LibKind.Signed),
        new("Other", "KEYCHAR",       "Cla$KEYCHAR",       LibKind.Unsigned),
        new("Other", "KEYSTATE",      "Cla$KEYSTATE",      LibKind.Unsigned),
        new("Other", "GETEXITCODE",   "Cla$GETEXITCODE",   LibKind.Signed),
        new("Other", "TODAY",         "Cla$TODAY",         LibKind.Date),
        new("Other", "CLOCK",         "Cla$CLOCK",         LibKind.Time),
    };
}
