using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace ClarionDbg.App;

/// <summary>
/// Attached property that renders a line of Clarion source into colored runs on a TextBlock.
/// The keyword/type/function vocabulary and its precedence mirror the Clarion-Extension TextMate
/// grammar (msarson/Clarion-Extension, syntaxes/clarion.tmLanguage.json), consolidated into a
/// professional VS-style palette (no purple). Tokenizing is per line and stateless, so multi-line
/// constructs (OMIT/COMPILE regions, multi-line strings) are not tracked.
/// </summary>
public static class SyntaxHighlight
{
    static readonly Brush Keyword  = Frozen("#FF569CD6");   // blue   — control flow, declarations, attributes, directives
    static readonly Brush Type     = Frozen("#FF4EC9B0");   // teal   — data / structure / control types
    static readonly Brush Function = Frozen("#FFDCDCAA");   // yellow — built-in (runtime library) functions
    static readonly Brush Str      = Frozen("#FFCE9178");   // soft orange
    static readonly Brush Comment  = Frozen("#FF6A9955");   // green
    static readonly Brush Number   = Frozen("#FFB5CEA8");   // pale green — numeric & boolean literals
    static readonly Brush Picture  = Frozen("#FFD7BA7D");   // gold — picture tokens (@N9.2, @D6, @S30…)
    static readonly Brush Label    = Frozen("#FF4EC9B0");   // teal — column-1 label / entity name
    static readonly Brush Plain    = Frozen("#FFDCDCDC");   // default text

    static Brush Frozen(string hex)
    { var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); b.Freeze(); return b; }

    // --- vocabulary, verbatim from the TextMate grammar's repository groups ---
    const string ControlFlow = "IF ELSIF ELSE END CASE OF OROF LOOP WHILE UNTIL TIMES TO BY BREAK CYCLE EXIT GOTO RETURN CHOOSE EXECUTE DO THEN ACCEPT";
    const string Declarations = "PROGRAM PROCEDURE FUNCTION ROUTINE MODULE MEMBER MAP CODE DATA";
    const string Oop = "CLASS INTERFACE NEW DISPOSE SELF PARENT PROPERTY INDEXER DERIVED REPLACE";
    const string DataTypes = "ANY ASTRING BFLOAT4 BFLOAT8 BLOB MEMO BOOL BSTRING BYTE CSTRING DATE DECIMAL DOUBLE FLOAT4 LONG PDECIMAL PSTRING REAL SHORT SIGNED SREAL STRING TIME ULONG UNSIGNED USHORT VARIANT";
    const string StructureTypes = "APPLICATION GROUP QUEUE RECORD FILE TABLE VIEW STRUCT ENUM UNION LIKE";
    const string ControlTypes = "WINDOW REPORT MENU MENUBAR TOOLBAR SHEET TAB BUTTON CHECK COMBO CUSTOM DETAIL ELLIPSE ENTRY FOOTER FORM HEADER IMAGE ITEM KEY INDEX LINE LIST OCX OLE OLECONTROL OPTION PANEL PROGRESS PROJECT PROMPT RADIO REGION ROW SEPARATOR SPIN TEXT VBX";
    const string ProcedureModifiers = "PASCAL C RAW DLL PROC VIRTUAL PRIVATE PROTECTED EXTERNAL GLOBALCLASS";
    const string DataAttributes = "THREAD STATIC CONST DIM OVER PRE NAME BINDABLE TYPE AUTO INLINE";
    const string ControlAttributes = "ABOVE ABSOLUTE ALONE ALRT ANGLE AT AUTOSIZE AVE BELOW BEVEL BINARY BITMAP BOXED CAP CENTER CENTERED CNT COLOR COLUMN COM COMPATIBILITY CURSOR DEFAULT DELAY DERIVED DOCK DOCKED DOWN DRAGID DRIVER DROP DROPID DUP ENCRYPT EXPAND EXTEND FILL FILTER FIRST FIX FIXED FLAT FONT FROM FULL GRAY GRID HIDE HLP HSCROLL HVSCROLL ICON ICONIZE IMM IMPLEMENTS INNER INS LANDSCAPE LAST LATE LAYOUT LENGTH LFT LINEWIDTH LINK LOCATE MARK MASK MAX MAXIMIZE MDI META MIN MM MODAL MSG NOBAR NOCASE NOFRAME NOMEMO NOMERGE NOSHEET OEM OPT ORDER OUTER OVR OWNER PAGE PAGEAFTER PAGEBEFORE PALETTE PAPER PASSWORD POINTS PREVIEW PRIMARY RANGE READONLY RECLAIM REPEAT REQ RESIZE SCROLL SINGLE SMOOTH SPREAD STD STEP STRETCH SUM SUPPRESS TALLY TARGET THOUS TILED TIMER TIP TOGETHER TOOLBOX TRN UP UPR USE VALUE VERTICAL VCR VSCROLL WALLPAPER WIDTH WITHNEXT WITHPRIOR WIZARD WRAP ZOOM CHECK DOUBLE SEPARATOR PAGENO RTF SYSTEM JOIN DOCUMENT";
    const string Directives = "ASSERT BEGIN COMPILE EQUATE INCLUDE ITEMIZE OMIT ONCE SECTION SIZE";
    const string IoStatements = "OPEN CLOSE CREATE BUILD SET RESET NEXT PREVIOUS HOLD LOCK UNLOCK FLUSH SHARE FREE";
    const string DataStatements = "ADD GET PUT DELETE CLEAR REGET DUPLICATE MAXIMUM POSITION RECORDS FIXFORMAT UNFIXFORMAT FREESTATE GETNULLS GETSTATE RESTORESTATE SETNULLS SETNONULL SETNULL STATUS UNBIND ADDRESS POINTER CONTENTS BAND BOR BSHIFT BXOR";
    const string BuiltInFunctions = "ACCEPTED ACOS ALERT ALIAS ALL ARC ASIN ASK ATAN BEEP BINDEXPRESSION BLANK BOF BOX BUFFER BYTES CALL CENTER CHAIN CHANGE CHANGES CHOICE CHORD CHR CLIP CLIPBOARD CLOCK CLONE COLORDIALOG COMMAND COMMIT COMPRESS CONVERTANSITOOEM CONVERTOEMTOANSI COPY COS DATE DAY DEBUGHOOK DECOMPRESS DEFORMAT DELETEREG DESTROY DIRECTORY DISABLE DISPLAY DRAGID DROPID ELLIPSE EMPTY ENABLE ENDPAGE EOF ERASE ERROR ERRORCODE ERRORFILE EVALUATE EVENT EXISTS FIELD FILEDIALOG FILEDIALOGA FILEERROR FILEERRORCODE FILEEXISTS FIRSTFIELD FOCUS FONTDIALOG FONTDIALOGA FORWARDKEY FORMAT FREEZE FULLNAME GETEXITCODE GETFONT GETGROUP GETINI GETPOSITION GETREG GETREGSUBKEYS GETREGVALUES HALT HELP HIDE HOWMANY IDLE IMAGE INCOMPLETE INLIST INRANGE INSTRING INSTANCE INT ISALPHA ISGROUP ISLOWER ISSTRING ISUPPER KEYBOARD KEYCHAR KEYCODE KEYSTATE LASTFIELD LEFT LEN LINE LOCALE LOCKTHREAD LOG10 LOGE LOGOUT LONGPATH LOWER MATCH MESSAGE MONTH MOUSEX MOUSEY NAME NEXT NOMEMO NOTIFICATION NOTIFY NUMERIC OMITTED PACK PATH PEEK PENCOLOR PENSTYLE PENWIDTH PIE POKE POLYGON POPBIND POPERRORS POPUP POST PRAGMA PRESS PRESSKEY PREVIOUS PRINT PRINTER PRINTERDIALOG PRINTERDIALOGA PUSHBIND PUSHERRORS PUTREG PUTINI QUOTE RANDOM REGISTER REGISTEREVENT REJECTCODE RELEASE REMOVE RENAME RESUME RIGHT ROLLBACK ROUND ROUNDBOX RUN RUNCODE SAVEDIALOG SELECT SELECTED SEND SET3DLOOK SETCLIPBOARD SETCLOCK SETCOMMAND SETCURSOR SETDROPID SETEXITCODE SETFONT SETKEYCHAR SETKEYCODE SETLAYOUT SETPATH SETPENCOLOR SETPENSTYLE SETPENWIDTH SETPOSITION SETTARGET SETTODAY SHIFT SHORTPATH SHOW SHUTDOWN SIN SKIP SORT SQRT START STOP STREAM STRPOS SUB SUSPEND TAN THREAD THREADLOCKED TIE TIED TODAY TYPE UNFREEZE UNHIDE UNLOAD UNLOCKTHREAD UNQUOTE UNREGISTER UNREGISTEREVENT UNTIE UPDATE UPPER VAL WATCH WHAT WHERE WHO XOR YEAR YIELD ABS AFTER AGE APPEND BEFORE BIND DDEACKNOWLEDGE DDEAPP DDECHANNEL DDECLIENT DDECLOSE DDEEXECUTE DDEITEM DDEPOKE DDEQUERY DDEREAD DDESERVER DDETOPIC DDEVALUE DDEWRITE DECOMPRESS DISPOSE OCXLOADIMAGE OCXREGISTEREVENTPROC OCXREGISTERPROPCHANGE OCXREGISTERPROPEDIT OCXSETPARAM OCXUNREGISTEREVENTPROC OCXUNREGISTERPROPCHANGE OCXUNREGISTERPROPEDIT OLEDIRECTORY _PROC _PROC1 _PROC2 _PROC3";
    const string Constants = "TRUE FALSE";

    // word -> colour, built in the grammar's include order so shared words resolve the same way
    // (e.g. CHECK/DATE/LINE -> type, not attribute/function; THREAD/NAME/TYPE -> keyword, not function).
    static readonly Dictionary<string, Brush> Vocab = BuildVocab();

    static Dictionary<string, Brush> BuildVocab()
    {
        var map = new Dictionary<string, Brush>(StringComparer.OrdinalIgnoreCase);
        void Add(string words, Brush b) { foreach (var w in words.Split(' ', StringSplitOptions.RemoveEmptyEntries)) map.TryAdd(w, b); }
        Add(ControlFlow, Keyword);
        Add(Declarations, Keyword);
        Add(Oop, Keyword);
        Add(DataTypes, Type);
        Add(StructureTypes, Type);
        Add(ControlTypes, Type);
        Add(ProcedureModifiers, Keyword);
        Add(DataAttributes, Keyword);
        Add(ControlAttributes, Keyword);
        Add(Directives, Keyword);
        Add(IoStatements, Keyword);
        Add(DataStatements, Keyword);
        Add(BuiltInFunctions, Function);
        Add(Constants, Number);
        return map;
    }

    public static readonly DependencyProperty TextProperty = DependencyProperty.RegisterAttached(
        "Text", typeof(string), typeof(SyntaxHighlight),
        new PropertyMetadata(null, OnTextChanged));

    public static void SetText(DependencyObject o, string v) => o.SetValue(TextProperty, v);
    public static string? GetText(DependencyObject o) => (string?)o.GetValue(TextProperty);

    static void OnTextChanged(DependencyObject o, DependencyPropertyChangedEventArgs e)
    {
        if (o is not TextBlock tb) return;
        tb.Inlines.Clear();
        var line = e.NewValue as string ?? "";
        foreach (var (text, brush) in Tokenize(line))
            tb.Inlines.Add(new Run(text) { Foreground = brush });
    }

    static IEnumerable<(string, Brush)> Tokenize(string s)
    {
        int i = 0, n = s.Length;
        // a label (or statement) that begins at column 1 with no leading whitespace
        bool col1 = n > 0 && !char.IsWhiteSpace(s[0]);
        bool firstToken = true;
        while (i < n)
        {
            char c = s[i];
            if (c == '!' || c == '|')                      // comment to end of line ('|' = line continuation)
            { yield return (s[i..], Comment); yield break; }
            if (c == '\'')                                 // string literal
            {
                int j = i + 1;
                while (j < n && s[j] != '\'') j++;
                if (j < n) j++;                            // include closing quote
                yield return (s[i..j], Str); i = j; firstToken = false; continue;
            }
            if (c == '@' && i + 1 < n && char.IsLetter(s[i + 1]))   // picture token: @N9.2, @D6, @S30, @T3, @E12.4
            {
                int j = i + 2;
                while (j < n && (char.IsLetterOrDigit(s[j]) || s[j] is '.' or '_' or '-')) j++;
                if (j < n && s[j] == '~') { j++; while (j < n && s[j] != '~') j++; if (j < n) j++; }   // ~currency~ wrap
                yield return (s[i..j], Picture); i = j; firstToken = false; continue;
            }
            if (char.IsLetter(c) || c == '_')              // identifier / keyword / type / function / label
            {
                int j = i;
                while (j < n && (char.IsLetterOrDigit(s[j]) || s[j] == '_' || s[j] == ':')) j++;
                string word = s[i..j];
                Brush b = Vocab.TryGetValue(word, out var kw) ? kw
                        : (firstToken && col1 ? Label : Plain);
                yield return (word, b); i = j; firstToken = false; continue;
            }
            if (char.IsDigit(c))                           // number (incl. hex/binary/octal suffixes)
            {
                int j = i;
                while (j < n && (char.IsLetterOrDigit(s[j]) || s[j] == '.')) j++;
                yield return (s[i..j], Number); i = j; firstToken = false; continue;
            }
            if (!char.IsWhiteSpace(c)) firstToken = false;
            yield return (c.ToString(), Plain); i++;
        }
    }
}
