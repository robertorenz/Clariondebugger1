using System;
using System.Collections.Generic;
using System.IO;
using System.Xml.Linq;

namespace Clarion.SourceResolution
{
    /// <summary>
    /// A filename → absolute-path lookup built from a Clarion compiler
    /// <c>&lt;proj&gt;.cwproj.FileList.xml</c>'s <c>&lt;Opened_Files&gt;</c> section.
    ///
    /// This is the debugger's PRIMARY source resolver: the compiler already ran
    /// redirection and recorded the exact absolute path of every file it opened
    /// (project .clw plus all ABC/libsrc includes), config-correct (it lives in
    /// obj\&lt;config&gt;). Resolving a TSWD module name therefore collapses to a
    /// dictionary lookup, with the ported redirection engine kept only as a
    /// fallback for when this build artifact is absent/stale.
    ///
    /// Keys are the file name (with extension) lowercased, so OBJ/CLW siblings
    /// that share a stem don't collide. On a same-name-same-extension clash
    /// across directories, first occurrence wins (matching the compiler's own
    /// first-match redirection semantics).
    /// </summary>
    public sealed class FileListIndex
    {
        private readonly Dictionary<string, string> _byName;

        private FileListIndex(Dictionary<string, string> byName) => _byName = byName;

        /// <summary>Number of distinct opened files indexed.</summary>
        public int Count => _byName.Count;

        /// <summary>
        /// Resolves a module / file name (e.g. "SCHOOL001.clw") to its absolute
        /// path, or null if not present. Any directory part on the input is
        /// ignored — only the file name is matched, case-insensitively.
        /// </summary>
        public string? Resolve(string moduleName)
        {
            if (string.IsNullOrEmpty(moduleName))
                return null;
            var key = Path.GetFileName(moduleName).ToLowerInvariant();
            return _byName.TryGetValue(key, out var path) ? path : null;
        }

        /// <summary>True if the index contains the given file name.</summary>
        public bool Contains(string moduleName) => Resolve(moduleName) != null;

        /// <summary>
        /// Loads an index from a single FileList.xml. Returns an empty index if
        /// the file is missing or unparseable (callers treat empty as "fall
        /// back to redirection").
        /// </summary>
        public static FileListIndex Load(string fileListXmlPath)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            AddFromFile(map, fileListXmlPath);
            return new FileListIndex(map);
        }

        /// <summary>
        /// Loads and merges several FileList.xml files into one index — used for
        /// multi-project / multi-DLL targets (the EXE plus sibling debug DLLs,
        /// each with its own FileList). First file wins on key collisions.
        /// </summary>
        public static FileListIndex LoadMany(IEnumerable<string> fileListXmlPaths)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (fileListXmlPaths != null)
                foreach (var path in fileListXmlPaths)
                    AddFromFile(map, path);
            return new FileListIndex(map);
        }

        private static void AddFromFile(Dictionary<string, string> map, string fileListXmlPath)
        {
            if (string.IsNullOrEmpty(fileListXmlPath) || !File.Exists(fileListXmlPath))
                return;

            XDocument doc;
            try { doc = XDocument.Load(fileListXmlPath); }
            catch { return; }

            var opened = doc.Root?.Element("Opened_Files");
            if (opened == null)
                return;

            foreach (var file in opened.Elements("file"))
            {
                var full = (string?)file.Attribute("name");
                if (string.IsNullOrEmpty(full))
                    continue;

                var key = Path.GetFileName(full).ToLowerInvariant();
                if (key.Length == 0)
                    continue;

                // First-match wins (don't overwrite an earlier index's entry).
                if (!map.ContainsKey(key))
                    map[key] = full!;
            }
        }
    }
}
