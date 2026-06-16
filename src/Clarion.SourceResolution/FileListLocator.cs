using System;
using System.IO;
using System.Linq;

namespace Clarion.SourceResolution
{
    /// <summary>
    /// Locates a project's <c>&lt;proj&gt;.cwproj.FileList.xml</c> on disk.
    ///
    /// Its location is itself redirection-driven — the version's global red
    /// (e.g. <c>Clarion110.red</c>) forces <c>*.FileList.xml = obj\&lt;config&gt;</c>
    /// (anchored on the project dir), so it is NOT a hard compiler default.
    /// In practice ~every install uses the shipped red, so the default
    /// <c>&lt;projectDir&gt;\obj\&lt;config&gt;\</c> path is tried first; a recursive
    /// search is the fallback for projects whose local red redirects obj output
    /// elsewhere. (Resolving the single <c>*.FileList.xml</c> rule through the
    /// ported redirection engine is the exact route once that engine lands.)
    /// </summary>
    public static class FileListLocator
    {
        private const string FileListSuffix = ".FileList.xml";

        /// <summary>
        /// The default path: <c>&lt;projectDir&gt;\obj\&lt;config&gt;\&lt;cwprojFileName&gt;.FileList.xml</c>.
        /// The config segment is lowercased to match the shipped red's
        /// <c>obj\debug</c> / <c>obj\release</c> (Windows FS is case-insensitive
        /// anyway, but this keeps the path canonical).
        /// </summary>
        /// <param name="projectDir">The directory containing the .cwproj.</param>
        /// <param name="cwprojFileName">The .cwproj file name, e.g. "SCHOOL.cwproj".</param>
        /// <param name="configuration">e.g. "Debug" / "Release".</param>
        public static string GetDefaultPath(string projectDir, string cwprojFileName, string configuration)
        {
            if (projectDir == null) throw new ArgumentNullException(nameof(projectDir));
            if (cwprojFileName == null) throw new ArgumentNullException(nameof(cwprojFileName));
            if (configuration == null) throw new ArgumentNullException(nameof(configuration));

            return Path.Combine(
                projectDir, "obj", configuration.ToLowerInvariant(),
                cwprojFileName + FileListSuffix);
        }

        /// <summary>
        /// Returns the FileList.xml path for the project+config: the default
        /// path if it exists, else the best recursive match under
        /// <paramref name="projectDir"/> (preferring one under the requested
        /// config's obj folder), else null.
        /// </summary>
        public static string? Find(string projectDir, string cwprojFileName, string configuration)
        {
            var defaultPath = GetDefaultPath(projectDir, cwprojFileName, configuration);
            if (File.Exists(defaultPath))
                return defaultPath;

            if (!Directory.Exists(projectDir))
                return null;

            var wanted = cwprojFileName + FileListSuffix;
            string[] matches;
            try
            {
                matches = Directory.GetFiles(projectDir, wanted, SearchOption.AllDirectories);
            }
            catch
            {
                return null;
            }

            if (matches.Length == 0)
                return null;

            // Prefer a match sitting under obj\<config> for the requested config.
            var configSegment = Path.DirectorySeparatorChar + "obj" +
                                Path.DirectorySeparatorChar + configuration;
            var preferred = matches.FirstOrDefault(m =>
                m.IndexOf(configSegment, StringComparison.OrdinalIgnoreCase) >= 0);

            return preferred ?? matches[0];
        }
    }
}
