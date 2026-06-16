using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Clarion.SourceResolution
{
    /// <summary>Which strategy resolved a source file.</summary>
    public enum SourceOrigin
    {
        /// <summary>From a compiler FileList.xml index (the primary, pre-resolved path).</summary>
        FileList,
        /// <summary>From the redirection engine (the fallback resolver).</summary>
        Redirection,
    }

    /// <summary>A facade resolution result: the absolute path and how it was found.</summary>
    public sealed class SourceLookup
    {
        public string Path { get; }
        public SourceOrigin Origin { get; }
        /// <summary>For redirection hits, the underlying source tier; null for FileList hits.</summary>
        public FilePathSource? RedirectionSource { get; }

        public SourceLookup(string path, SourceOrigin origin, FilePathSource? redirectionSource = null)
        {
            Path = path;
            Origin = origin;
            RedirectionSource = redirectionSource;
        }
    }

    /// <summary>
    /// The single entry point the debugger consumes. Given a solution, a chosen
    /// Clarion version, and its ClarionProperties.xml, it wires the package's
    /// building blocks into one <see cref="Resolve(string)"/> call:
    ///
    ///  - resolves the active configuration (IDE prefs → .sln.cache → default),
    ///  - parses the solution's projects,
    ///  - for each project locates and indexes its FileList.xml (primary), and
    ///    builds a redirection parser (fallback),
    ///  - resolves a module name FileList-first, then redirection across projects.
    ///
    /// Solution-centric by design: the debugger's first-open handshake supplies
    /// the (solution, version, config) anchors; a bare EXE with no associated
    /// solution stays on the debugger's legacy lookup.
    /// </summary>
    public sealed class ClarionSourceResolver
    {
        private readonly FileListIndex _fileList;
        private readonly IReadOnlyList<RedirectionParser> _redParsers;

        /// <summary>The parsed solution.</summary>
        public ClarionSolution Solution { get; }

        /// <summary>The chosen Clarion compiler version.</summary>
        public ClarionCompilerVersion Version { get; }

        /// <summary>The resolved active configuration name (e.g. "Debug").</summary>
        public string Configuration { get; }

        /// <summary>Number of files indexed across all project FileLists (0 ⇒ redirection-only).</summary>
        public int FileListCount => _fileList.Count;

        private ClarionSourceResolver(
            ClarionSolution solution,
            ClarionCompilerVersion version,
            string configuration,
            FileListIndex fileList,
            IReadOnlyList<RedirectionParser> redParsers)
        {
            Solution = solution;
            Version = version;
            Configuration = configuration;
            _fileList = fileList;
            _redParsers = redParsers;
        }

        /// <summary>
        /// Builds a resolver for <paramref name="solutionPath"/> against the
        /// chosen <paramref name="version"/>. <paramref name="propertiesFile"/>
        /// is the version's ClarionProperties.xml (used to locate the IDE prefs
        /// for config). <paramref name="configurationOverride"/>, if supplied,
        /// wins over auto-detection.
        /// </summary>
        public static ClarionSourceResolver Create(
            string solutionPath,
            ClarionCompilerVersion version,
            string propertiesFile,
            string? configurationOverride = null)
        {
            if (solutionPath == null) throw new ArgumentNullException(nameof(solutionPath));
            if (version == null) throw new ArgumentNullException(nameof(version));

            var configuration = ResolveConfiguration(solutionPath, propertiesFile, configurationOverride);
            var solution = SolutionParser.Parse(solutionPath);

            var fileListPaths = new List<string>();
            var redParsers = new List<RedirectionParser>();

            foreach (var project in solution.Projects)
            {
                var fileList = FileListLocator.Find(project.ProjectDir, project.ProjectFileName, configuration);
                if (fileList != null)
                    fileListPaths.Add(fileList);

                var parser = new RedirectionParser(
                    RedirectionContext.FromVersion(version, project.ProjectDir, configuration));
                parser.Parse();
                redParsers.Add(parser);
            }

            // A solution with no .cwproj entries still gets a redirection parser
            // anchored on the solution dir, so bare lookups have somewhere to go.
            if (redParsers.Count == 0)
            {
                var parser = new RedirectionParser(
                    RedirectionContext.FromVersion(version, solution.SolutionDir, configuration));
                parser.Parse();
                redParsers.Add(parser);
            }

            return new ClarionSourceResolver(
                solution, version, configuration,
                FileListIndex.LoadMany(fileListPaths), redParsers);
        }

        /// <summary>Convenience overload taking a detected installation (uses its PropertiesPath).</summary>
        public static ClarionSourceResolver Create(
            string solutionPath,
            ClarionInstallation installation,
            ClarionCompilerVersion version,
            string? configurationOverride = null)
        {
            if (installation == null) throw new ArgumentNullException(nameof(installation));
            return Create(solutionPath, version, installation.PropertiesPath, configurationOverride);
        }

        /// <summary>
        /// Builds a resolver from the solution's persisted
        /// <see cref="SolutionAssociation"/> sidecar — the reopen path that needs
        /// no prompts. Resolves the install from the sidecar's explicit
        /// PropertiesFile (ConfigDir override) if set, else by version name across
        /// detected installs, else the most recent install. Returns null if there
        /// is no sidecar or the version can't be resolved (caller then runs the
        /// first-open handshake).
        /// </summary>
        public static ClarionSourceResolver? CreateFromAssociation(string solutionPath)
        {
            var assoc = SolutionAssociationStore.Read(solutionPath);
            if (assoc == null)
                return null;

            ClarionInstallation? install = null;
            if (!string.IsNullOrEmpty(assoc.PropertiesFile))
                install = ClarionInstallationDetector.ParseInstallationFromPropertiesPath(assoc.PropertiesFile!);

            if (install == null && !string.IsNullOrEmpty(assoc.VersionName))
                install = ClarionInstallationDetector.DetectInstallations()
                    .FirstOrDefault(i => i.CompilerVersions.Any(v =>
                        string.Equals(v.Name, assoc.VersionName, StringComparison.OrdinalIgnoreCase)));

            install ??= ClarionInstallationDetector.GetMostRecentInstallation();
            if (install == null)
                return null;

            var version = (!string.IsNullOrEmpty(assoc.VersionName)
                ? install.CompilerVersions.FirstOrDefault(v =>
                    string.Equals(v.Name, assoc.VersionName, StringComparison.OrdinalIgnoreCase))
                : null) ?? install.CompilerVersions.FirstOrDefault();
            if (version == null)
                return null;

            return Create(solutionPath, version, install.PropertiesPath, assoc.ConfigurationOverride);
        }

        /// <summary>
        /// Resolves a TSWD module / file name (e.g. "MyProc.clw") to an absolute
        /// path, FileList-first then redirection across projects. Returns null if
        /// nothing resolves.
        /// </summary>
        public string? Resolve(string moduleName) => ResolveDetailed(moduleName)?.Path;

        /// <summary>
        /// As <see cref="Resolve(string)"/> but reports which strategy produced
        /// the hit (useful for the debugger's source-pane label / diagnostics).
        /// </summary>
        public SourceLookup? ResolveDetailed(string moduleName)
        {
            if (string.IsNullOrEmpty(moduleName))
                return null;

            // 1. FileList index — pre-resolved, config-correct, the hot path.
            var fromList = _fileList.Resolve(moduleName);
            if (fromList != null)
                return new SourceLookup(fromList, SourceOrigin.FileList);

            // 2. Redirection fallback — first project that resolves it wins.
            foreach (var parser in _redParsers)
            {
                var hit = parser.FindFile(moduleName);
                if (hit != null)
                    return new SourceLookup(hit.Path, SourceOrigin.Redirection, hit.Source);
            }

            return null;
        }

        /// <summary>
        /// Resolves the active configuration name using the documented chain:
        /// explicit override → IDE preferences (<c>ActiveConfiguration</c>) →
        /// <c>.sln.cache</c> → "Debug" default.
        /// </summary>
        public static string ResolveConfiguration(
            string solutionPath, string? propertiesFile, string? configurationOverride)
        {
            if (!string.IsNullOrWhiteSpace(configurationOverride))
                return configurationOverride!.Trim();

            if (!string.IsNullOrEmpty(propertiesFile))
            {
                var prefs = IdePreferencesReader.ReadIdePreferences(solutionPath, propertiesFile!);
                if (!string.IsNullOrEmpty(prefs?.ActiveConfiguration))
                    return prefs!.ActiveConfiguration!;
            }

            var cacheFull = SlnCacheReader.ReadActiveConfiguration(solutionPath);
            if (!string.IsNullOrEmpty(cacheFull))
                return SlnCacheReader.ConfigNameFromFull(cacheFull!);

            return "Debug";
        }
    }
}
