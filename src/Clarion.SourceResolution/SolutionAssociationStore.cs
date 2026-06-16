using System;
using System.IO;
using System.Text.Json;

namespace Clarion.SourceResolution
{
    /// <summary>
    /// Reads and writes the <see cref="SolutionAssociation"/> JSON sidecar that
    /// sits next to a <c>.sln</c> (named <c>&lt;solution&gt;.sln.clarionsrc.json</c>,
    /// mirroring the <c>.sln.cache</c> convention). The debugger's first-open
    /// handshake writes it; subsequent opens read it so the user is asked once.
    /// </summary>
    public static class SolutionAssociationStore
    {
        private const string SidecarSuffix = ".clarionsrc.json";

        private static readonly JsonSerializerOptions WriteOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };

        private static readonly JsonSerializerOptions ReadOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };

        /// <summary>The sidecar path for a solution: <c>&lt;slnPath&gt;.clarionsrc.json</c>.</summary>
        public static string GetSidecarPath(string solutionPath)
        {
            if (solutionPath == null) throw new ArgumentNullException(nameof(solutionPath));
            return solutionPath + SidecarSuffix;
        }

        /// <summary>
        /// Reads the association for a solution, or null if no sidecar exists or
        /// it can't be parsed (caller then runs the first-open handshake).
        /// </summary>
        public static SolutionAssociation? Read(string solutionPath)
        {
            var path = GetSidecarPath(solutionPath);
            if (!File.Exists(path))
                return null;
            try
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<SolutionAssociation>(json, ReadOptions);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Writes (or overwrites) the association sidecar for a solution.</summary>
        public static void Write(string solutionPath, SolutionAssociation association)
        {
            if (association == null) throw new ArgumentNullException(nameof(association));
            var path = GetSidecarPath(solutionPath);
            var json = JsonSerializer.Serialize(association, WriteOptions);
            File.WriteAllText(path, json);
        }
    }
}
