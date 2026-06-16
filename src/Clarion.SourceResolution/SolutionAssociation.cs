using System.Text.Json.Serialization;

namespace Clarion.SourceResolution
{
    /// <summary>
    /// The per-solution association the debugger records when a user first opens
    /// a solution outside the IDE: which Clarion version (and, if non-default,
    /// which ClarionProperties.xml) it belongs to, plus optional overrides.
    /// Persisted as a JSON sidecar in the solution directory (see
    /// <see cref="SolutionAssociationStore"/>); JSON is used so the schema can be
    /// shared with the TypeScript Clarion-Extension.
    /// </summary>
    public sealed class SolutionAssociation
    {
        /// <summary>Schema version for forward compatibility.</summary>
        [JsonPropertyName("schemaVersion")]
        public int SchemaVersion { get; set; } = 1;

        /// <summary>The chosen compiler version name, e.g. "Clarion 11.1.13855".</summary>
        [JsonPropertyName("versionName")]
        public string? VersionName { get; set; }

        /// <summary>
        /// Explicit ClarionProperties.xml path, for installs whose config lives
        /// in a non-default location (the ConfigDir override). Null ⇒ use default
        /// AppData detection by <see cref="VersionName"/>.
        /// </summary>
        [JsonPropertyName("propertiesFile")]
        public string? PropertiesFile { get; set; }

        /// <summary>Forces a build configuration (e.g. "Debug"). Null ⇒ auto-detect (prefs → .sln.cache).</summary>
        [JsonPropertyName("configurationOverride")]
        public string? ConfigurationOverride { get; set; }

        /// <summary>Optional: the EXE this solution debugs (EXE↔solution mapping).</summary>
        [JsonPropertyName("exePath")]
        public string? ExePath { get; set; }
    }
}
