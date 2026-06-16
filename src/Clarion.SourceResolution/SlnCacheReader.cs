using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Clarion.SourceResolution
{
    /// <summary>
    /// Reads the active build configuration from the MSBuild-generated
    /// <c>&lt;solution&gt;.sln.cache</c>. This is the FALLBACK config source
    /// (behind the IDE preferences file) — it only exists when the solution was
    /// last built through the .sln wrapper and is deleted on Clean, so callers
    /// must tolerate its absence. Read-only port of the extension's
    /// <c>SlnCacheUtils</c>; we never synthesize the file.
    /// </summary>
    public static class SlnCacheReader
    {
        private static readonly Regex ConfigTag = new Regex(
            @"<_SolutionProjectConfiguration>([^<]+)</_SolutionProjectConfiguration>",
            RegexOptions.Compiled);

        /// <summary>
        /// Returns the full "Config|Platform" string (e.g. "Release|Win32") from
        /// the .sln.cache next to <paramref name="slnPath"/>, or null if the
        /// file is missing or the tag is absent.
        /// </summary>
        public static string? ReadActiveConfiguration(string slnPath)
        {
            if (string.IsNullOrEmpty(slnPath))
                return null;
            var cachePath = slnPath + ".cache";
            if (!File.Exists(cachePath))
                return null;

            try
            {
                var content = File.ReadAllText(cachePath);
                var m = ConfigTag.Match(content);
                if (m.Success)
                {
                    var full = m.Groups[1].Value.Trim();
                    return full.Length > 0 ? full : null;
                }
            }
            catch { /* unreadable cache — treat as absent */ }
            return null;
        }

        /// <summary>Extracts the config name from a "Config|Platform" string ("Release|Win32" → "Release").</summary>
        public static string ConfigNameFromFull(string fullConfig) =>
            (fullConfig ?? string.Empty).Split('|')[0].Trim();
    }
}
