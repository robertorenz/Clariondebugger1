using System;
using System.Collections.Generic;
using System.IO;
using Clarion.SourceResolution;
using Xunit;

namespace Clarion.SourceResolution.Tests
{
    public class ClarionSourceResolverTests
    {
        // Builds a realistic install + solution on disk and tears it down.
        private sealed class Layout : IDisposable
        {
            public string Root { get; }
            public string BinDir { get; }
            public string ProjDir { get; }
            public string LibSrcDir { get; }
            public string SlnPath { get; }
            public string PropertiesFile { get; }

            public Layout()
            {
                Root = Path.Combine(Path.GetTempPath(), "ClaFacade_" + Guid.NewGuid().ToString("N"));
                BinDir = Path.Combine(Root, "bin");
                ProjDir = Path.Combine(Root, "proj");
                LibSrcDir = Path.Combine(Root, "libsrc", "win");
                Directory.CreateDirectory(BinDir);
                Directory.CreateDirectory(ProjDir);
                Directory.CreateDirectory(LibSrcDir);

                // Global red: obj routing + a Common catch-all on the project dir.
                File.WriteAllText(Path.Combine(BinDir, "Clarion110.red"),
@"[Debug]
*.FileList.xml = obj\debug
[Common]
*.* = .; %ROOT%\libsrc\win
");

                // Solution with one EXE project.
                SlnPath = Path.Combine(ProjDir, "MyApp.sln");
                File.WriteAllText(SlnPath,
@"
Microsoft Visual Studio Solution File, Format Version 12.00
Project(""{12B76EC0-1D7B-4FA7-A7D0-C524288B48A1}"") = ""MyApp"", ""MyApp.cwproj"", ""{11111111-1111-1111-1111-111111111111}""
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Win32 = Debug|Win32
	EndGlobalSection
EndGlobal");
                File.WriteAllText(Path.Combine(ProjDir, "MyApp.cwproj"),
@"<Project xmlns=""http://schemas.microsoft.com/developer/msbuild/2003"">
  <PropertyGroup>
    <ProjectGuid>{11111111-1111-1111-1111-111111111111}</ProjectGuid>
    <OutputType>Exe</OutputType>
    <AssemblyName>MyApp</AssemblyName>
  </PropertyGroup>
</Project>");

                // A FileList in obj\debug listing one source by absolute path.
                var inListPath = Path.Combine(ProjDir, "Generated", "InList.clw");
                Directory.CreateDirectory(Path.GetDirectoryName(inListPath)!);
                File.WriteAllText(inListPath, "  CODE\n");
                var flDir = Path.Combine(ProjDir, "obj", "debug");
                Directory.CreateDirectory(flDir);
                File.WriteAllText(Path.Combine(flDir, "MyApp.cwproj.FileList.xml"),
                    $"<File_List><Opened_Files><file name=\"{inListPath}\" /></Opened_Files></File_List>");

                // A source NOT in the FileList, resolvable only via redirection
                // (Common catch-all → project dir).
                File.WriteAllText(Path.Combine(ProjDir, "ViaRed.clw"), "  CODE\n");

                // ClarionProperties.xml location (only its path matters for prefs).
                PropertiesFile = Path.Combine(Root, "appdata", "11.0", "ClarionProperties.xml");
                Directory.CreateDirectory(Path.GetDirectoryName(PropertiesFile)!);
                File.WriteAllText(PropertiesFile, "<ClarionProperties/>");
            }

            public string InListExpectedPath => Path.Combine(ProjDir, "Generated", "InList.clw");

            public ClarionCompilerVersion Version() => new ClarionCompilerVersion
            {
                Name = "Clarion 11.1",
                Path = BinDir,
                RedirectionFile = "Clarion110.red",
                LibSrc = Path.Combine(Root, "libsrc", "win"),
                Macros = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["root"] = Root },
            };

            // Drops an IDE prefs file at the hashed location for this solution.
            public void WritePrefs(string activeConfiguration)
            {
                var prefsPath = IdePreferencesReader.GetPreferencesFilePath(SlnPath, PropertiesFile);
                Directory.CreateDirectory(Path.GetDirectoryName(prefsPath)!);
                File.WriteAllText(prefsPath,
                    $"<Properties><ActiveConfiguration value=\"{activeConfiguration}\" /><ActivePlatform value=\"Win32\" /></Properties>");
            }

            public void WriteSlnCache(string fullConfig)
            {
                File.WriteAllText(SlnPath + ".cache",
                    $"<Project><PropertyGroup><_SolutionProjectConfiguration>{fullConfig}</_SolutionProjectConfiguration></PropertyGroup></Project>");
            }

            public void Dispose()
            {
                try { if (Directory.Exists(Root)) Directory.Delete(Root, true); } catch { }
            }
        }

        [Fact]
        public void Resolve_PrefersFileList_ThenRedirection()
        {
            using var lay = new Layout();
            var resolver = ClarionSourceResolver.Create(
                lay.SlnPath, lay.Version(), lay.PropertiesFile, configurationOverride: "Debug");

            // In the FileList → comes back as a FileList hit at the recorded path.
            var inList = resolver.ResolveDetailed("InList.clw");
            Assert.NotNull(inList);
            Assert.Equal(SourceOrigin.FileList, inList!.Origin);
            Assert.Equal(lay.InListExpectedPath, inList.Path);

            // Not in the FileList → redirection Common catch-all finds it in proj dir.
            var viaRed = resolver.ResolveDetailed("ViaRed.clw");
            Assert.NotNull(viaRed);
            Assert.Equal(SourceOrigin.Redirection, viaRed!.Origin);
            Assert.Equal(Path.Combine(lay.ProjDir, "ViaRed.clw"), viaRed.Path);

            // Neither → null.
            Assert.Null(resolver.Resolve("Ghost.clw"));
            Assert.True(resolver.FileListCount >= 1);
            Assert.Equal("Debug", resolver.Configuration);
        }

        [Fact]
        public void ResolveConfiguration_OverrideWins()
        {
            using var lay = new Layout();
            lay.WritePrefs("Debug");
            lay.WriteSlnCache("Release|Win32");
            Assert.Equal("Release",
                ClarionSourceResolver.ResolveConfiguration(lay.SlnPath, lay.PropertiesFile, "Release"));
        }

        [Fact]
        public void ResolveConfiguration_PrefsBeatSlnCache()
        {
            using var lay = new Layout();
            lay.WritePrefs("Release");          // prefs say Release
            lay.WriteSlnCache("Debug|Win32");   // cache says Debug
            Assert.Equal("Release",
                ClarionSourceResolver.ResolveConfiguration(lay.SlnPath, lay.PropertiesFile, null));
        }

        [Fact]
        public void ResolveConfiguration_FallsBackToSlnCache_ThenDefault()
        {
            using var lay = new Layout();
            // No prefs written. sln.cache present → used.
            lay.WriteSlnCache("Release|Win32");
            Assert.Equal("Release",
                ClarionSourceResolver.ResolveConfiguration(lay.SlnPath, lay.PropertiesFile, null));

            // Remove the cache → default Debug.
            File.Delete(lay.SlnPath + ".cache");
            Assert.Equal("Debug",
                ClarionSourceResolver.ResolveConfiguration(lay.SlnPath, lay.PropertiesFile, null));
        }

        [Fact]
        public void Create_UsesResolvedConfig_FromPrefs_WhenNoOverride()
        {
            using var lay = new Layout();
            lay.WritePrefs("Debug");
            var resolver = ClarionSourceResolver.Create(lay.SlnPath, lay.Version(), lay.PropertiesFile);
            Assert.Equal("Debug", resolver.Configuration);
            Assert.Equal("MyApp", resolver.Solution.Projects[0].Name);
        }
    }
}
