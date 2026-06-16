using System;
using System.IO;
using Clarion.SourceResolution;
using Xunit;

namespace Clarion.SourceResolution.Tests
{
    public class SolutionAssociationTests
    {
        [Fact]
        public void GetSidecarPath_IsSlnPathPlusSuffix()
        {
            Assert.Equal(
                @"C:\proj\MyApp.sln.clarionsrc.json",
                SolutionAssociationStore.GetSidecarPath(@"C:\proj\MyApp.sln"));
        }

        [Fact]
        public void WriteThenRead_RoundTrips()
        {
            var dir = NewTempDir();
            try
            {
                var sln = Path.Combine(dir, "MyApp.sln");
                var assoc = new SolutionAssociation
                {
                    VersionName = "Clarion 11.1.13855",
                    PropertiesFile = @"D:\Custom\ConfigDir\ClarionProperties.xml",
                    ConfigurationOverride = "Release",
                    ExePath = Path.Combine(dir, "MyApp.exe"),
                };

                SolutionAssociationStore.Write(sln, assoc);
                var read = SolutionAssociationStore.Read(sln);

                Assert.NotNull(read);
                Assert.Equal(1, read!.SchemaVersion);
                Assert.Equal("Clarion 11.1.13855", read.VersionName);
                Assert.Equal(@"D:\Custom\ConfigDir\ClarionProperties.xml", read.PropertiesFile);
                Assert.Equal("Release", read.ConfigurationOverride);
                Assert.Equal(Path.Combine(dir, "MyApp.exe"), read.ExePath);
            }
            finally { TryDeleteDir(dir); }
        }

        [Fact]
        public void Read_MissingSidecar_ReturnsNull()
        {
            var dir = NewTempDir();
            try
            {
                Assert.Null(SolutionAssociationStore.Read(Path.Combine(dir, "Nope.sln")));
            }
            finally { TryDeleteDir(dir); }
        }

        [Fact]
        public void Read_CorruptSidecar_ReturnsNull()
        {
            var dir = NewTempDir();
            try
            {
                var sln = Path.Combine(dir, "Bad.sln");
                File.WriteAllText(SolutionAssociationStore.GetSidecarPath(sln), "{ not valid json ");
                Assert.Null(SolutionAssociationStore.Read(sln));
            }
            finally { TryDeleteDir(dir); }
        }

        [Fact]
        public void CreateFromAssociation_UsesExplicitPropertiesFile_AndResolves()
        {
            using var lay = new AssocLayout();
            // Sidecar points at the explicit (non-default) ClarionProperties.xml
            // and forces Debug — exercises the ConfigDir-override path.
            SolutionAssociationStore.Write(lay.SlnPath, new SolutionAssociation
            {
                VersionName = "Clarion 11.1",
                PropertiesFile = lay.PropertiesFile,
                ConfigurationOverride = "Debug",
            });

            var resolver = ClarionSourceResolver.CreateFromAssociation(lay.SlnPath);

            Assert.NotNull(resolver);
            Assert.Equal("Debug", resolver!.Configuration);
            Assert.Equal("Clarion 11.1", resolver.Version.Name);
            // Resolves a project source via the redirection Common catch-all.
            Assert.Equal(
                Path.Combine(lay.ProjDir, "Main.clw"),
                resolver.Resolve("Main.clw"));
        }

        [Fact]
        public void CreateFromAssociation_NoSidecar_ReturnsNull()
        {
            using var lay = new AssocLayout();
            Assert.Null(ClarionSourceResolver.CreateFromAssociation(lay.SlnPath));
        }

        // A layout with a real ClarionProperties.xml so the detector can resolve
        // the version named in the sidecar.
        private sealed class AssocLayout : IDisposable
        {
            public string Root { get; }
            public string BinDir { get; }
            public string ProjDir { get; }
            public string SlnPath { get; }
            public string PropertiesFile { get; }

            public AssocLayout()
            {
                Root = Path.Combine(Path.GetTempPath(), "ClaAssoc_" + Guid.NewGuid().ToString("N"));
                BinDir = Path.Combine(Root, "bin");
                ProjDir = Path.Combine(Root, "proj");
                Directory.CreateDirectory(BinDir);
                Directory.CreateDirectory(ProjDir);

                File.WriteAllText(Path.Combine(BinDir, "Clarion110.red"),
                    "[Common]\n*.* = .\n");

                SlnPath = Path.Combine(ProjDir, "MyApp.sln");
                File.WriteAllText(SlnPath,
@"
Project(""{12B76EC0-1D7B-4FA7-A7D0-C524288B48A1}"") = ""MyApp"", ""MyApp.cwproj"", ""{11111111-1111-1111-1111-111111111111}""
EndProject");
                File.WriteAllText(Path.Combine(ProjDir, "MyApp.cwproj"),
@"<Project xmlns=""http://schemas.microsoft.com/developer/msbuild/2003"">
  <PropertyGroup><ProjectGuid>{11111111-1111-1111-1111-111111111111}</ProjectGuid><OutputType>Exe</OutputType></PropertyGroup>
</Project>");
                File.WriteAllText(Path.Combine(ProjDir, "Main.clw"), "  CODE\n");

                // Explicit (non-default) ClarionProperties.xml referencing this install.
                PropertiesFile = Path.Combine(Root, "config", "ClarionProperties.xml");
                Directory.CreateDirectory(Path.GetDirectoryName(PropertiesFile)!);
                File.WriteAllText(PropertiesFile,
$@"<ClarionProperties>
  <Properties name=""Clarion.Versions"">
    <Properties name=""Clarion 11.1"">
      <path value=""{BinDir}"" />
      <Properties name=""RedirectionFile"">
        <Name value=""Clarion110.red"" />
        <Properties name=""Macros""><root value=""{Root}"" /></Properties>
      </Properties>
      <libsrc value=""{Root}"" />
    </Properties>
  </Properties>
</ClarionProperties>");
            }

            public void Dispose()
            {
                try { if (Directory.Exists(Root)) Directory.Delete(Root, true); } catch { }
            }
        }

        private static string NewTempDir()
        {
            var dir = Path.Combine(Path.GetTempPath(), "ClaAssocS_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDeleteDir(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
        }
    }
}
