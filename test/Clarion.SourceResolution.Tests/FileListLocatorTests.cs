using System;
using System.IO;
using Clarion.SourceResolution;
using Xunit;

namespace Clarion.SourceResolution.Tests
{
    public class FileListLocatorTests
    {
        [Fact]
        public void GetDefaultPath_LowercasesConfigSegment()
        {
            var path = FileListLocator.GetDefaultPath(@"C:\Proj\School", "SCHOOL.cwproj", "Release");
            Assert.Equal(@"C:\Proj\School\obj\release\SCHOOL.cwproj.FileList.xml", path);
        }

        [Fact]
        public void Find_ReturnsDefaultPath_WhenPresent()
        {
            var projectDir = NewTempDir();
            try
            {
                var expected = FileListLocator.GetDefaultPath(projectDir, "SCHOOL.cwproj", "Debug");
                Directory.CreateDirectory(Path.GetDirectoryName(expected)!);
                File.WriteAllText(expected, "<File_List/>");

                Assert.Equal(expected, FileListLocator.Find(projectDir, "SCHOOL.cwproj", "Debug"));
            }
            finally { TryDeleteDir(projectDir); }
        }

        [Fact]
        public void Find_FallsBackToRecursiveSearch_PreferringRequestedConfig()
        {
            var projectDir = NewTempDir();
            try
            {
                // Put the FileList somewhere other than the default obj\debug,
                // and also a release copy, to prove config preference.
                var debugPath = Path.Combine(projectDir, "build", "obj", "Debug", "SCHOOL.cwproj.FileList.xml");
                var releasePath = Path.Combine(projectDir, "build", "obj", "Release", "SCHOOL.cwproj.FileList.xml");
                Directory.CreateDirectory(Path.GetDirectoryName(debugPath)!);
                Directory.CreateDirectory(Path.GetDirectoryName(releasePath)!);
                File.WriteAllText(debugPath, "<File_List/>");
                File.WriteAllText(releasePath, "<File_List/>");

                var found = FileListLocator.Find(projectDir, "SCHOOL.cwproj", "Release");
                Assert.Equal(releasePath, found);
            }
            finally { TryDeleteDir(projectDir); }
        }

        [Fact]
        public void Find_ReturnsNull_WhenNothingMatches()
        {
            var projectDir = NewTempDir();
            try
            {
                Assert.Null(FileListLocator.Find(projectDir, "SCHOOL.cwproj", "Debug"));
            }
            finally { TryDeleteDir(projectDir); }
        }

        private static string NewTempDir()
        {
            var dir = Path.Combine(Path.GetTempPath(), "ClaFLLoc_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDeleteDir(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
