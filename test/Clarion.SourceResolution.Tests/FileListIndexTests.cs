using System;
using System.IO;
using Clarion.SourceResolution;
using Xunit;

namespace Clarion.SourceResolution.Tests
{
    public class FileListIndexTests
    {
        // Mirrors a real SCHOOL.cwproj.FileList.xml: UPPERCASE absolute paths,
        // a project .clw, an ABC/libsrc include, plus OBJ/EXE noise that must
        // not interfere with source resolution.
        private const string SampleXml =
@"<File_List name=""SCHOOL.cwproj"" version=""1"">
  <Opened_Files>
    <file name=""C:\CLARION\CLARION11.1\EXAMPLES\EXAMPLES\SCHOOL\SCHOOL001.CLW"" />
    <file name=""C:\CLARION\CLARION11.1\LIBSRC\WIN\ABWINDOW.INC"" />
    <file name=""C:\CLARION\CLARION11.1\EXAMPLES\EXAMPLES\SCHOOL\OBJ\DEBUG\SCHOOL001.OBJ"" />
    <file name=""C:\CLARION\CLARION11.1\EXAMPLES\EXAMPLES\SCHOOL\SCHOOL.EXE"" />
  </Opened_Files>
  <Created_Files>
    <file name=""C:\CLARION\CLARION11.1\EXAMPLES\EXAMPLES\SCHOOL\SCHOOL.EXE"" />
  </Created_Files>
</File_List>";

        [Fact]
        public void Resolve_MatchesByFilename_CaseInsensitive()
        {
            var path = WriteTemp(SampleXml, "SCHOOL.cwproj.FileList.xml");
            try
            {
                var idx = FileListIndex.Load(path);

                // TSWD hands lowercase-ish "SCHOOL001.clw" — resolves to the
                // UPPERCASE absolute path the compiler recorded.
                Assert.Equal(
                    @"C:\CLARION\CLARION11.1\EXAMPLES\EXAMPLES\SCHOOL\SCHOOL001.CLW",
                    idx.Resolve("SCHOOL001.clw"));

                // ABC/libsrc include resolved for free (no hardcoded libsrc list).
                Assert.Equal(
                    @"C:\CLARION\CLARION11.1\LIBSRC\WIN\ABWINDOW.INC",
                    idx.Resolve("abwindow.inc"));
            }
            finally { TryDelete(path); }
        }

        [Fact]
        public void Resolve_StemSharedAcrossExtensions_DoesNotCollide()
        {
            var path = WriteTemp(SampleXml, "SCHOOL.cwproj.FileList.xml");
            try
            {
                var idx = FileListIndex.Load(path);
                // SCHOOL001.CLW and SCHOOL001.OBJ share a stem but distinct keys.
                Assert.EndsWith("SCHOOL001.CLW", idx.Resolve("school001.clw"));
                Assert.EndsWith("SCHOOL001.OBJ", idx.Resolve("school001.obj"));
            }
            finally { TryDelete(path); }
        }

        [Fact]
        public void Resolve_Unknown_ReturnsNull()
        {
            var path = WriteTemp(SampleXml, "SCHOOL.cwproj.FileList.xml");
            try
            {
                Assert.Null(FileListIndex.Load(path).Resolve("nope.clw"));
            }
            finally { TryDelete(path); }
        }

        [Fact]
        public void Load_MissingFile_ReturnsEmptyIndex()
        {
            var missing = Path.Combine(Path.GetTempPath(), "no_" + Guid.NewGuid().ToString("N") + ".xml");
            var idx = FileListIndex.Load(missing);
            Assert.Equal(0, idx.Count);
            Assert.Null(idx.Resolve("anything.clw"));
        }

        [Fact]
        public void LoadMany_Merges_FirstFileWinsOnCollision()
        {
            const string xmlA =
@"<File_List><Opened_Files>
  <file name=""C:\A\SHARED.CLW"" />
  <file name=""C:\A\ONLYA.CLW"" />
</Opened_Files></File_List>";
            const string xmlB =
@"<File_List><Opened_Files>
  <file name=""C:\B\SHARED.CLW"" />
  <file name=""C:\B\ONLYB.CLW"" />
</Opened_Files></File_List>";

            var a = WriteTemp(xmlA, "A.cwproj.FileList.xml");
            var b = WriteTemp(xmlB, "B.cwproj.FileList.xml");
            try
            {
                var idx = FileListIndex.LoadMany(new[] { a, b });
                Assert.Equal(@"C:\A\SHARED.CLW", idx.Resolve("shared.clw")); // first wins
                Assert.Equal(@"C:\A\ONLYA.CLW", idx.Resolve("onlya.clw"));
                Assert.Equal(@"C:\B\ONLYB.CLW", idx.Resolve("onlyb.clw"));
            }
            finally { TryDelete(a); TryDelete(b); }
        }

        private static string WriteTemp(string content, string fileName)
        {
            var dir = Path.Combine(Path.GetTempPath(), "ClaFL_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, fileName);
            File.WriteAllText(path, content);
            return path;
        }

        private static void TryDelete(string path)
        {
            try
            {
                var dir = Path.GetDirectoryName(path);
                if (dir != null && Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
            catch { }
        }
    }
}
