using System.Text;
using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class BatchSourceSnapshotTests
{
    [Fact]
    public void AnalyzeFiles_CapturesOriginalSourceForCorrectDesktopNavigation()
    {
        string path = Path.Combine(Path.GetTempPath(),
            "bomb-squad-batch-snapshot-" + Guid.NewGuid().ToString("N") + ".ps1");

        try
        {
            const string inspected = "Remove-Item -LiteralPath 'cache'";
            File.WriteAllText(path, inspected, new UTF8Encoding(false));

            BatchAnalysisResult batch = new BatchAnalysisService()
                .AnalyzeFiles(new[] { path });

            File.WriteAllText(path, "Get-Date", new UTF8Encoding(false));

            BatchFileAnalysis file = Assert.Single(batch.Files);
            Assert.NotNull(file.Result);
            Assert.Equal(inspected, file.SourceText);
            Assert.Equal("BS-FS-001", Assert.Single(file.Result.Findings).RuleId);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void AnalyzeFiles_InputErrorsHaveNoSourceSnapshot()
    {
        string path = Path.Combine(Path.GetTempPath(),
            "bomb-squad-batch-missing-" + Guid.NewGuid().ToString("N") + ".ps1");

        BatchFileAnalysis file = Assert.Single(
            new BatchAnalysisService().AnalyzeFiles(new[] { path }).Files);

        Assert.NotNull(file.InputError);
        Assert.Null(file.SourceText);
    }
}
