using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public class AnalysisServiceTests
{
    [Theory]
    [InlineData("Get-Process")]
    [InlineData("Remove-Item .\\demo-cache -Recurse")]
    [InlineData("Write-Output \"unterminated")]
    public void Analyze_NeverClaimsUnimplementedInspectionIsSafe(
        string source)
    {
        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source, "sample.ps1")
        );

        Assert.Equal(
            AnalysisStatus.NotImplemented,
            result.Status
        );

        Assert.True(result.RulesSkipped);
        Assert.Empty(result.Findings);
        Assert.Empty(result.Diagnostics);

        Assert.Contains(
            result.Limitations,
            limitation => limitation.Contains(
                "No safety verdict",
                StringComparison.OrdinalIgnoreCase
            )
        );
    }

    [Fact]
    public void Analyze_EmptySourceRemainsNotImplemented()
    {
        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(string.Empty)
        );

        Assert.Equal(
            AnalysisStatus.NotImplemented,
            result.Status
        );

        Assert.True(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_NullRequestThrows()
    {
        var service = new AnalysisService();

        Assert.Throws<ArgumentNullException>(
            () => service.Analyze(null!)
        );
    }

    [Fact]
    public void Analyze_DoesNotExecutePowerShellSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-test-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'unexpected'";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(
            AnalysisStatus.NotImplemented,
            result.Status
        );

        Assert.False(File.Exists(marker));
    }
}
