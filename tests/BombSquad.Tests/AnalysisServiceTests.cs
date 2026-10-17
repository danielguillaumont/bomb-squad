using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public class AnalysisServiceTests
{
    [Theory]
    [InlineData("Get-Process", "Get-Process")]
    [InlineData("Remove-Item .\\demo-cache -Recurse", "Remove-Item")]
    public void Analyze_ValidSourceReportsParsingOnly(
        string source,
        string expectedCommand)
    {
        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source, "sample.ps1")
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Single(result.Commands);
        Assert.Equal(
            expectedCommand,
            result.Commands[0].CommandName
        );

        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.True(result.RulesSkipped);

        Assert.Contains(
            result.Limitations,
            limitation => limitation.Contains(
                "No safety verdict",
                StringComparison.OrdinalIgnoreCase
            )
        );
    }

    [Fact]
    public void Analyze_MalformedSourcePreservesDiagnostics()
    {
        const string source = "Write-Output \"unterminated";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(
            AnalysisStatus.ParsedWithErrors,
            result.Status
        );

        Assert.NotEmpty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.True(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_EmptySourceReturnsNoCommands()
    {
        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(string.Empty)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Commands);
        Assert.Empty(result.Findings);
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
    public void Analyze_DoesNotExecuteImportedSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-service-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Single(result.Commands);
        Assert.Equal(
            "Set-Content",
            result.Commands[0].CommandName
        );

        Assert.False(File.Exists(marker));
        Assert.Empty(result.Findings);
        Assert.True(result.RulesSkipped);
    }
}
