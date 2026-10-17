using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public class AnalysisServiceTests
{
    [Theory]
    [InlineData("Get-Process", "Get-Process", 0)]
    [InlineData("Remove-Item .\\demo-cache -Recurse", "Remove-Item", 1)]
    public void Analyze_ValidSourceEvaluatesImplementedRules(
        string source,
        string expectedCommand,
        int expectedFindingCount)
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
        Assert.Equal(expectedFindingCount, result.Findings.Length);
        Assert.False(result.RulesSkipped);

        Assert.Contains(
            result.Limitations,
            limitation => limitation.Contains(
                "absence of findings",
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
    public void Analyze_MalformedSourceSkipsRulesEvenWithRemoveItem()
    {
        const string source =
            "Remove-Item -Path 'demo-cache'\n" +
            "Write-Output 'unterminated";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(
            AnalysisStatus.ParsedWithErrors,
            result.Status
        );

        Assert.Contains(
            result.Commands,
            command => command.CommandName == "Remove-Item"
        );

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
        Assert.False(result.RulesSkipped);
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
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_FindingPreservesExactSourceEvidence()
    {
        const string source =
            "Get-Date\nRemove-Item -LiteralPath 'demo-cache'";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Finding finding = Assert.Single(result.Findings);

        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Equal(FindingFamily.Filesystem, finding.Family);
        Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Equal(2, finding.SourceSpan.StartLine);
        Assert.Equal(1, finding.SourceSpan.StartColumn);

        Assert.Equal(
            finding.Evidence,
            source.Substring(
                finding.SourceSpan.StartOffset,
                finding.SourceSpan.Length
            )
        );

        Assert.NotEmpty(finding.Limitations);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_DynamicCommandRemainsUnresolved()
    {
        const string source = "& $command -Argument 'value'";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Null(Assert.Single(result.Commands).CommandName);
        Assert.Empty(result.Findings);
        Assert.NotEmpty(result.UnsupportedConstructs);
        Assert.False(result.RulesSkipped);
    }
}
