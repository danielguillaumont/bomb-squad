using System.Diagnostics;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

/// <summary>
/// Small, deterministic v0.7 closeout probes. Source is parsed as inert text;
/// no pasted PowerShell is executed or written to a script file.
/// </summary>
public sealed class V07ReleaseReadinessTests
{
    private static AnalysisResult Inspect(string source) =>
        new AnalysisService().Analyze(new AnalysisRequest(
            PastedPowerShellInput.Validate(source), PastedPowerShellInput.SourceIdentifier));

    [Fact]
    public void ManyBenignCommandsDoNotCauseUnexpectedRuleMatches()
    {
        string source = string.Join("\n", Enumerable.Repeat("Get-Date", 800));
        var clock = Stopwatch.StartNew();
        AnalysisResult result = Inspect(source);
        clock.Stop();

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Equal(800, result.Commands.Length);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30),
            $"The 800-command synthetic fixture took {clock.Elapsed}.");
    }

    [Fact]
    public void LongUnicodeCommentAndCrlfKeepExactFindingPosition()
    {
        const string deletion = "Remove-Item -LiteralPath 'demo-cache'";
        string source = "#" + new string('界', 4096) + "\r\n   " + deletion;
        AnalysisResult result = Inspect(source);

        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Equal(2, finding.SourceSpan.StartLine);
        Assert.Equal(4, finding.SourceSpan.StartColumn);
        Assert.Equal(deletion, finding.Evidence);
    }

    [Fact]
    public void MultibyteSourceBelowByteLimitIsPreservedVerbatim()
    {
        string text = "#" + new string('界', 300_000);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(text) <
            PastedPowerShellInput.MaximumSourceSizeBytes);
        Assert.Same(text, PastedPowerShellInput.Validate(text));
    }

    [Fact]
    public void MultibyteSourceAboveByteLimitIsRejectedBeforeAnalysis()
    {
        string text = "#" + new string('界', 400_000);
        Assert.Throws<ArgumentException>(() => PastedPowerShellInput.Validate(text));
    }

    [Fact]
    public void MalformedSourceWithEarlierRiskyCommandNeverClaimsFullCoverage()
    {
        AnalysisResult result = Inspect(
            "Get-Date\nRemove-Item -LiteralPath 'cache'\nWrite-Output 'unterminated");

        Assert.Equal(AnalysisStatus.ParsedWithErrors, result.Status);
        Assert.True(result.RulesSkipped);
        Assert.NotEmpty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.Contains(result.UnsupportedConstructs, item =>
            item.Contains("Incomplete analysis:", StringComparison.Ordinal));
    }

    [Fact]
    public void ExternalAndQualifiedTargetsRemainUnresolvedInTheSameScript()
    {
        AnalysisResult result = Inspect("reviewer.exe\nExampleModule\\Invoke-Review");
        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
        Assert.Contains(result.UnsupportedConstructs, item =>
            item.Contains("reviewer.exe", StringComparison.Ordinal));
        Assert.Contains(result.UnsupportedConstructs, item =>
            item.Contains("ExampleModule\\Invoke-Review", StringComparison.Ordinal));
    }
}
