using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

/// <summary>
/// Release-gate probes grounded in the original BOMB SQUAD v1 master plan.
/// These lock down current supported behaviors; known gaps remain visible in
/// docs/v07-acceptance-audit.md instead of being disguised as passing tests.
/// </summary>
public sealed class V07AcceptanceGateAuditTests
{
    private static AnalysisResult Inspect(string text) =>
        new AnalysisService().Analyze(new AnalysisRequest(text, "synthetic-gate.ps1"));

    [Fact]
    public void A01_CommentsAndQuotedTextDoNotProduceDeletionFindings()
    {
        const string source =
            "# Remove-Item -Recurse -Path 'C:\\demo'\n" +
            "Write-Output 'Remove-Item -Recurse'";
        AnalysisResult result = Inspect(source);
        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void A02_RecursiveRemovalHasEvidenceAndCorrectSourceSpan()
    {
        const string source = "Get-Date\nRemove-Item -Path '.\\demo-cache' -Recurse";
        AnalysisResult result = Inspect(source);
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Equal(2, finding.SourceSpan.StartLine);
        Assert.Equal(1, finding.SourceSpan.StartColumn);
        Assert.Equal("Remove-Item -Path '.\\demo-cache' -Recurse", finding.Evidence);
        Assert.Equal(finding.Evidence,
            source.Substring(finding.SourceSpan.StartOffset, finding.SourceSpan.Length));
    }

    [Fact]
    public void A03_RelativeDeletePathIsNotClaimedResolved()
    {
        AnalysisResult result = Inspect("Remove-Item -Path '.\\temp' -Recurse");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Contains(finding.Limitations, limit =>
            limit.Contains("not resolved", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A04_TaskActionDefinitionDoesNotGetMisclassifiedAsRegistration()
    {
        AnalysisResult result = Inspect(
            "New-ScheduledTaskAction -Execute 'synthetic-demo.exe'");
        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Findings);
        // A separate explanatory finding for definitions is not yet implemented.
    }

    [Fact]
    public void A05_TaskRegistrationIsRecognizedAsConditional()
    {
        AnalysisResult result = Inspect(
            "Register-ScheduledTask -TaskName 'SyntheticTask' -Action $action");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-TS-001", finding.RuleId);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Contains("registration", finding.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A06_DefenderSettingIsConditionalAndDoesNotClaimSuccess()
    {
        AnalysisResult result = Inspect(
            "Set-MpPreference -DisableRealtimeMonitoring $true");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-SS-001", finding.RuleId);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Contains(finding.Limitations, limit =>
            limit.Contains("does not prove execution", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A07_TextEvaluationPreservesUnknownInputLimitation()
    {
        AnalysisResult result = Inspect("Invoke-Expression $syntheticText");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-DE-001", finding.RuleId);
        Assert.Contains(finding.Limitations, limit =>
            limit.Contains("not resolved", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A10_MalformedSourceReportsDiagnosticsAndExplicitlySkipsRules()
    {
        AnalysisResult result = Inspect(
            "Remove-Item -Path 'synthetic-cache'\nWrite-Output 'unterminated");
        Assert.Equal(AnalysisStatus.ParsedWithErrors, result.Status);
        Assert.NotEmpty(result.Diagnostics);
        Assert.True(result.RulesSkipped);
        Assert.Empty(result.Findings);
        // Master-plan goal to retain partial findings remains an open gap.
    }

    [Fact]
    public void A12_UnicodeAndCrlfPreserveSourceOffsets()
    {
        const string source =
            "Write-Output 'caf\u00e9'\r\n  Remove-Item -LiteralPath 'demo-cache'";
        AnalysisResult result = Inspect(source);
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal(2, finding.SourceSpan.StartLine);
        Assert.Equal(3, finding.SourceSpan.StartColumn);
        Assert.Equal(finding.Evidence,
            source.Substring(finding.SourceSpan.StartOffset, finding.SourceSpan.Length));
    }

    [Fact]
    public void A13_PastedInputAboveLimitIsRejectedBeforeAnalysis()
    {
        string oversized = new('a', PastedPowerShellInput.MaximumSourceSizeBytes + 1);
        Assert.Throws<ArgumentException>(() => PastedPowerShellInput.Validate(oversized));
        // This covers pasted input only, not all file and batch input paths.
    }

    [Fact]
    public void A15_NoMatchedRuleDoesNotProduceSafeVerdict()
    {
        AnalysisResult result = Inspect("Get-Date");
        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Findings);
        Assert.Contains(result.Limitations, limit =>
            limit.Contains("absence of findings does not establish safety",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SafetyGate_AnalyzedPowerShellCannotCreateMarkerFile()
    {
        string marker = Path.Combine(Path.GetTempPath(),
            $"bomb-squad-v07-gate-{Guid.NewGuid():N}.txt");
        string escaped = marker.Replace("'", "''", StringComparison.Ordinal);
        string source =
            $"Set-Content -LiteralPath '{escaped}' -Value 'would-have-executed'\n" +
            "Invoke-Expression $syntheticText";
        AnalysisResult result = Inspect(source);
        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.False(File.Exists(marker));
        Assert.Contains(result.Findings, finding => finding.RuleId == "BS-DE-001");
    }
}
