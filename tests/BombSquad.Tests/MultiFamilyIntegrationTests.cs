using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class MultiFamilyIntegrationTests
{
    [Fact]
    public void Analyze_ReportsBothFamiliesInSourceOrder()
    {
        const string source =
            "Get-Date\n" +
            "Remove-Item -LiteralPath 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Add-MpPreference -ExclusionPath 'C:\\demo'";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(3, result.Findings.Length);

        Assert.Equal(
            new[] { "BS-FS-001", "BS-SS-001", "BS-SS-001" },
            result.Findings.Select(finding => finding.RuleId)
        );

        Assert.Equal(
            FindingFamily.Filesystem,
            result.Findings[0].Family
        );

        Assert.Equal(
            FindingFamily.SecuritySettings,
            result.Findings[1].Family
        );

        Assert.Equal(
            FindingFamily.SecuritySettings,
            result.Findings[2].Family
        );

        for (int i = 0; i < result.Findings.Length; i++)
        {
            Finding finding = result.Findings[i];

            Assert.Equal(
                i + 2,
                finding.SourceSpan.StartLine
            );

            Assert.Equal(
                finding.Evidence,
                source.Substring(
                    finding.SourceSpan.StartOffset,
                    finding.SourceSpan.Length
                )
            );

            Assert.Equal(Certainty.Conditional, finding.Certainty);
            Assert.NotEmpty(finding.Limitations);
        }
    }

    [Fact]
    public void Analyze_MalformedScriptSkipsAllRuleFamilies()
    {
        const string source =
            "Remove-Item -Path 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Write-Output 'unterminated";

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
    public void Analyze_DoesNotReportCommandsInsideCommentsOrStrings()
    {
        const string source =
            "# Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Write-Output 'Remove-Item and Add-MpPreference'";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_DoesNotExecuteSourceWhenDefenderRuleMatches()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-multi-family-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true";

        var service = new AnalysisService();

        AnalysisResult result = service.Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);

        Finding finding = Assert.Single(result.Findings);

        Assert.Equal("BS-SS-001", finding.RuleId);
        Assert.False(File.Exists(marker));
        Assert.False(result.RulesSkipped);
    }
}
