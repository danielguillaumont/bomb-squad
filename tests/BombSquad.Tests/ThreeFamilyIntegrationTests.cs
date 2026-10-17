using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class ThreeFamilyIntegrationTests
{
    [Fact]
    public void Analyze_ReportsThreeFamiliesInSourceOrder()
    {
        const string source =
            "Get-Date\n" +
            "Remove-Item -LiteralPath 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\BombSquadDemo' -Name Enabled -Value 1";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(3, result.Findings.Length);

        Assert.Equal(
            new[] { "BS-FS-001", "BS-SS-001", "BS-RG-001" },
            result.Findings.Select(finding => finding.RuleId)
        );

        Assert.Equal(
            new[]
            {
                FindingFamily.Filesystem,
                FindingFamily.SecuritySettings,
                FindingFamily.Registry
            },
            result.Findings.Select(finding => finding.Family)
        );

        for (int i = 0; i < result.Findings.Length; i++)
        {
            Finding finding = result.Findings[i];

            Assert.Equal(i + 2, finding.SourceSpan.StartLine);
            Assert.Equal(Certainty.Conditional, finding.Certainty);
            Assert.NotEmpty(finding.Limitations);

            Assert.Equal(
                finding.Evidence,
                source.Substring(
                    finding.SourceSpan.StartOffset,
                    finding.SourceSpan.Length
                )
            );
        }
    }

    [Fact]
    public void Analyze_DoesNotFlagNonRegistryProviderAsRegistry()
    {
        const string source =
            "Set-ItemProperty -Path 'Env:\\Demo' -Name Enabled -Value 1";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_MalformedScriptSkipsAllThreeRules()
    {
        const string source =
            "Remove-Item -Path 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name X -Value 1\n" +
            "Write-Output 'unterminated";

        AnalysisResult result = new AnalysisService().Analyze(
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
    public void Analyze_RegistryDetectionDoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-three-family-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name X -Value 1";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Equal("BS-RG-001", Assert.Single(result.Findings).RuleId);
        Assert.False(File.Exists(marker));
        Assert.False(result.RulesSkipped);
    }
}
