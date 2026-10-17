using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class FourFamilyIntegrationTests
{
    [Fact]
    public void Analyze_ReportsFourFamiliesInSourceOrder()
    {
        const string source =
            "Get-Date\n" +
            "Remove-Item -LiteralPath 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name Enabled -Value 1\n" +
            "Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(4, result.Findings.Length);

        Assert.Equal(
            new[]
            {
                "BS-FS-001",
                "BS-SS-001",
                "BS-RG-001",
                "BS-ID-001"
            },
            result.Findings.Select(finding => finding.RuleId)
        );

        Assert.Equal(
            new[]
            {
                FindingFamily.Filesystem,
                FindingFamily.SecuritySettings,
                FindingFamily.Registry,
                FindingFamily.Identity
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
    public void Analyze_DetectsBothLocalIdentityCmdlets()
    {
        const string source =
            "New-LocalUser -Name 'demo-user'\n" +
            "Add-LocalGroupMember -Group 'Users' -Member 'demo-user'";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(2, result.Findings.Length);

        Assert.All(result.Findings, finding =>
        {
            Assert.Equal("BS-ID-001", finding.RuleId);
            Assert.Equal(FindingFamily.Identity, finding.Family);
            Assert.Equal(Certainty.Conditional, finding.Certainty);
        });
    }

    [Fact]
    public void Analyze_DoesNotMatchIdentityCommandsInCommentsOrStrings()
    {
        const string source =
            "# Add-LocalGroupMember -Group Administrators -Member demo\n" +
            "Write-Output 'New-LocalUser'\n" +
            "Get-LocalUser";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_MalformedScriptSkipsAllFourFamilies()
    {
        const string source =
            "Remove-Item -Path 'demo-cache'\n" +
            "New-LocalUser -Name 'demo-user'\n" +
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
    public void Analyze_IdentityDetectionDoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-four-family-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "New-LocalUser -Name 'demo-user'";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);

        Finding finding = Assert.Single(result.Findings);

        Assert.Equal("BS-ID-001", finding.RuleId);
        Assert.False(File.Exists(marker));
        Assert.False(result.RulesSkipped);
    }
}
