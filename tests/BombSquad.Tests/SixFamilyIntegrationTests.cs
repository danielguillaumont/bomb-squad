using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class SixFamilyIntegrationTests
{
    [Fact]
    public void Analyze_ReportsSixFamiliesInSourceOrder()
    {
        const string source =
            "Get-Date\n" +
            "Remove-Item -LiteralPath 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name Enabled -Value 1\n" +
            "Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'\n" +
            "Register-ScheduledTask -TaskName 'DemoTask' -Action $action\n" +
            "Invoke-Expression $dynamicSource";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(6, result.Findings.Length);

        Assert.Equal(
            new[]
            {
                "BS-FS-001",
                "BS-SS-001",
                "BS-RG-001",
                "BS-ID-001",
                "BS-TS-001",
                "BS-DE-001"
            },
            result.Findings.Select(finding => finding.RuleId)
        );

        Assert.Equal(
            new[]
            {
                FindingFamily.Filesystem,
                FindingFamily.SecuritySettings,
                FindingFamily.Registry,
                FindingFamily.Identity,
                FindingFamily.TasksAndServices,
                FindingFamily.DynamicExecution
            },
            result.Findings.Select(finding => finding.Family)
        );

        for (int i = 0; i < result.Findings.Length; i++)
        {
            Finding finding = result.Findings[i];

            Assert.Equal(i + 2, finding.SourceSpan.StartLine);
            Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
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

        Assert.Equal(
            6,
            result.Findings.Select(finding => finding.Id).Distinct().Count()
        );
    }

    [Fact]
    public void Analyze_DetectsTextEvaluationAndDynamicInvocations()
    {
        const string source =
            "iex $source\n" +
            "& $operation\n" +
            ". $scriptPath";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(3, result.Findings.Length);

        Assert.All(result.Findings, finding =>
        {
            Assert.Equal("BS-DE-001", finding.RuleId);
            Assert.Equal(FindingFamily.DynamicExecution, finding.Family);
            Assert.Equal(Certainty.Conditional, finding.Certainty);
        });

        Assert.Equal(
            new[]
            {
                "Potential PowerShell text evaluation",
                "Potential expression-based command invocation",
                "Potential expression-based command invocation"
            },
            result.Findings.Select(finding => finding.Title)
        );
    }

    [Fact]
    public void Analyze_IgnoresDynamicExecutionTextInStringsAndComments()
    {
        const string source =
            "# Invoke-Expression $source\n" +
            "Write-Output 'iex $source'\n" +
            "& 'Get-Date'\n" +
            "Get-Command Invoke-Expression";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_MalformedScriptSkipsAllSixFamilies()
    {
        const string source =
            "Invoke-Expression $source\n" +
            "Remove-Item -LiteralPath 'demo-cache'\n" +
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
    public void Analyze_DynamicExecutionDetectionDoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-six-family-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Invoke-Expression $source\n" +
            "& $operation";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(2, result.Findings.Length);

        Assert.All(result.Findings, finding =>
            Assert.Equal("BS-DE-001", finding.RuleId)
        );

        Assert.False(File.Exists(marker));
    }
}
