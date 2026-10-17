using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class FiveFamilyIntegrationTests
{
    [Fact]
    public void Analyze_ReportsFiveFamiliesInSourceOrder()
    {
        const string source =
            "Get-Date\n" +
            "Remove-Item -LiteralPath 'demo-cache'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name Enabled -Value 1\n" +
            "Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'\n" +
            "Register-ScheduledTask -TaskName 'DemoTask' -Action $action";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(5, result.Findings.Length);

        Assert.Equal(
            new[]
            {
                "BS-FS-001",
                "BS-SS-001",
                "BS-RG-001",
                "BS-ID-001",
                "BS-TS-001"
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
                FindingFamily.TasksAndServices
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
            5,
            result.Findings.Select(finding => finding.Id).Distinct().Count()
        );
    }

    [Fact]
    public void Analyze_RecognizesAllThreeTaskAndServiceCommands()
    {
        const string source =
            "Register-ScheduledTask -TaskName 'DemoTask' -Action $action\n" +
            "New-Service -Name 'DemoService' -BinaryPathName 'C:\\Demo\\service.exe'\n" +
            "Set-Service -Name 'DemoService' -StartupType Manual";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.False(result.RulesSkipped);
        Assert.Equal(3, result.Findings.Length);

        Assert.All(result.Findings, finding =>
        {
            Assert.Equal("BS-TS-001", finding.RuleId);

            Assert.Equal(
                FindingFamily.TasksAndServices,
                finding.Family
            );

            Assert.Equal(Certainty.Conditional, finding.Certainty);
        });

        Assert.Equal(
            new[]
            {
                "Potential scheduled task registration",
                "Potential Windows service creation",
                "Potential Windows service configuration change"
            },
            result.Findings.Select(finding => finding.Title)
        );
    }

    [Fact]
    public void Analyze_IgnoresReadOnlyTaskAndServiceCommands()
    {
        const string source =
            "# Register-ScheduledTask -TaskName 'Demo'\n" +
            "Write-Output 'New-Service and Set-Service'\n" +
            "Get-Service\n" +
            "Get-ScheduledTask";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void Analyze_MalformedScriptSkipsAllFiveFamilies()
    {
        const string source =
            "Remove-Item -Path 'demo-cache'\n" +
            "New-LocalUser -Name 'demo-user'\n" +
            "Register-ScheduledTask -TaskName 'DemoTask' -Action $action\n" +
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
    public void Analyze_TasksAndServicesDetectionDoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-five-family-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Set-Service -Name 'DemoService' -StartupType Manual";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source)
        );

        Assert.Equal(AnalysisStatus.Parsed, result.Status);

        Finding finding = Assert.Single(result.Findings);

        Assert.Equal("BS-TS-001", finding.RuleId);
        Assert.False(File.Exists(marker));
        Assert.False(result.RulesSkipped);
    }
}
