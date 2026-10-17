using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class TasksAndServicesRuleTests
{
    [Theory]
    [InlineData(
        "Register-ScheduledTask -TaskName 'DemoTask' -Action $action",
        "Potential scheduled task registration"
    )]
    [InlineData(
        "REGISTER-SCHEDULEDTASK -TaskName 'DemoTask' -Action $action",
        "Potential scheduled task registration"
    )]
    [InlineData(
        "New-Service -Name 'DemoService' -BinaryPathName 'C:\\Demo\\service.exe'",
        "Potential Windows service creation"
    )]
    [InlineData(
        "Set-Service -Name 'DemoService' -StartupType Manual",
        "Potential Windows service configuration change"
    )]
    public void Evaluate_DetectsTaskAndServiceOperations(
        string source,
        string expectedTitle)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new TasksAndServicesRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-TS-001", finding.RuleId);
        Assert.Equal(expectedTitle, finding.Title);

        Assert.Equal(
            FindingFamily.TasksAndServices,
            finding.Family
        );

        Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
        Assert.Equal(Certainty.Conditional, finding.Certainty);

        Assert.Equal(source, finding.Evidence);
        Assert.Equal(parsed.Commands[0].Span, finding.SourceSpan);

        Assert.NotEmpty(finding.PotentialEffect);
        Assert.NotEmpty(finding.Limitations);
        Assert.NotEmpty(finding.NextStep);
    }

    [Theory]
    [InlineData("Get-ScheduledTask -TaskName 'DemoTask'")]
    [InlineData("Get-Service -Name 'DemoService'")]
    [InlineData("# Register-ScheduledTask -TaskName 'DemoTask'\nWrite-Output 'Set-Service'")]
    [InlineData("& $operation -TaskName 'Register-ScheduledTask'")]
    public void Evaluate_IgnoresCommentsStringsAndUnmatchedCommands(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new TasksAndServicesRule();

        Assert.Empty(parsed.Diagnostics);

        Assert.Empty(
            rule.Evaluate(parsed.Commands)
        );
    }

    [Fact]
    public void Evaluate_ReportsMultipleOperationsInSourceOrder()
    {
        const string source =
            "Set-Service -Name 'DemoService' -StartupType Manual\n" +
            "Register-ScheduledTask -TaskName 'DemoTask' -Action $action\n" +
            "New-Service -Name 'OtherService' -BinaryPathName 'C:\\Demo\\app.exe'";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new TasksAndServicesRule();

        Assert.Empty(parsed.Diagnostics);

        var findings = rule.Evaluate(parsed.Commands);

        Assert.Equal(3, findings.Length);

        Assert.Equal(
            new[]
            {
                "Potential Windows service configuration change",
                "Potential scheduled task registration",
                "Potential Windows service creation"
            },
            findings.Select(finding => finding.Title)
        );

        for (int i = 0; i < findings.Length; i++)
        {
            Finding finding = findings[i];

            Assert.Equal(i + 1, finding.SourceSpan.StartLine);

            Assert.Equal(
                finding.Evidence,
                source.Substring(
                    finding.SourceSpan.StartOffset,
                    finding.SourceSpan.Length
                )
            );
        }

        Assert.Equal(
            3,
            findings.Select(finding => finding.Id).Distinct().Count()
        );
    }

    [Fact]
    public void Evaluate_DoesNotExecuteImportedSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-tasks-services-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Register-ScheduledTask -TaskName 'DemoTask' -Action $action";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new TasksAndServicesRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-TS-001", finding.RuleId);

        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var rule = new TasksAndServicesRule();

        Assert.Throws<ArgumentNullException>(
            () => rule.Evaluate(null!)
        );
    }
}
