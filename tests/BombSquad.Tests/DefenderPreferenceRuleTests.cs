using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class DefenderPreferenceRuleTests
{
    [Fact]
    public void Evaluate_DetectsBothDefenderPreferenceCommands()
    {
        const string source =
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Add-MpPreference -ExclusionPath 'C:\\demo'";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new DefenderPreferenceRule();

        Assert.Empty(parsed.Diagnostics);

        var findings = rule.Evaluate(parsed.Commands);

        Assert.Equal(2, findings.Length);

        Assert.All(findings, finding =>
        {
            Assert.Equal("BS-SS-001", finding.RuleId);
            Assert.Equal(
                FindingFamily.SecuritySettings,
                finding.Family
            );
            Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
            Assert.Equal(Certainty.Conditional, finding.Certainty);
            Assert.NotEmpty(finding.Limitations);
        });

        Assert.Equal(
            parsed.Commands[0].Text,
            findings[0].Evidence
        );

        Assert.Equal(
            parsed.Commands[1].Span,
            findings[1].SourceSpan
        );

        Assert.Equal(1, findings[0].SourceSpan.StartLine);
        Assert.Equal(2, findings[1].SourceSpan.StartLine);

        Assert.NotEqual(findings[0].Id, findings[1].Id);
    }

    [Theory]
    [InlineData("SET-MPPREFERENCE -DisableRealtimeMonitoring $true")]
    [InlineData("add-mppreference -ExclusionPath 'C:\\demo'")]
    public void Evaluate_MatchesCommandNamesRegardlessOfCase(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new DefenderPreferenceRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-SS-001", finding.RuleId);
    }

    [Theory]
    [InlineData("# Set-MpPreference -DisableRealtimeMonitoring $true\nWrite-Output 'Set-MpPreference'")]
    [InlineData("Get-MpPreference")]
    [InlineData("& $dynamicCommand -Argument 'Set-MpPreference'")]
    public void Evaluate_DoesNotMatchCommentsStringsOrOtherCommands(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new DefenderPreferenceRule();

        Assert.Empty(parsed.Diagnostics);
        Assert.Empty(rule.Evaluate(parsed.Commands));
    }

    [Fact]
    public void Evaluate_DoesNotExecutePowerShellSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-defender-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new DefenderPreferenceRule();

        Assert.Empty(parsed.Diagnostics);
        Assert.Single(rule.Evaluate(parsed.Commands));
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var rule = new DefenderPreferenceRule();

        Assert.Throws<ArgumentNullException>(
            () => rule.Evaluate(null!)
        );
    }
}
