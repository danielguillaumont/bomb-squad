using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class LocalIdentityChangeRuleTests
{
    [Theory]
    [InlineData("New-LocalUser -Name 'demo-user'")]
    [InlineData("Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'")]
    [InlineData("ADD-LOCALGROUPMEMBER -Group 'Users' -Member 'demo-user'")]
    public void Evaluate_DetectsLocalIdentityOperations(string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new LocalIdentityChangeRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-ID-001", finding.RuleId);
        Assert.Equal(FindingFamily.Identity, finding.Family);
        Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Equal(source, finding.Evidence);
        Assert.Equal(parsed.Commands[0].Span, finding.SourceSpan);
        Assert.NotEmpty(finding.Limitations);
    }

    [Theory]
    [InlineData("Get-LocalUser")]
    [InlineData("Get-LocalGroupMember -Group 'Administrators'")]
    [InlineData("# New-LocalUser -Name 'demo'\nWrite-Output 'Add-LocalGroupMember'")]
    [InlineData("& $operation -Argument 'New-LocalUser'")]
    public void Evaluate_IgnoresUnmatchedAndUnresolvedCommands(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new LocalIdentityChangeRule();

        Assert.Empty(parsed.Diagnostics);
        Assert.Empty(rule.Evaluate(parsed.Commands));
    }

    [Fact]
    public void Evaluate_ReportsMultipleFindingsInSourceOrder()
    {
        const string source =
            "New-LocalUser -Name 'demo-user'\n" +
            "Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new LocalIdentityChangeRule();

        Assert.Empty(parsed.Diagnostics);

        var findings = rule.Evaluate(parsed.Commands);

        Assert.Equal(2, findings.Length);
        Assert.NotEqual(findings[0].Id, findings[1].Id);

        Assert.Equal(1, findings[0].SourceSpan.StartLine);
        Assert.Equal(2, findings[1].SourceSpan.StartLine);

        Assert.All(findings, finding =>
            Assert.Equal(Certainty.Conditional, finding.Certainty)
        );
    }

    [Fact]
    public void Evaluate_DoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-identity-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "New-LocalUser -Name 'demo-user'";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new LocalIdentityChangeRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-ID-001", finding.RuleId);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var rule = new LocalIdentityChangeRule();

        Assert.Throws<ArgumentNullException>(
            () => rule.Evaluate(null!)
        );
    }
}
