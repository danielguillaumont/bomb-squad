using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class RemoveItemRuleTests
{
    [Fact]
    public void Evaluate_ReportsPotentialDeletionWithSourceEvidence()
    {
        const string source =
            "Get-Date\nRemove-Item -LiteralPath 'demo-cache'";

        var parser = new PowerShellParser();
        var parsed = parser.Parse(source);
        var rule = new RemoveItemRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Equal(FindingFamily.Filesystem, finding.Family);
        Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
        Assert.Equal(Certainty.Conditional, finding.Certainty);

        Assert.Equal(2, finding.SourceSpan.StartLine);

        Assert.Equal(
            parsed.Commands[1].Span,
            finding.SourceSpan
        );

        Assert.Equal(
            "Remove-Item -LiteralPath 'demo-cache'",
            finding.Evidence
        );

        Assert.NotEmpty(finding.Limitations);
    }

    [Theory]
    [InlineData("# Remove-Item -Force\nWrite-Output 'Remove-Item'")]
    [InlineData("& $commandName -Argument 'Remove-Item'")]
    public void Evaluate_DoesNotMatchCommentsStringsOrDynamicNames(
        string source)
    {
        var parser = new PowerShellParser();
        var parsed = parser.Parse(source);
        var rule = new RemoveItemRule();

        Assert.Empty(parsed.Diagnostics);
        Assert.Empty(rule.Evaluate(parsed.Commands));
    }

    [Fact]
    public void Evaluate_GeneratesDistinctFindingsForDistinctCommands()
    {
        const string source =
            "Remove-Item -Path 'first'\nRemove-Item -Path 'second'";

        var parser = new PowerShellParser();
        var parsed = parser.Parse(source);
        var rule = new RemoveItemRule();

        var findings = rule.Evaluate(parsed.Commands);

        Assert.Equal(2, findings.Length);

        Assert.NotEqual(
            findings[0].Id,
            findings[1].Id
        );

        Assert.Equal(1, findings[0].SourceSpan.StartLine);
        Assert.Equal(2, findings[1].SourceSpan.StartLine);
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var rule = new RemoveItemRule();

        Assert.Throws<ArgumentNullException>(
            () => rule.Evaluate(null!)
        );
    }
}
