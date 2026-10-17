using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class RuleEngineTests
{
    [Fact]
    public void Evaluate_DefaultEngineDetectsRemoveItem()
    {
        const string source =
            "Get-Date\nRemove-Item -LiteralPath 'demo-cache'";

        var parsed = new PowerShellParser().Parse(source);
        var engine = new RuleEngine();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            engine.Evaluate(parsed.Commands)
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
            parsed.Commands[1].Text,
            finding.Evidence
        );

        Assert.NotEmpty(finding.Limitations);
    }

    [Fact]
    public void Evaluate_IgnoresCommentsAndUnmatchedCommands()
    {
        const string source =
            "# Remove-Item -Recurse\nWrite-Output 'Remove-Item'";

        var parsed = new PowerShellParser().Parse(source);
        var engine = new RuleEngine();

        Assert.Empty(parsed.Diagnostics);
        Assert.Empty(engine.Evaluate(parsed.Commands));
    }

    [Fact]
    public void Evaluate_ReturnsFindingsInSourceOrder()
    {
        const string source =
            "Remove-Item -Path 'first'\nRemove-Item -Path 'second'";

        var parsed = new PowerShellParser().Parse(source);
        var engine = new RuleEngine();

        Assert.Empty(parsed.Diagnostics);

        var findings = engine.Evaluate(parsed.Commands);

        Assert.Equal(2, findings.Length);

        Assert.True(
            findings[0].SourceSpan.StartOffset <
            findings[1].SourceSpan.StartOffset
        );

        Assert.NotEqual(
            findings[0].Id,
            findings[1].Id
        );
    }

    [Fact]
    public void Evaluate_DoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-rule-engine-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Remove-Item -LiteralPath 'demo-cache'";

        var parsed = new PowerShellParser().Parse(source);
        var engine = new RuleEngine();

        Assert.Empty(parsed.Diagnostics);
        Assert.Single(engine.Evaluate(parsed.Commands));

        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var engine = new RuleEngine();

        Assert.Throws<ArgumentNullException>(
            () => engine.Evaluate(null!)
        );
    }

    [Fact]
    public void Constructor_RejectsEmptyRuleSet()
    {
        Assert.Throws<ArgumentException>(
            () => new RuleEngine(Array.Empty<IFindingRule>())
        );
    }
}
