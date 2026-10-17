using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class DynamicExecutionRuleTests
{
    [Theory]
    [InlineData("Invoke-Expression $source")]
    [InlineData("iex $source")]
    [InlineData("INVOKE-EXPRESSION 'Write-Output demo'")]
    public void Evaluate_DetectsPowerShellTextEvaluation(string source)
    {
        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            new DynamicExecutionRule().Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-DE-001", finding.RuleId);

        Assert.Equal(
            "Potential PowerShell text evaluation",
            finding.Title
        );

        Assert.Equal(FindingFamily.DynamicExecution, finding.Family);
        Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Equal(source, finding.Evidence);
        Assert.NotEmpty(finding.Limitations);
    }

    [Theory]
    [InlineData("& $operation")]
    [InlineData(". $scriptPath")]
    public void Evaluate_DetectsExpressionBasedInvocations(string source)
    {
        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var command = Assert.Single(parsed.Commands);

        Assert.True(command.IsDynamicInvocation);

        Finding finding = Assert.Single(
            new DynamicExecutionRule().Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-DE-001", finding.RuleId);

        Assert.Equal(
            "Potential expression-based command invocation",
            finding.Title
        );

        Assert.Equal(FindingFamily.DynamicExecution, finding.Family);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Equal(source, finding.Evidence);
        Assert.Equal(command.Span, finding.SourceSpan);

        Assert.Contains(finding.Limitations, limitation =>
            limitation.Contains("not resolved")
        );
    }

    [Theory]
    [InlineData("Write-Output 'Invoke-Expression'")]
    [InlineData("# iex $source\nGet-Date")]
    [InlineData("Get-Command Invoke-Expression")]
    [InlineData("& 'Get-Date'")]
    public void Evaluate_IgnoresNonMatchingOrLiteralCommands(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        Assert.Empty(
            new DynamicExecutionRule().Evaluate(parsed.Commands)
        );
    }

    [Fact]
    public void Evaluate_ReportsMultipleFindingsInSourceOrder()
    {
        const string source =
            "Invoke-Expression $source\n" +
            "& $operation\n" +
            "iex $otherSource";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new DynamicExecutionRule();

        Assert.Empty(parsed.Diagnostics);

        var findings = rule.Evaluate(parsed.Commands);

        Assert.Equal(3, findings.Length);

        Assert.Equal(
            new[]
            {
                "Potential PowerShell text evaluation",
                "Potential expression-based command invocation",
                "Potential PowerShell text evaluation"
            },
            findings.Select(finding => finding.Title)
        );

        for (int i = 0; i < findings.Length; i++)
        {
            Finding finding = findings[i];

            Assert.Equal(i + 1, finding.SourceSpan.StartLine);
            Assert.Equal(Certainty.Conditional, finding.Certainty);

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
    public void Evaluate_DoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-dynamic-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Invoke-Expression $source\n" +
            "& $operation";

        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var findings = new DynamicExecutionRule().Evaluate(
            parsed.Commands
        );

        Assert.Equal(2, findings.Length);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var rule = new DynamicExecutionRule();

        Assert.Throws<ArgumentNullException>(
            () => rule.Evaluate(null!)
        );
    }

    [Fact]
    public void Parse_DistinguishesLiteralAndExpressionBasedCalls()
    {
        const string source =
            "& 'Get-Date'\n" +
            "& $operation";

        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);
        Assert.Equal(2, parsed.Commands.Length);

        Assert.False(parsed.Commands[0].IsDynamicInvocation);
        Assert.True(parsed.Commands[1].IsDynamicInvocation);
    }
}
