using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class RegistryPropertyRuleTests
{
    [Theory]
    [InlineData("Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name Enabled -Value 1")]
    [InlineData("New-ItemProperty -Path 'HKLM:\\Software\\Demo' -Name Enabled -Value 1")]
    [InlineData("Remove-ItemProperty -LiteralPath 'Registry::HKEY_CURRENT_USER\\Software\\Demo' -Name Enabled")]
    public void Evaluate_DetectsExplicitRegistryPropertyMutations(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new RegistryPropertyRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-RG-001", finding.RuleId);
        Assert.Equal(FindingFamily.Registry, finding.Family);
        Assert.Equal(ReviewLevel.Review, finding.ReviewLevel);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Equal(source, finding.Evidence);
        Assert.Equal(parsed.Commands[0].Span, finding.SourceSpan);
        Assert.NotEmpty(finding.Limitations);
    }

    [Theory]
    [InlineData("Get-ItemProperty -Path 'HKLM:\\Software\\Demo' -Name Enabled")]
    [InlineData("Set-ItemProperty -Path 'Env:\\Demo' -Name Enabled -Value 1")]
    [InlineData("Set-ItemProperty -Path $target -Name Enabled -Value 1")]
    [InlineData("# Set-ItemProperty -Path 'HKCU:\\Software\\Demo'\nWrite-Output 'Set-ItemProperty'")]
    public void Evaluate_DoesNotReportUnsupportedOrUnmatchedCases(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new RegistryPropertyRule();

        Assert.Empty(parsed.Diagnostics);
        Assert.Empty(rule.Evaluate(parsed.Commands));
    }

    [Fact]
    public void Evaluate_GeneratesDistinctFindingsInSourceOrder()
    {
        const string source =
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name X -Value 1\n" +
            "Remove-ItemProperty -Path 'HKLM:\\Software\\Demo' -Name X";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new RegistryPropertyRule();

        Assert.Empty(parsed.Diagnostics);

        var findings = rule.Evaluate(parsed.Commands);

        Assert.Equal(2, findings.Length);
        Assert.NotEqual(findings[0].Id, findings[1].Id);
        Assert.Equal(1, findings[0].SourceSpan.StartLine);
        Assert.Equal(2, findings[1].SourceSpan.StartLine);
    }

    [Fact]
    public void Evaluate_DoesNotExecuteImportedSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-registry-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'\n" +
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' -Name X -Value 1";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new RegistryPropertyRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-RG-001", finding.RuleId);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Evaluate_RejectsNullCommands()
    {
        var rule = new RegistryPropertyRule();

        Assert.Throws<ArgumentNullException>(
            () => rule.Evaluate(null!)
        );
    }
}
