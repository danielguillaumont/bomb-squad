using BombSquad.Analysis;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class RegistryFalsePositiveTests
{
    [Theory]
    [InlineData(
        "Set-ItemProperty -Path 'Env:\\Demo' -Name X -Value '-Path HKCU:\\Software\\Decoy'"
    )]
    [InlineData(
        "Set-ItemProperty -Path $target -Name '-Path HKLM:\\Software\\Decoy' -Value 1"
    )]
    [InlineData(
        "New-ItemProperty -Path 'Env:\\Demo' -Name X -Value '-LiteralPath Registry::HKEY_CURRENT_USER\\Software\\Decoy'"
    )]
    public void Evaluate_DoesNotTreatOtherArgumentTextAsRegistryPath(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);
        var rule = new RegistryPropertyRule();

        Assert.Empty(parsed.Diagnostics);

        Assert.Empty(
            rule.Evaluate(parsed.Commands)
        );
    }

    [Fact]
    public void Evaluate_DetectsRegistryPathAfterOtherParameters()
    {
        const string source =
            "Set-ItemProperty -Name X -Value 1 " +
            "-Path 'HKCU:\\Software\\Demo'";

        var parsed = new PowerShellParser().Parse(source);
        var rule = new RegistryPropertyRule();

        Assert.Empty(parsed.Diagnostics);

        Finding finding = Assert.Single(
            rule.Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-RG-001", finding.RuleId);
        Assert.Equal(FindingFamily.Registry, finding.Family);
        Assert.Equal(Certainty.Conditional, finding.Certainty);
        Assert.Equal(source, finding.Evidence);
    }
}
