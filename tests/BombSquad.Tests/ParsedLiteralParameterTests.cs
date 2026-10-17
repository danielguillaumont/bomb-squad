using BombSquad.Analysis;
using BombSquad.Rules;

namespace BombSquad.Tests;

public sealed class ParsedLiteralParameterTests
{
    [Fact]
    public void Parse_ExtractsNamedLiteralPathAndName()
    {
        const string source =
            "Set-ItemProperty -Path 'HKCU:\\Software\\Demo' " +
            "-Name 'Enabled' -Value 1";

        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var command = Assert.Single(parsed.Commands);

        Assert.Contains(command.LiteralParameters, parameter =>
            parameter.Name == "Path" &&
            parameter.Value == @"HKCU:\Software\Demo"
        );

        Assert.Contains(command.LiteralParameters, parameter =>
            parameter.Name == "Name" &&
            parameter.Value == "Enabled"
        );
    }

    [Theory]
    [InlineData(
        "Set-ItemProperty -Path 'Env:\\Demo' -Name X -Value '-Path HKCU:\\Software\\Decoy'"
    )]
    [InlineData(
        "Set-ItemProperty -Path $target -Name '-Path HKLM:\\Software\\Decoy' -Value 1"
    )]
    public void Parse_DecoyTextDoesNotBecomePathParameter(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var command = Assert.Single(parsed.Commands);

        Assert.Contains(command.LiteralParameters, parameter =>
            (parameter.Name == "Name" ||
             parameter.Name == "Value") &&
            parameter.Value.Contains("-Path ")
        );

        Assert.Empty(
            new RegistryPropertyRule().Evaluate(parsed.Commands)
        );
    }

    [Theory]
    [InlineData(
        "Set-ItemProperty -Path $target -Name X -Value 1"
    )]
    [InlineData(
        "Set-ItemProperty -Path \"HKCU:\\$subkey\" -Name X -Value 1"
    )]
    public void Parse_DynamicPathsRemainUnresolved(
        string source)
    {
        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var command = Assert.Single(parsed.Commands);

        Assert.DoesNotContain(command.LiteralParameters, parameter =>
            string.Equals(
                parameter.Name,
                "Path",
                StringComparison.OrdinalIgnoreCase
            )
        );

        Assert.Empty(
            new RegistryPropertyRule().Evaluate(parsed.Commands)
        );
    }

    [Fact]
    public void Parse_RecognizesColonAttachedLiteralPath()
    {
        const string source =
            "Set-ItemProperty -Path:'HKCU:\\Software\\Demo' " +
            "-Name X -Value 1";

        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var command = Assert.Single(parsed.Commands);

        Assert.Contains(command.LiteralParameters, parameter =>
            parameter.Name == "Path" &&
            parameter.Value == @"HKCU:\Software\Demo"
        );

        var finding = Assert.Single(
            new RegistryPropertyRule().Evaluate(parsed.Commands)
        );

        Assert.Equal("BS-RG-001", finding.RuleId);
        Assert.Equal(source, finding.Evidence);
    }
}
