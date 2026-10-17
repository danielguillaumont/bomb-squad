using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class PowerShellParserEdgeCaseTests
{
    [Fact]
    public void Parse_IgnoresCommentsAndLiteralStrings()
    {
        const string source =
            "# Remove-Item -Recurse\n'Get-Process'";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.Empty(result.Diagnostics);
        Assert.Empty(result.Commands);
    }

    [Fact]
    public void Parse_FindsCommandsInsideFunctions()
    {
        const string source =
            "function Invoke-Demo { Get-Service }\nInvoke-Demo";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.Empty(result.Diagnostics);
        Assert.Equal(2, result.Commands.Length);

        Assert.Contains(
            result.Commands,
            command => command.CommandName == "Get-Service"
        );

        Assert.Contains(
            result.Commands,
            command => command.CommandName == "Invoke-Demo"
        );
    }

    [Fact]
    public void Parse_PreservesWindowsLineEndingsAndOffsets()
    {
        const string source = "Get-Date\r\n  Get-Service";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.Empty(result.Diagnostics);
        Assert.Equal(2, result.Commands.Length);

        var second = Assert.Single(
            result.Commands,
            command => command.CommandName == "Get-Service"
        );

        Assert.Equal(2, second.Span.StartLine);
        Assert.Equal(3, second.Span.StartColumn);
        Assert.Equal(12, second.Span.StartOffset);

        Assert.Equal(
            second.Text,
            source.Substring(
                second.Span.StartOffset,
                second.Span.Length
            )
        );
    }

    [Fact]
    public void Parse_DynamicCommandNameRemainsUnresolved()
    {
        const string source = "& $command -Argument 'value'";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.Empty(result.Diagnostics);

        var command = Assert.Single(result.Commands);

        Assert.Null(command.CommandName);
        Assert.Equal(source, command.Text);
    }
}
