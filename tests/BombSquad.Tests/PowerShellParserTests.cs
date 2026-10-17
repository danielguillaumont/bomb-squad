using BombSquad.Analysis;

namespace BombSquad.Tests;

public class PowerShellParserTests
{
    [Fact]
    public void Parse_ExtractsCommandsAndSourceLocations()
    {
        const string source =
            "Get-Process\nRemove-Item -LiteralPath 'demo-cache'";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.Empty(result.Diagnostics);
        Assert.Equal(2, result.Commands.Length);

        var first = result.Commands[0];
        var second = result.Commands[1];

        Assert.Equal("Get-Process", first.CommandName);
        Assert.Equal(1, first.Span.StartLine);
        Assert.Equal(0, first.Span.StartOffset);

        Assert.Equal("Remove-Item", second.CommandName);
        Assert.Equal(2, second.Span.StartLine);
        Assert.Equal(1, second.Span.StartColumn);

        Assert.Equal(
            second.Text,
            source.Substring(
                second.Span.StartOffset,
                second.Span.Length
            )
        );
    }

    [Fact]
    public void Parse_MalformedPowerShellReturnsDiagnostics()
    {
        const string source = "Write-Output 'unterminated";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.NotEmpty(result.Diagnostics);

        Assert.All(
            result.Diagnostics,
            diagnostic =>
                Assert.False(
                    string.IsNullOrWhiteSpace(diagnostic.Message)
                )
        );
    }

    [Fact]
    public void Parse_DoesNotExecuteSource()
    {
        string marker = Path.Combine(
            Path.GetTempPath(),
            $"bomb-squad-parser-{Guid.NewGuid():N}.txt"
        );

        string escapedPath = marker.Replace("'", "''");

        string source =
            $"Set-Content -LiteralPath '{escapedPath}' -Value 'executed'";

        var parser = new PowerShellParser();
        var result = parser.Parse(source);

        Assert.Empty(result.Diagnostics);
        Assert.Single(result.Commands);
        Assert.Equal(
            "Set-Content",
            result.Commands[0].CommandName
        );

        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void Parse_RejectsNullInput()
    {
        var parser = new PowerShellParser();

        Assert.Throws<ArgumentNullException>(
            () => parser.Parse(null!)
        );
    }
}
