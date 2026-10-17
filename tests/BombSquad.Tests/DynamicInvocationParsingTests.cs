using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class DynamicInvocationParsingTests
{
    [Theory]
    [InlineData("& $operation", true)]
    [InlineData(". $scriptPath", true)]
    [InlineData("& 'Get-Date'", false)]
    [InlineData("Get-Date", false)]
    [InlineData("iex $source", false)]
    [InlineData("Write-Output '& $operation'", false)]
    public void Parse_DistinguishesLiteralAndExpressionInvocations(
        string source,
        bool expectedDynamic)
    {
        var parsed = new PowerShellParser().Parse(source);

        Assert.Empty(parsed.Diagnostics);

        var command = Assert.Single(parsed.Commands);

        Assert.Equal(
            expectedDynamic,
            command.IsDynamicInvocation
        );

        Assert.Equal(source, command.Text);
        Assert.Equal(source.Length, command.Span.Length);
    }
}
