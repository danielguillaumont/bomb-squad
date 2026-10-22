using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class ParserDiagnosticNavigationTests
{
    [Theory]
    [InlineData("Write-Output 'unterminated", 1)]
    [InlineData("# leading comment\nWrite-Output 'unterminated", 2)]
    public void MalformedScript_ParserDiagnosticPointsToOriginalSourceLine(
        string source, int expectedLine)
    {
        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(source, "malformed-test.ps1"));
        ScriptSourceDocument document = new(source);

        Assert.True(result.RulesSkipped);
        Assert.Empty(result.Findings);
        Assert.NotEmpty(result.Diagnostics);

        ParseDiagnostic diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(expectedLine, diagnostic.SourceSpan.StartLine);
        ScriptSourceLine? sourceLine =
            document.GetLine(diagnostic.SourceSpan.StartLine);

        Assert.NotNull(sourceLine);
        Assert.Contains("Write-Output", sourceLine.Text);
    }
}
