using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class MultipleParserDiagnosticTests
{
    private const string MalformedSource = """
        # Deliberately malformed test fixture
        Write-Output "before"

        }

        $broken = )

        Write-Output "after"
        """;

    [Fact]
    public void MultipleErrors_KeepIndependentOriginalLineAndColumnLocations()
    {
        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(MalformedSource, "multi-error-test.ps1"));

        Assert.True(result.RulesSkipped);
        Assert.Empty(result.Findings);
        Assert.True(result.Diagnostics.Length >= 2);
        Assert.Contains(result.Diagnostics, item => item.SourceSpan.StartLine == 4);
        Assert.Contains(result.Diagnostics, item => item.SourceSpan.StartLine == 6);
        Assert.All(result.Diagnostics, item =>
        {
            Assert.True(item.SourceSpan.StartLine >= 1);
            Assert.True(item.SourceSpan.StartColumn >= 1);
        });
    }

    [Fact]
    public void MultipleErrors_CanResolveEachDiagnosticToOriginalSourceText()
    {
        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(MalformedSource, "multi-error-test.ps1"));
        ScriptSourceDocument document = new(MalformedSource);

        Assert.NotEmpty(result.Diagnostics);
        foreach (ParseDiagnostic diagnostic in result.Diagnostics)
        {
            ScriptSourceLine? line =
                document.GetLine(diagnostic.SourceSpan.StartLine);

            Assert.NotNull(line);
            Assert.InRange(diagnostic.SourceSpan.StartColumn, 1, line.Text.Length + 1);
        }
    }
}
