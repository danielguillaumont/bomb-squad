using System.Text.Json;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

/// <summary>
/// No invoked PowerShell source is executed. Recognition is syntax-only,
/// not a claim of command identity, runtime behavior, or safety.
/// </summary>
public sealed class V07UnresolvedInputTests
{
    private static AnalysisResult Inspect(string source) =>
        new AnalysisService().Analyze(new AnalysisRequest(source, "synthetic.ps1"));

    [Fact]
    public void MalformedSourceReportsIncompleteAnalysisAndSkipsAllRules()
    {
        AnalysisResult result = Inspect(
            "Remove-Item -LiteralPath 'cache'\nWrite-Output 'unterminated");
        Assert.Equal(AnalysisStatus.ParsedWithErrors, result.Status);
        Assert.NotEmpty(result.Diagnostics);
        Assert.True(result.RulesSkipped);
        Assert.Empty(result.Findings);
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("Incomplete analysis:", StringComparison.Ordinal));
    }

    [Fact]
    public void MalformedSourcePreservesCommandsForReviewWithoutClaimingClearance()
    {
        AnalysisResult result = Inspect(
            "Remove-Item -Path 'cache'\nWrite-Output 'unterminated");
        Assert.Contains(result.Commands, command => command.CommandName == "Remove-Item");
        Assert.Contains(result.Limitations, limit =>
            limit.Contains("Partial AST commands", StringComparison.Ordinal));
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("not cleared of risk", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("demo.exe")]
    [InlineData("demo.cmd")]
    [InlineData("demo.bat")]
    [InlineData("demo.com")]
    [InlineData("demo.ps1")]
    public void ExtensionBasedInvocationIsUnresolvedRatherThanFlaggedAsSafe(string name)
    {
        AnalysisResult result = Inspect(name);
        Assert.False(result.RulesSkipped);
        Assert.Empty(result.Findings);
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("Unresolved external or qualified command target", StringComparison.Ordinal) &&
            note.Contains(name, StringComparison.Ordinal));
        Assert.Contains(result.Limitations, note =>
            note.Contains("not complete command discovery", StringComparison.Ordinal));
    }

    [Fact]
    public void ModuleQualifiedInvocationIsNotClaimedResolved()
    {
        AnalysisResult result = Inspect("ExampleModule\\Invoke-Review");
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("ExampleModule\\Invoke-Review", StringComparison.Ordinal));
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void OrdinaryLiteralCommandDoesNotCreateSpuriousUnknownWarning()
    {
        AnalysisResult result = Inspect("Get-Date");
        Assert.Empty(result.UnsupportedConstructs);
        Assert.Empty(result.Findings);
        Assert.False(result.RulesSkipped);
    }

    [Fact]
    public void DynamicInvocationKeepsItsExistingUnknownTargetNote()
    {
        AnalysisResult result = Inspect("& $someCommand");
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("Unresolved command name", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "BS-DE-001");
    }

    [Fact]
    public void KnownFindingIsPreservedAlongsideExternalTargetNote()
    {
        AnalysisResult result = Inspect("Remove-Item 'cache'\ninspector.exe");
        Assert.Contains(result.Findings, finding => finding.RuleId == "BS-FS-001");
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("inspector.exe", StringComparison.Ordinal));
    }

    [Fact]
    public void JsonReportRetainsIncompleteStatusAndReviewNote()
    {
        AnalysisResult result = Inspect("Write-Output 'unterminated");
        using JsonDocument doc = JsonDocument.Parse(
            JsonAnalysisReportWriter.Serialize("synthetic.ps1", result));
        JsonElement root = doc.RootElement;
        Assert.Equal("ParsedWithErrors", root.GetProperty("status").GetString());
        Assert.True(root.GetProperty("rulesSkipped").GetBoolean());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
        Assert.Contains(root.GetProperty("unresolvedConstructs").EnumerateArray().ToArray(), item =>
            item.GetString()!.Contains("Incomplete analysis:", StringComparison.Ordinal));
    }

    [Fact]
    public void PowerShellTextAndNativeCommandAreNeverExecuted()
    {
        string marker = Path.Combine(Path.GetTempPath(),
            $"bomb-squad-v07-unresolved-{Guid.NewGuid():N}.txt");
        string escaped = marker.Replace("'", "''", StringComparison.Ordinal);
        AnalysisResult result = Inspect(
            $"Set-Content -LiteralPath '{escaped}' -Value 'unexpected'\n" +
            "reviewer.exe");
        Assert.False(result.RulesSkipped);
        Assert.False(File.Exists(marker));
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("reviewer.exe", StringComparison.Ordinal));
    }
}
