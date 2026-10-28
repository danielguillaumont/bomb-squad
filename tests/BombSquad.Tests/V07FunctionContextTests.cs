using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

/// <summary>
/// Function definitions are inert AST nodes, not proof of invocation.
/// Same-named source functions create conservative command-binding ambiguity.
/// These tests do not run any PowerShell source.
/// </summary>
public sealed class V07FunctionContextTests
{
    private static AnalysisResult Inspect(string source) =>
        new AnalysisService().Analyze(new AnalysisRequest(source, "synthetic.ps1"));

    [Fact]
    public void ParserMarksCommandInsideFunctionDefinition()
    {
        var parsed = new PowerShellParser().Parse(
            "function Demo { Remove-Item -LiteralPath 'cache' }");
        ParsedCommand command = Assert.Single(parsed.Commands);
        Assert.True(command.IsInsideFunctionDefinition);
        Assert.Equal("Remove-Item", command.CommandName);
    }

    [Fact]
    public void ParserMarksNestedFunctionBody()
    {
        var parsed = new PowerShellParser().Parse(
            "function Outer { function Inner { Invoke-Expression $text } }");
        ParsedCommand command = Assert.Single(parsed.Commands);
        Assert.True(command.IsInsideFunctionDefinition);
    }

    [Fact]
    public void TopLevelCommandIsNotInsideFunctionDefinition()
    {
        var parsed = new PowerShellParser().Parse("Remove-Item -Path 'demo'");
        Assert.False(Assert.Single(parsed.Commands).IsInsideFunctionDefinition);
    }

    [Fact]
    public void FunctionBodyFindingStatesDefinitionDoesNotInvokeFunction()
    {
        AnalysisResult result = Inspect(
            "function Demo { Remove-Item -LiteralPath 'cache' }");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Contains(finding.Limitations, limit =>
            limit.Contains("Defining the function does not call it", StringComparison.Ordinal));
        Assert.Contains(result.Limitations, limit =>
            limit.Contains("Definition is not execution", StringComparison.Ordinal));
    }

    [Fact]
    public void NestedFunctionBodyPreservesPotentialDynamicFindingWithCaveat()
    {
        AnalysisResult result = Inspect(
            "function Outer { function Inner { Invoke-Expression $text } }");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-DE-001", finding.RuleId);
        Assert.Contains(finding.Limitations, limit =>
            limit.Contains("whether this function is invoked is unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void SourceDefinedRemoveItemPreventsBuiltInDeletionAssumption()
    {
        AnalysisResult result = Inspect(
            "function Remove-Item { Write-Output 'synthetic only' }\nRemove-Item 'demo'");
        Assert.Empty(result.Findings);
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("matches a function name", StringComparison.Ordinal));
        Assert.Contains(result.Limitations, note =>
            note.Contains("conservative file-wide check", StringComparison.Ordinal));
    }

    [Fact]
    public void ShadowingCheckIsCaseInsensitive()
    {
        AnalysisResult result = Inspect(
            "function remove-item { Write-Output 'custom' }\nREMOVE-ITEM 'demo'");
        Assert.Empty(result.Findings);
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("REMOVE-ITEM", StringComparison.Ordinal));
    }

    [Fact]
    public void SourceDefinedInvokeExpressionPreventsBuiltInEvaluationAssumption()
    {
        AnalysisResult result = Inspect(
            "function Invoke-Expression { Write-Output 'custom' }\nInvoke-Expression $text");
        Assert.Empty(result.Findings);
        Assert.Contains(result.UnsupportedConstructs, note =>
            note.Contains("Invoke-Expression", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownDeclarationOrderIsConservativelyMarked()
    {
        AnalysisResult result = Inspect(
            "Remove-Item 'demo'\nfunction Remove-Item { Write-Output 'late declaration' }");
        Assert.Empty(result.Findings);
        Assert.Contains(result.Limitations, note =>
            note.Contains("declaration order", StringComparison.Ordinal));
    }

    [Fact]
    public void UnshadowedTopLevelRulesStillReportPotentialOperations()
    {
        AnalysisResult result = Inspect(
            "function Utility { Write-Output 'hello' }\nRemove-Item -LiteralPath 'demo'");
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.DoesNotContain(finding.Limitations, limit =>
            limit.Contains("Defining the function does not call it", StringComparison.Ordinal));
    }

    [Fact]
    public void OrdinaryDefinedHelperCallDoesNotCreateUnsupportedWarning()
    {
        AnalysisResult result = Inspect(
            "function Utility { Write-Output 'hello' }\nUtility");
        Assert.Empty(result.Findings);
        Assert.Empty(result.UnsupportedConstructs);
        Assert.DoesNotContain(result.Limitations, note =>
            note.Contains("conservative file-wide check", StringComparison.Ordinal));
    }

    [Fact]
    public void InspectionDoesNotExecuteCodeInsideFunctionOrAtTopLevel()
    {
        string marker = Path.Combine(Path.GetTempPath(),
            $"bomb-squad-v07-function-{Guid.NewGuid():N}.txt");
        string escaped = marker.Replace("'", "''", StringComparison.Ordinal);
        AnalysisResult result = Inspect(
            $"function Demo {{ Set-Content -LiteralPath '{escaped}' -Value 'bad' }}\n" +
            "Invoke-Expression $text");
        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.False(File.Exists(marker));
    }
}
