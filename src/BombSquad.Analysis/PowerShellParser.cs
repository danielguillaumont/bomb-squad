using System.Collections.Immutable;
using System.Management.Automation.Language;
using BombSquad.Core;

namespace BombSquad.Analysis;

public sealed class PowerShellParser
{
    public PowerShellParseResult Parse(string source)
    {
        ArgumentNullException.ThrowIfNull(source);

        ScriptBlockAst ast = Parser.ParseInput(
            source,
            out _,
            out ParseError[] errors
        );

        var commands = ast
            .FindAll(
                node => node is CommandAst,
                searchNestedScriptBlocks: true
            )
            .OfType<CommandAst>()
            .Select(command => new ParsedCommand(
                CommandName: command.GetCommandName(),
                Text: command.Extent.Text,
                Span: ToSourceSpan(command.Extent)
            ))
            .ToImmutableArray();

        var diagnostics = errors
            .Select(error => new ParseDiagnostic(
                Code: error.ErrorId,
                Message: error.Message,
                SourceSpan: ToSourceSpan(error.Extent)
            ))
            .ToImmutableArray();

        return new PowerShellParseResult(
            Commands: commands,
            Diagnostics: diagnostics
        );
    }

    private static SourceSpan ToSourceSpan(
        IScriptExtent extent)
    {
        return new SourceSpan(
            StartOffset: extent.StartOffset,
            EndOffset: extent.EndOffset,
            StartLine: extent.StartLineNumber,
            StartColumn: extent.StartColumnNumber,
            EndLine: extent.EndLineNumber,
            EndColumn: extent.EndColumnNumber
        );
    }
}
